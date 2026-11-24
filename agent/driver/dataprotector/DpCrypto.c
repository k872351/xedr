/*++

Module Name:

    DpCrypto.c

Abstract:

    File encryption for protected files (XEDR replacement of the original
    fixed-key XOR test provider).

    - Master keys (KEK, AES-256) are provisioned at runtime by the user-mode
      agent through the policy port and kept only in non-paged memory. Until a
      key is loaded DpCryptoIsReady() is FALSE and protected I/O fails closed.
    - Each file carries a DP_FILE_KEY_BLOB (random nonce + KEK id + check).
      Its AES-256 data key is AES-ECB_KEK(nonce^1) || AES-ECB_KEK(nonce^2), so
      every file has a distinct key and footers hold no secret material.
    - Data is AES-256-CTR keyed by the per-file key, counter = 16-byte block
      index of the file offset. CTR is length preserving, supports random
      access and is its own inverse, matching the original transform contract.

--*/

#include "DataProtector.h"
#include <bcrypt.h>

#define DP_TAG_CRYPTO          'kCpD'
#define DP_AES_BLOCK           16u
#define DP_CRYPTO_CHUNK_BLOCKS 256u

typedef struct _DP_KEK {
    ULONG KeyId;
    BCRYPT_KEY_HANDLE Handle;
    PUCHAR Object;
} DP_KEK, *PDP_KEK;

typedef struct _DP_KEK_RING {
    ULONG Count;
    ULONG ActiveKeyId;
    DP_KEK Keys[DP_CRYPTO_MAX_KEYS];
} DP_KEK_RING, *PDP_KEK_RING;

static BCRYPT_ALG_HANDLE gDpAesEcb = NULL;
static ULONG gDpAesObjectLength = 0;
// Readers run at <= DISPATCH_LEVEL inside I/O completion, so the ring is
// guarded by an EX_SPIN_LOCK (shared for readers, exclusive to swap).
static EX_SPIN_LOCK gDpKekLock = 0;
static PDP_KEK_RING gDpKekRing = NULL;

static
VOID
DpCryptoFreeRing(
    _In_opt_ PDP_KEK_RING Ring
    )
{
    ULONG index;

    if (Ring == NULL) {
        return;
    }

    for (index = 0; index < Ring->Count; index++) {
        if (Ring->Keys[index].Handle != NULL) {
            BCryptDestroyKey(Ring->Keys[index].Handle);
        }
        if (Ring->Keys[index].Object != NULL) {
            RtlSecureZeroMemory(Ring->Keys[index].Object, gDpAesObjectLength);
            ExFreePoolWithTag(Ring->Keys[index].Object, DP_TAG_CRYPTO);
        }
    }

    RtlSecureZeroMemory(Ring, sizeof(*Ring));
    ExFreePoolWithTag(Ring, DP_TAG_CRYPTO);
}

NTSTATUS
DpCryptoInitialize(
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    ULONG cb = 0;

    UNREFERENCED_PARAMETER(RegistryPath);

    status = BCryptOpenAlgorithmProvider(&gDpAesEcb, BCRYPT_AES_ALGORITHM, NULL, BCRYPT_PROV_DISPATCH);
    if (!NT_SUCCESS(status)) {
        gDpAesEcb = NULL;
        return status;
    }

    status = BCryptSetProperty(gDpAesEcb,
                               BCRYPT_CHAINING_MODE,
                               (PUCHAR)BCRYPT_CHAIN_MODE_ECB,
                               sizeof(BCRYPT_CHAIN_MODE_ECB),
                               0);
    if (NT_SUCCESS(status)) {
        status = BCryptGetProperty(gDpAesEcb,
                                   BCRYPT_OBJECT_LENGTH,
                                   (PUCHAR)&gDpAesObjectLength,
                                   sizeof(gDpAesObjectLength),
                                   &cb,
                                   0);
    }

    if (!NT_SUCCESS(status) || gDpAesObjectLength == 0) {
        BCryptCloseAlgorithmProvider(gDpAesEcb, 0);
        gDpAesEcb = NULL;
        return NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
    }

    gDpKekLock = 0;
    gDpKekRing = NULL;
    return STATUS_SUCCESS;
}

VOID
DpCryptoUninitialize(
    VOID
    )
{
    PDP_KEK_RING old;
    KIRQL irql;

    irql = ExAcquireSpinLockExclusive(&gDpKekLock);
    old = gDpKekRing;
    gDpKekRing = NULL;
    ExReleaseSpinLockExclusive(&gDpKekLock, irql);

    DpCryptoFreeRing(old);

    if (gDpAesEcb != NULL) {
        BCryptCloseAlgorithmProvider(gDpAesEcb, 0);
        gDpAesEcb = NULL;
    }
}

BOOLEAN
DpCryptoIsReady(
    VOID
    )
{
    BOOLEAN ready;
    KIRQL irql;

    if (gDpAesEcb == NULL) {
        return FALSE;
    }

    irql = ExAcquireSpinLockShared(&gDpKekLock);
    ready = (gDpKekRing != NULL && gDpKekRing->Count != 0);
    ExReleaseSpinLockShared(&gDpKekLock, irql);

    return ready;
}

NTSTATUS
DpCryptoSetKeys(
    _In_ const DP_CRYPTO_KEYS *Keys
    )
{
    PDP_KEK_RING ring;
    PDP_KEK_RING old;
    ULONG index;
    ULONG other;
    BOOLEAN activeFound = FALSE;
    NTSTATUS status = STATUS_SUCCESS;
    KIRQL irql;

    PAGED_CODE();

    if (gDpAesEcb == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (Keys == NULL ||
        Keys->Version != DP_CRYPTO_KEYS_VERSION ||
        Keys->KeyCount == 0 ||
        Keys->KeyCount > DP_CRYPTO_MAX_KEYS) {

        return STATUS_INVALID_PARAMETER;
    }

    for (index = 0; index < Keys->KeyCount; index++) {
        if (Keys->Keys[index].KeyId == 0) {
            return STATUS_INVALID_PARAMETER;
        }
        for (other = index + 1; other < Keys->KeyCount; other++) {
            if (Keys->Keys[other].KeyId == Keys->Keys[index].KeyId) {
                return STATUS_INVALID_PARAMETER;
            }
        }
        if (Keys->Keys[index].KeyId == Keys->ActiveKeyId) {
            activeFound = TRUE;
        }
    }

    if (!activeFound) {
        return STATUS_INVALID_PARAMETER;
    }

    ring = (PDP_KEK_RING)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(DP_KEK_RING), DP_TAG_CRYPTO);
    if (ring == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ring->ActiveKeyId = Keys->ActiveKeyId;

    for (index = 0; index < Keys->KeyCount; index++) {
        PDP_KEK kek = &ring->Keys[index];

        kek->KeyId = Keys->Keys[index].KeyId;
        kek->Object = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, gDpAesObjectLength, DP_TAG_CRYPTO);
        if (kek->Object == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        status = BCryptGenerateSymmetricKey(gDpAesEcb,
                                            &kek->Handle,
                                            kek->Object,
                                            gDpAesObjectLength,
                                            (PUCHAR)Keys->Keys[index].Key,
                                            DP_CRYPTO_KEY_BYTES,
                                            0);
        ring->Count = index + 1;
        if (!NT_SUCCESS(status)) {
            kek->Handle = NULL;
            break;
        }
    }

    if (!NT_SUCCESS(status)) {
        DpCryptoFreeRing(ring);
        return status;
    }

    irql = ExAcquireSpinLockExclusive(&gDpKekLock);
    old = gDpKekRing;
    gDpKekRing = ring;
    ExReleaseSpinLockExclusive(&gDpKekLock, irql);

    // No reader can still hold the old ring: readers only use it under the shared lock.
    DpCryptoFreeRing(old);

    return STATUS_SUCCESS;
}

VOID
DpCryptoQueryStatus(
    _Out_ PDP_CRYPTO_STATUS Status
    )
{
    KIRQL irql;
    ULONG index;

    RtlZeroMemory(Status, sizeof(*Status));
    Status->Version = DP_CRYPTO_STATUS_VERSION;

    irql = ExAcquireSpinLockShared(&gDpKekLock);
    if (gDpKekRing != NULL && gDpAesEcb != NULL) {
        Status->Ready = gDpKekRing->Count != 0;
        Status->ActiveKeyId = gDpKekRing->ActiveKeyId;
        Status->KeyCount = gDpKekRing->Count;
        for (index = 0; index < gDpKekRing->Count; index++) {
            Status->KeyIds[index] = gDpKekRing->Keys[index].KeyId;
        }
    }
    ExReleaseSpinLockShared(&gDpKekLock, irql);
}

//
// Out (48 bytes) = AES-ECB_KEK(nonce^1) || AES-ECB_KEK(nonce^2) || AES-ECB_KEK(nonce^3).
// KeyId == 0 selects the active KEK and returns its id.
//
static
NTSTATUS
DpCryptoKdf(
    _Inout_ PULONG KeyId,
    _In_reads_bytes_(16) const UCHAR *Nonce,
    _Out_writes_bytes_(48) PUCHAR Out
    )
{
    UCHAR in[48];
    ULONG index;
    ULONG cb = 0;
    NTSTATUS status = STATUS_ACCESS_DENIED;
    KIRQL irql;

    for (index = 0; index < 3; index++) {
        RtlCopyMemory(in + (index * DP_AES_BLOCK), Nonce, DP_AES_BLOCK);
        in[(index * DP_AES_BLOCK) + 15] ^= (UCHAR)(index + 1);
    }

    irql = ExAcquireSpinLockShared(&gDpKekLock);
    if (gDpKekRing != NULL) {
        ULONG want = (*KeyId == 0) ? gDpKekRing->ActiveKeyId : *KeyId;

        for (index = 0; index < gDpKekRing->Count; index++) {
            if (gDpKekRing->Keys[index].KeyId == want) {
                status = BCryptEncrypt(gDpKekRing->Keys[index].Handle,
                                       in, sizeof(in), NULL, NULL, 0,
                                       Out, 48, &cb, 0);
                if (NT_SUCCESS(status) && cb != 48) {
                    status = STATUS_UNSUCCESSFUL;
                }
                *KeyId = want;
                break;
            }
        }
    }
    ExReleaseSpinLockShared(&gDpKekLock, irql);

    RtlSecureZeroMemory(in, sizeof(in));
    return status;
}

NTSTATUS
DpCryptoNewFileKey(
    _Out_writes_bytes_(DP_FILE_KEY_LENGTH) UCHAR *Key,
    _Out_ PULONG KeyLength
    )
{
    DP_FILE_KEY_BLOB blob;
    UCHAR derived[48];
    ULONG keyId = 0;
    NTSTATUS status;

    *KeyLength = 0;
    RtlZeroMemory(Key, DP_FILE_KEY_LENGTH);

    if (!DpCryptoIsReady()) {
        return STATUS_DEVICE_NOT_READY;
    }

    RtlZeroMemory(&blob, sizeof(blob));
    status = BCryptGenRandom(NULL, blob.Nonce, sizeof(blob.Nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = DpCryptoKdf(&keyId, blob.Nonce, derived);
    if (!NT_SUCCESS(status)) {
        RtlSecureZeroMemory(derived, sizeof(derived));
        return status;
    }

    blob.Magic = DP_FILE_KEY_BLOB_MAGIC;
    blob.KeyId = keyId;
    RtlCopyMemory(&blob.Check, derived + 32, sizeof(blob.Check));
    RtlSecureZeroMemory(derived, sizeof(derived));

    RtlCopyMemory(Key, &blob, sizeof(blob));
    *KeyLength = DP_FILE_KEY_LENGTH;
    return STATUS_SUCCESS;
}

NTSTATUS
DpCryptoTransformBufferWithKey(
    _Inout_updates_bytes_(Length) PUCHAR Buffer,
    _In_ ULONG Length,
    _In_ LARGE_INTEGER ByteOffset,
    _In_reads_bytes_(KeyLength) const UCHAR *Key,
    _In_ ULONG KeyLength
    )
{
    DP_FILE_KEY_BLOB blob;
    UCHAR derived[48];
    ULONG keyId;
    ULONG check;
    PUCHAR work = NULL;
    PUCHAR keyObject;
    PUCHAR counters;
    PUCHAR stream;
    BCRYPT_KEY_HANDLE dataKey = NULL;
    ULONGLONG baseOffset;
    ULONG done = 0;
    ULONG cb;
    NTSTATUS status;

    if (Length == 0) {
        return STATUS_SUCCESS;
    }

    if (Buffer == NULL || Key == NULL || KeyLength != DP_FILE_KEY_LENGTH ||
        ByteOffset.QuadPart < 0 || gDpAesEcb == NULL) {

        return STATUS_INVALID_PARAMETER;
    }

    RtlCopyMemory(&blob, Key, sizeof(blob));
    if (blob.Magic != DP_FILE_KEY_BLOB_MAGIC || blob.KeyId == 0) {
        // Legacy/foreign footer or missing key: never "decrypt" into garbage.
        return STATUS_ACCESS_DENIED;
    }

    keyId = blob.KeyId;
    status = DpCryptoKdf(&keyId, blob.Nonce, derived);
    if (!NT_SUCCESS(status)) {
        RtlSecureZeroMemory(derived, sizeof(derived));
        return status;
    }

    RtlCopyMemory(&check, derived + 32, sizeof(check));
    if (check != blob.Check) {
        RtlSecureZeroMemory(derived, sizeof(derived));
        return STATUS_ACCESS_DENIED;
    }

    work = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                   gDpAesObjectLength + (2 * DP_CRYPTO_CHUNK_BLOCKS * DP_AES_BLOCK),
                                   DP_TAG_CRYPTO);
    if (work == NULL) {
        RtlSecureZeroMemory(derived, sizeof(derived));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    keyObject = work;
    counters = work + gDpAesObjectLength;
    stream = counters + (DP_CRYPTO_CHUNK_BLOCKS * DP_AES_BLOCK);

    status = BCryptGenerateSymmetricKey(gDpAesEcb, &dataKey, keyObject, gDpAesObjectLength,
                                        derived, DP_CRYPTO_KEY_BYTES, 0);
    RtlSecureZeroMemory(derived, sizeof(derived));
    if (!NT_SUCCESS(status)) {
        dataKey = NULL;
        goto Exit;
    }

    baseOffset = (ULONGLONG)ByteOffset.QuadPart;

    while (done < Length) {
        ULONGLONG absolute = baseOffset + done;
        ULONGLONG block = absolute / DP_AES_BLOCK;
        ULONG skip = (ULONG)(absolute % DP_AES_BLOCK);
        ULONG remaining = Length - done;
        ULONG blocks = (skip + remaining + DP_AES_BLOCK - 1) / DP_AES_BLOCK;
        ULONG take;
        ULONG index;

        if (blocks > DP_CRYPTO_CHUNK_BLOCKS) {
            blocks = DP_CRYPTO_CHUNK_BLOCKS;
        }

        RtlZeroMemory(counters, blocks * DP_AES_BLOCK);
        for (index = 0; index < blocks; index++) {
            ULONGLONG counter = block + index;
            RtlCopyMemory(counters + (index * DP_AES_BLOCK), &counter, sizeof(counter));
        }

        cb = 0;
        status = BCryptEncrypt(dataKey, counters, blocks * DP_AES_BLOCK, NULL, NULL, 0,
                               stream, blocks * DP_AES_BLOCK, &cb, 0);
        if (!NT_SUCCESS(status) || cb != blocks * DP_AES_BLOCK) {
            status = NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
            goto Exit;
        }

        take = (blocks * DP_AES_BLOCK) - skip;
        if (take > remaining) {
            take = remaining;
        }

        for (index = 0; index < take; index++) {
            Buffer[done + index] ^= stream[skip + index];
        }

        done += take;
    }

    status = STATUS_SUCCESS;

Exit:
    if (dataKey != NULL) {
        BCryptDestroyKey(dataKey);
    }
    RtlSecureZeroMemory(work, gDpAesObjectLength + (2 * DP_CRYPTO_CHUNK_BLOCKS * DP_AES_BLOCK));
    ExFreePoolWithTag(work, DP_TAG_CRYPTO);
    return status;
}
