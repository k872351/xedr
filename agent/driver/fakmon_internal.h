#pragma once
#include "fakmon.h"

// 未在 WDK 头文件中声明；缺声明时 C 会按返回 int 隐式声明，x64 下指针被截断为 32 位后解引用即蓝屏。
NTKERNELAPI PUCHAR PsGetProcessImageFileName(_In_ PEPROCESS Process);

VOID FaPush(ULONG type, ULONG pid, ULONG ppid, ULONG tid, PCUNICODE_STRING path);
BOOLEAN FaContains(PCUNICODE_STRING s, PCWSTR needle);
BOOLEAN FaImageNameIs(PUCHAR img, const char* want);
ULONG FaProtectedPid(VOID);

NTSTATUS FaRegInit(PDRIVER_OBJECT DriverObject);
VOID FaRegUnload(VOID);
