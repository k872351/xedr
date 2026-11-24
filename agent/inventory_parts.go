package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"unicode/utf8"
)

const (
	snapshotPartBytes     = 192 * 1024
	snapshotPartsMaxBytes = 2 * 1024 * 1024
)

func snapshotRequiresPaging(raw []byte) bool {
	var meta struct {
		Paged  bool `json:"paged_software"`
		Assets bool `json:"paged_inventory"`
	}
	return json.Unmarshal(raw, &meta) == nil && (meta.Paged || meta.Assets)
}

// Keep the original outbox row intact until every staged part is acknowledged.
// A retry or process restart reconstructs the same ordered fragments and IDs.
func snapshotPartEvents(r readyRow) ([]map[string]any, error) {
	var original map[string]any
	if err := json.Unmarshal(r.payload, &original); err != nil {
		return nil, err
	}
	if !utf8.Valid(r.payload) || len(r.payload) > snapshotPartsMaxBytes {
		return nil, fmt.Errorf("snapshot parts size or encoding invalid")
	}
	checksum := sha256.Sum256(r.payload)
	transfer := sha256.Sum256([]byte(r.uuid))
	transferID := hex.EncodeToString(transfer[:])
	var fragments []string
	step := snapshotPartBytes
	if snapshotRequiresPaging(r.payload) && len(r.payload) <= step {
		step = (len(r.payload) + 1) / 2
	}
	for start := 0; start < len(r.payload); {
		end := min(start+step, len(r.payload))
		for end < len(r.payload) && !utf8.RuneStart(r.payload[end]) {
			end--
		}
		fragments = append(fragments, string(r.payload[start:end]))
		start = end
	}
	if len(fragments) < 2 || len(fragments) > 12 {
		return nil, fmt.Errorf("snapshot part count invalid")
	}
	events := make([]map[string]any, 0, len(fragments))
	for i, fragment := range fragments {
		id := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", transferID, i)))
		events = append(events, map[string]any{
			"uuid": hex.EncodeToString(id[:]), "seq": r.seq, "kind": "snapshot_part",
			"payload": map[string]any{
				"module": original["module"], "transfer_id": transferID,
				"part_index": i, "part_count": len(fragments),
				"checksum": hex.EncodeToString(checksum[:]), "fragment": fragment,
			},
		})
	}
	return events, nil
}

func (o *outbox) sendSnapshotParts(api *APIClient, r readyRow) (int, error) {
	events, err := snapshotPartEvents(r)
	if err != nil {
		return 0, err
	}
	for _, event := range events {
		resp, err := api.SendBatch(outboxStream, []map[string]any{event})
		if err != nil {
			if isV2Unsupported(err) || isV2BatchRejected(err) {
				o.snapshotParts.Store(false)
				return o.sendV2(api, []readyRow{r})
			}
			return 0, err
		}
		id := event["uuid"].(string)
		for _, rejected := range resp.Rejected {
			if rejected.UUID == id {
				var payload map[string]any
				_ = json.Unmarshal(r.payload, &payload)
				if o.onReject != nil {
					o.onReject(r.kind, payload, rejected.Error)
				}
				o.rejected.Add(1)
				o.deleteSeqs([]int64{r.seq})
				return 1, nil
			}
		}
		acked := false
		for _, ack := range resp.Acked {
			if ack == id {
				acked = true
				break
			}
		}
		if !acked {
			o.bumpAttempt([]int64{r.seq}, map[int64]int{r.seq: r.attempt})
			return 0, nil
		}
	}
	o.deleteSeqs([]int64{r.seq})
	o.sent.Add(1)
	return 1, nil
}
