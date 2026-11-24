package main

// configuredComponentState classifies configuration-only information.
// Enabling a component is not evidence that initialization succeeded.
func configuredComponentState(enabled bool) string {
	if !enabled {
		return "OFF"
	}
	return "UNKNOWN"
}

// observedComponentState classifies an already available runtime observation.
func observedComponentState(enabled, observed, healthy bool, starting bool) string {
	if !enabled {
		return "OFF"
	}
	if !observed {
		return "UNKNOWN"
	}
	if starting {
		return "STARTING"
	}
	if healthy {
		return "OK"
	}
	return "FAILED"
}

// CollectionCompleteness is the AG-01 contract for a single collection cycle.
// Values: complete | partial | failed | unknown | skipped
type CollectionCompleteness string

const (
	CompletenessComplete CollectionCompleteness = "complete"
	CompletenessPartial  CollectionCompleteness = "partial"
	CompletenessFailed   CollectionCompleteness = "failed"
	CompletenessUnknown  CollectionCompleteness = "unknown"
	CompletenessSkipped  CollectionCompleteness = "skipped"
)

// classifyCollectionCompleteness maps observed run outcomes to AG-01 states.
// expected>0 with returned==0 and err ⇒ failed; returned in (0, expected) or truncated ⇒ partial.
func classifyCollectionCompleteness(enabled, supported bool, expected, returned int, truncated bool, err error) CollectionCompleteness {
	if !enabled || !supported {
		return CompletenessSkipped
	}
	if err != nil {
		if returned > 0 {
			return CompletenessPartial
		}
		return CompletenessFailed
	}
	if expected < 0 && returned < 0 {
		return CompletenessUnknown
	}
	if truncated || (expected > 0 && returned >= 0 && returned < expected) {
		return CompletenessPartial
	}
	if returned >= 0 {
		return CompletenessComplete
	}
	return CompletenessUnknown
}
