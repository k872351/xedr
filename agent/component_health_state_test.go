package main

import (
	"errors"
	"testing"
)

func TestComponentHealthState(t *testing.T) {
	if configuredComponentState(true) != "UNKNOWN" || configuredComponentState(false) != "OFF" {
		t.Fatal("configuration alone cannot establish health")
	}
	for _, tc := range []struct {
		enabled, observed, healthy, starting bool
		want                                 string
	}{
		{false, true, true, false, "OFF"},
		{true, false, false, false, "UNKNOWN"},
		{true, true, false, true, "STARTING"},
		{true, true, true, false, "OK"},
		{true, true, false, false, "FAILED"},
	} {
		if got := observedComponentState(tc.enabled, tc.observed, tc.healthy, tc.starting); got != tc.want {
			t.Fatalf("got %q, want %q", got, tc.want)
		}
	}
}

func TestClassifyCollectionCompleteness(t *testing.T) {
	cases := []struct {
		enabled, supported bool
		expected, returned int
		truncated           bool
		err                error
		want               CollectionCompleteness
	}{
		{false, true, 10, 0, false, nil, CompletenessSkipped},
		{true, false, 10, 0, false, nil, CompletenessSkipped},
		{true, true, 10, 10, false, nil, CompletenessComplete},
		{true, true, 10, 4, false, nil, CompletenessPartial},
		{true, true, 10, 10, true, nil, CompletenessPartial},
		{true, true, 10, 0, false, errors.New("sample"), CompletenessFailed},
		{true, true, 10, 3, false, errors.New("sample"), CompletenessPartial},
		{true, true, -1, -1, false, nil, CompletenessUnknown},
	}
	for i, tc := range cases {
		got := classifyCollectionCompleteness(tc.enabled, tc.supported, tc.expected, tc.returned, tc.truncated, tc.err)
		if got != tc.want {
			t.Fatalf("case %d: got %q want %q", i, got, tc.want)
		}
	}
}
