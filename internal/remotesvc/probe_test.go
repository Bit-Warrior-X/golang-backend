package remotesvc

import "testing"

func TestMapSystemdToRuntime(t *testing.T) {
	tests := map[string]string{
		"active":       "running",
		"reloading":    "running",
		"activating":   "stopped",
		"deactivating": "stopped",
		"failed":       "stopped",
		"inactive":     "stopped",
		"dead":         "stopped",
		"unknown":      "unknown",
		"":             "unknown",
	}

	for input, want := range tests {
		if got := mapSystemdToRuntime(input); got != want {
			t.Fatalf("mapSystemdToRuntime(%q) = %q, want %q", input, got, want)
		}
	}
}
