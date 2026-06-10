package remotesvc

import "testing"

func TestParseHostMetricsOutput(t *testing.T) {
	raw := `CPU=42.5
MEM_USED=4194304
MEM_TOTAL=8388608
DISK_USED=107374182400
DISK_TOTAL=536870912000
`
	got, err := parseHostMetricsOutput(raw)
	if err != nil {
		t.Fatalf("parseHostMetricsOutput: %v", err)
	}
	if got.CPUPercent != 42.5 {
		t.Fatalf("cpu = %v, want 42.5", got.CPUPercent)
	}
	if got.MemoryUsedBytes != 4194304*1024 {
		t.Fatalf("mem used = %d", got.MemoryUsedBytes)
	}
	if got.MemoryTotalBytes != 8388608*1024 {
		t.Fatalf("mem total = %d", got.MemoryTotalBytes)
	}
	if got.DiskUsedBytes != 107374182400 {
		t.Fatalf("disk used = %d", got.DiskUsedBytes)
	}
	if got.DiskTotalBytes != 536870912000 {
		t.Fatalf("disk total = %d", got.DiskTotalBytes)
	}
}
