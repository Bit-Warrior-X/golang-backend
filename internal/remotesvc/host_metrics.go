package remotesvc

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// HostMetrics holds normalized resource usage for a remote Dorian host.
type HostMetrics struct {
	CPUPercent       float64 `json:"cpuPercent"`
	MemoryUsedBytes  int64   `json:"memoryUsedBytes"`
	MemoryTotalBytes int64   `json:"memoryTotalBytes"`
	DiskUsedBytes    int64   `json:"diskUsedBytes"`
	DiskTotalBytes   int64   `json:"diskTotalBytes"`
}

const hostMetricsScript = `
read -r _ user nice system idle iowait irq softirq steal _rest < /proc/stat
cpu_total=$((user+nice+system+idle+iowait+irq+softirq+steal))
cpu_idle=$idle
sleep 1
read -r _ user2 nice2 system2 idle2 iowait2 irq2 softirq2 steal2 _rest2 < /proc/stat
cpu_total2=$((user2+nice2+system2+idle2+iowait2+irq2+softirq2+steal2))
cpu_idle2=$idle2
total_diff=$((cpu_total2-cpu_total))
idle_diff=$((cpu_idle2-cpu_idle))
if [ "$total_diff" -gt 0 ]; then
  cpu_pct=$(awk "BEGIN {printf \"%.1f\", (($total_diff-$idle_diff)*100)/$total_diff}")
else
  cpu_pct="0.0"
fi
mem_total=$(awk '/MemTotal:/ {print $2}' /proc/meminfo)
mem_avail=$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)
mem_used=$((mem_total-mem_avail))
disk_used=$(df -B1 / 2>/dev/null | awk 'NR==2 {print $3}')
disk_total=$(df -B1 / 2>/dev/null | awk 'NR==2 {print $2}')
printf 'CPU=%s\nMEM_USED=%s\nMEM_TOTAL=%s\nDISK_USED=%s\nDISK_TOTAL=%s\n' \
  "$cpu_pct" "$mem_used" "$mem_total" "$disk_used" "$disk_total"
`

func parseHostMetricsOutput(raw string) (HostMetrics, error) {
	values := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		values[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}

	cpu, err := strconv.ParseFloat(values["CPU"], 64)
	if err != nil {
		return HostMetrics{}, fmt.Errorf("parse cpu: %w", err)
	}
	memUsed, err := parseMetricBytes(values["MEM_USED"], true)
	if err != nil {
		return HostMetrics{}, fmt.Errorf("parse memory used: %w", err)
	}
	memTotal, err := parseMetricBytes(values["MEM_TOTAL"], true)
	if err != nil {
		return HostMetrics{}, fmt.Errorf("parse memory total: %w", err)
	}
	diskUsed, err := parseMetricBytes(values["DISK_USED"], false)
	if err != nil {
		return HostMetrics{}, fmt.Errorf("parse disk used: %w", err)
	}
	diskTotal, err := parseMetricBytes(values["DISK_TOTAL"], false)
	if err != nil {
		return HostMetrics{}, fmt.Errorf("parse disk total: %w", err)
	}

	return HostMetrics{
		CPUPercent:       cpu,
		MemoryUsedBytes:  memUsed,
		MemoryTotalBytes: memTotal,
		DiskUsedBytes:    diskUsed,
		DiskTotalBytes:   diskTotal,
	}, nil
}

func parseMetricBytes(raw string, fromKib bool) (int64, error) {
	value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return 0, err
	}
	if fromKib {
		return value * 1024, nil
	}
	return value, nil
}

// ProbeHostMetrics SSHes to the target and reads CPU, memory, and root disk usage.
func ProbeHostMetrics(ctx context.Context, target SSHTarget) (HostMetrics, error) {
	client, err := dialSSH(ctx, target)
	if err != nil {
		return HostMetrics{}, err
	}
	defer client.Close()

	out, err := runRemoteScript(client, hostMetricsScript)
	if err != nil {
		return HostMetrics{}, fmt.Errorf("probe host metrics: %w", err)
	}
	return parseHostMetricsOutput(string(out))
}
