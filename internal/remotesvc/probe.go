package remotesvc

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	defaultSSHPort        = "22"
	defaultProbeAttempts  = 6
	defaultProbeInterval  = 2 * time.Second
	defaultDialTimeout    = 15 * time.Second
	defaultSessionTimeout = 20 * time.Second
)

// SSHTarget identifies a remote Dorian host for systemd probes.
type SSHTarget struct {
	Host     string
	User     string
	Password string
	Port     string
}

// RuntimeStatuses holds normalized runtime states for dashboard display.
type RuntimeStatuses struct {
	Angelos string
	L4      string
	L7      string
}

func (t SSHTarget) dialAddr() string {
	host := strings.TrimSpace(t.Host)
	port := strings.TrimSpace(t.Port)
	if port == "" {
		port = defaultSSHPort
	}
	return net.JoinHostPort(host, port)
}

func normalizeSystemdState(raw string) string {
	state := strings.TrimSpace(raw)
	if state == "" {
		return "unknown"
	}
	if idx := strings.LastIndex(state, "\n"); idx >= 0 {
		state = strings.TrimSpace(state[idx+1:])
	}
	return strings.ToLower(state)
}

// mapSystemdToRuntime maps systemd ActiveState tokens to dashboard runtime status.
// Only a stably active unit counts as running; activating/deactivating means the
// unit is transitioning (including crash-loop auto-restart) and is not healthy.
func mapSystemdToRuntime(state string) string {
	switch normalizeSystemdState(state) {
	case "active", "reloading":
		return "running"
	case "failed", "inactive", "dead", "activating", "deactivating":
		return "stopped"
	default:
		return "unknown"
	}
}

func probeUnit(client *ssh.Client, unit string) string {
	session, err := client.NewSession()
	if err != nil {
		return "unknown"
	}
	defer session.Close()

	_ = session.Setenv("LANG", "C")
	// Prefer is-failed for units in a failed/restart loop; only report active
	// when systemctl is-active is stably active or reloading.
	script := fmt.Sprintf(
		`unit=%q
active=$(systemctl is-active -- "$unit" 2>/dev/null || true)
if [ "$active" = "active" ] || [ "$active" = "reloading" ]; then
  printf 'active'
  exit 0
fi
if systemctl is-failed -- "$unit" >/dev/null 2>&1; then
  printf 'failed'
  exit 0
fi
printf '%%s' "${active:-unknown}"`,
		unit,
	)
	out, err := session.CombinedOutput(script)
	if err != nil && len(out) == 0 {
		return "unknown"
	}
	state := normalizeSystemdState(string(out))
	if state == "" || state == "unknown" {
		return "unknown"
	}
	return state
}

func probeOnce(ctx context.Context, target SSHTarget) (RuntimeStatuses, error) {
	user := strings.TrimSpace(target.User)
	if user == "" {
		return RuntimeStatuses{}, fmt.Errorf("ssh user is required")
	}
	if strings.TrimSpace(target.Host) == "" {
		return RuntimeStatuses{}, fmt.Errorf("ssh host is required")
	}

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(target.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         defaultDialTimeout,
	}

	dialer := &net.Dialer{Timeout: defaultDialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", target.dialAddr())
	if err != nil {
		return RuntimeStatuses{}, fmt.Errorf("ssh dial %s: %w", target.dialAddr(), err)
	}
	defer conn.Close()

	cc, chans, reqs, err := ssh.NewClientConn(conn, target.dialAddr(), config)
	if err != nil {
		return RuntimeStatuses{}, fmt.Errorf("ssh handshake %s: %w", target.dialAddr(), err)
	}
	client := ssh.NewClient(cc, chans, reqs)
	defer client.Close()

	angelosRaw := probeUnit(client, "angelos.service")
	spartaRaw := probeUnit(client, "sparta.service")
	athensRaw := probeUnit(client, "athens.service")

	return RuntimeStatuses{
		Angelos: mapSystemdToRuntime(angelosRaw),
		L4:      mapSystemdToRuntime(spartaRaw),
		L7:      mapSystemdToRuntime(athensRaw),
	}, nil
}

// ProbeDorianServices SSHes to the target and reads systemd state for
// angelos.service, sparta.service, and athens.service. Retries only on SSH errors.
func ProbeDorianServices(ctx context.Context, target SSHTarget) (RuntimeStatuses, error) {
	var last RuntimeStatuses
	var lastErr error

	for attempt := 1; attempt <= defaultProbeAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return last, err
		}
		if attempt > 1 {
			select {
			case <-ctx.Done():
				return last, ctx.Err()
			case <-time.After(defaultProbeInterval):
			}
		}

		attemptCtx, cancel := context.WithTimeout(ctx, defaultSessionTimeout)
		statuses, err := probeOnce(attemptCtx, target)
		cancel()

		last = statuses
		lastErr = err
		if err == nil {
			return statuses, nil
		}
	}

	if lastErr != nil {
		return last, lastErr
	}
	return last, nil
}
