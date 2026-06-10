package remotesvc

import (
	"context"
	"fmt"
	"strings"
)

func hostPowerScript(action string) string {
	switch action {
	case "poweroff":
		return `
if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
  sudo -n shutdown -h now
else
  shutdown -h now
fi`
	case "restart":
		return `
if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
  sudo -n reboot
else
  reboot
fi`
	default:
		return ""
	}
}

// ControlHostPower issues a remote power-off or restart command over SSH.
func ControlHostPower(ctx context.Context, target SSHTarget, action string) error {
	normalized := strings.ToLower(strings.TrimSpace(action))
	script := hostPowerScript(normalized)
	if script == "" {
		return fmt.Errorf("unsupported action %q", action)
	}

	client, err := dialSSH(ctx, target)
	if err != nil {
		return err
	}
	defer client.Close()

	_, err = runRemoteScript(client, script)
	if err != nil {
		return fmt.Errorf("host %s: %w", normalized, err)
	}
	return nil
}
