package remotesvc

import (
	"context"
	"fmt"
	"strings"
)

var serviceUnitNames = map[string]string{
	"angelos": "angelos.service",
	"sparta":  "sparta.service",
	"athens":  "athens.service",
}

func serviceUnitName(service string) (string, error) {
	unit, ok := serviceUnitNames[strings.ToLower(strings.TrimSpace(service))]
	if !ok {
		return "", fmt.Errorf("unsupported service %q", service)
	}
	return unit, nil
}

func serviceControlScript(unit, action string) string {
	return fmt.Sprintf(
		`unit=%q
action=%q
if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
  sudo -n systemctl "$action" -- "$unit"
else
  systemctl "$action" -- "$unit"
fi`,
		unit,
		action,
	)
}

// ControlDorianService starts or stops a Dorian systemd unit on the remote host.
func ControlDorianService(ctx context.Context, target SSHTarget, service, action string) error {
	unit, err := serviceUnitName(service)
	if err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "start", "stop":
	default:
		return fmt.Errorf("unsupported action %q", action)
	}

	client, err := dialSSH(ctx, target)
	if err != nil {
		return err
	}
	defer client.Close()

	_, err = runRemoteScript(client, serviceControlScript(unit, strings.ToLower(strings.TrimSpace(action))))
	if err != nil {
		return fmt.Errorf("control %s: %w", unit, err)
	}
	return nil
}
