package remotesvc

import (
	"context"
	"fmt"
	"net"
	"strings"

	"golang.org/x/crypto/ssh"
)

func dialSSH(ctx context.Context, target SSHTarget) (*ssh.Client, error) {
	user := strings.TrimSpace(target.User)
	if user == "" {
		return nil, fmt.Errorf("ssh user is required")
	}
	if strings.TrimSpace(target.Host) == "" {
		return nil, fmt.Errorf("ssh host is required")
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
		return nil, fmt.Errorf("ssh dial %s: %w", target.dialAddr(), err)
	}

	cc, chans, reqs, err := ssh.NewClientConn(conn, target.dialAddr(), config)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ssh handshake %s: %w", target.dialAddr(), err)
	}
	return ssh.NewClient(cc, chans, reqs), nil
}

func runRemoteScript(client *ssh.Client, script string) ([]byte, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("ssh session: %w", err)
	}
	defer session.Close()

	_ = session.Setenv("LANG", "C")
	out, err := session.CombinedOutput(script)
	if err != nil {
		if len(out) > 0 {
			return out, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
		}
		return out, err
	}
	return out, nil
}
