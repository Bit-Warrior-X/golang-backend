package api

import (
	"context"
	"log"
	"strings"
	"time"

	"vue-project-backend/internal/remotesvc"
)

const remoteRuntimeProbeTimeout = 120 * time.Second

func probeRemoteRuntimeStatuses(ctx context.Context, ip, user, pass, port string) (angelos, l4, l7 string) {
	probeCtx, cancel := context.WithTimeout(ctx, remoteRuntimeProbeTimeout)
	defer cancel()

	statuses, err := remotesvc.ProbeDorianServices(probeCtx, remotesvc.SSHTarget{
		Host:     ip,
		User:     user,
		Password: pass,
		Port:     port,
	})
	if err != nil {
		log.Printf("[api] remote runtime probe failed ssh_target=%s@%s:%s: %v",
			strings.TrimSpace(user),
			strings.TrimSpace(ip),
			strings.TrimSpace(port),
			err,
		)
	}
	return statuses.Angelos, statuses.L4, statuses.L7
}
