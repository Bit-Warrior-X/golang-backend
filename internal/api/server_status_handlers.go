package api

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"vue-project-backend/internal/config"
	"vue-project-backend/internal/remotesvc"
	"vue-project-backend/internal/store"
)

const remoteHostMetricsTimeout = 30 * time.Second
const remoteServiceControlTimeout = 45 * time.Second
const remoteHostPowerTimeout = 20 * time.Second

func sshTargetFromView(view store.ServerView) remotesvc.SSHTarget {
	return remotesvc.SSHTarget{
		Host:     view.IP,
		User:     view.SSHUser,
		Password: view.SSHPassword,
		Port:     view.SSHPort,
	}
}

func loadServerViewOrWriteError(w http.ResponseWriter, r *http.Request, servers store.ServerStore, serverID int64) (store.ServerView, bool) {
	view, err := servers.GetView(r.Context(), serverID)
	if err != nil {
		if store.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "server not found")
			return store.ServerView{}, false
		}
		writeError(w, http.StatusInternalServerError, "failed to load server")
		return store.ServerView{}, false
	}
	return view, true
}

func persistRuntimeStatuses(
	ctx context.Context,
	servers store.ServerStore,
	serverID int64,
	view store.ServerView,
) (store.ServerView, error) {
	deployServiceStatus, deployL4Status, deployL7Status := probeRemoteRuntimeStatuses(
		ctx,
		view.IP,
		view.SSHUser,
		view.SSHPassword,
		view.SSHPort,
	)
	tok := strings.TrimSpace(view.Token)
	if err := servers.UpdateDeploymentData(
		ctx,
		serverID,
		tok,
		"",
		"",
		"",
		"",
		nil,
		deployServiceStatus,
		deployL4Status,
		deployL7Status,
	); err != nil {
		return store.ServerView{}, err
	}
	return servers.GetView(ctx, serverID)
}

func handleServerHostMetrics(w http.ResponseWriter, r *http.Request, servers store.ServerStore, serverID int64) {
	view, ok := loadServerViewOrWriteError(w, r, servers, serverID)
	if !ok {
		return
	}

	probeCtx, cancel := context.WithTimeout(r.Context(), remoteHostMetricsTimeout)
	defer cancel()

	metrics, err := remotesvc.ProbeHostMetrics(probeCtx, sshTargetFromView(view))
	if err != nil {
		log.Printf("[api] GET /servers/%d/host-metrics failed ssh_target=%s@%s:%s: %v",
			serverID,
			strings.TrimSpace(view.SSHUser),
			strings.TrimSpace(view.IP),
			strings.TrimSpace(view.SSHPort),
			err,
		)
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, metrics)
}

type serverHostPowerRequest struct {
	Action string `json:"action"`
}

func handleServerHostPower(w http.ResponseWriter, r *http.Request, servers store.ServerStore, serverID int64) {
	view, ok := loadServerViewOrWriteError(w, r, servers, serverID)
	if !ok {
		return
	}

	var body serverHostPowerRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	action := strings.ToLower(strings.TrimSpace(body.Action))
	if action != "poweroff" && action != "restart" {
		writeError(w, http.StatusBadRequest, "action must be poweroff or restart")
		return
	}

	probeCtx, cancel := context.WithTimeout(r.Context(), remoteHostPowerTimeout)
	defer cancel()

	if err := remotesvc.ControlHostPower(probeCtx, sshTargetFromView(view), action); err != nil {
		log.Printf("[api] POST /servers/%d/host-power action=%q failed: %v", serverID, action, err)
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "action": action})
}

type serverServiceControlRequest struct {
	Service string `json:"service"`
	Action  string `json:"action"`
}

func handleServerServiceControl(w http.ResponseWriter, r *http.Request, cfg config.Config, servers store.ServerStore, serverID int64) {
	view, ok := loadServerViewOrWriteError(w, r, servers, serverID)
	if !ok {
		return
	}

	var body serverServiceControlRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	service := strings.ToLower(strings.TrimSpace(body.Service))
	action := strings.ToLower(strings.TrimSpace(body.Action))
	if service != "angelos" && service != "sparta" && service != "athens" {
		writeError(w, http.StatusBadRequest, "service must be angelos, sparta, or athens")
		return
	}
	if action != "start" && action != "stop" {
		writeError(w, http.StatusBadRequest, "action must be start or stop")
		return
	}

	controlCtx, cancel := context.WithTimeout(r.Context(), remoteServiceControlTimeout)
	defer cancel()

	if err := remotesvc.ControlDorianService(controlCtx, sshTargetFromView(view), service, action); err != nil {
		log.Printf("[api] POST /servers/%d/service-control service=%q action=%q failed: %v",
			serverID, service, action, err)
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}

	probeTimeout := remoteRuntimeProbeTimeout
	if cfg.DeployLicenseTimeoutSeconds > 0 {
		probeTimeout = time.Duration(cfg.DeployLicenseTimeoutSeconds) * time.Second
		if probeTimeout > remoteRuntimeProbeTimeout {
			probeTimeout = remoteRuntimeProbeTimeout
		}
	}
	probeCtx, cancelProbe := context.WithTimeout(r.Context(), probeTimeout)
	defer cancelProbe()

	outView, err := persistRuntimeStatuses(probeCtx, servers, serverID, view)
	if err != nil {
		log.Printf("[api] POST /servers/%d/service-control: persist runtime status failed: %v", serverID, err)
		writeError(w, http.StatusInternalServerError, "service updated but failed to refresh runtime status")
		return
	}
	writeJSON(w, http.StatusOK, outView)
}
