package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"vue-project-backend/internal/config"
	"vue-project-backend/internal/store"
)

type AgentClient struct {
	scheme      string
	port        string
	l4Path      string
	optionsPath string
	token       string
	httpClient  *http.Client
}

type AgentResponseError struct {
	StatusCode int
	Body       string
}

func (err AgentResponseError) Error() string {
	if err.Body == "" {
		return fmt.Sprintf("agent returned status %d", err.StatusCode)
	}
	return fmt.Sprintf("agent returned status %d: %s", err.StatusCode, err.Body)
}

func NewAgentClient(cfg config.Config) *AgentClient {
	scheme := strings.TrimSpace(cfg.AgentScheme)
	if scheme == "" {
		scheme = "http"
	}

	l4Path := strings.TrimSpace(cfg.AgentL4Path)
	if l4Path == "" {
		l4Path = "/l4_firewall_data"
	}
	if !strings.HasPrefix(l4Path, "/") {
		l4Path = "/" + l4Path
	}

	optionsPath := strings.TrimSpace(cfg.AgentL4OptionsPath)
	if optionsPath == "" {
		optionsPath = "/API/L4/options"
	}
	if !strings.HasPrefix(optionsPath, "/") {
		optionsPath = "/" + optionsPath
	}

	timeoutSeconds := cfg.AgentTimeoutSeconds
	if timeoutSeconds <= 0 {
		timeoutSeconds = 5
	}

	return &AgentClient{
		scheme:      scheme,
		port:        strings.TrimSpace(cfg.AgentPort),
		l4Path:      l4Path,
		optionsPath: optionsPath,
		token:       cfg.AgentToken,
		httpClient: &http.Client{
			Timeout: time.Duration(timeoutSeconds) * time.Second,
		},
	}
}

type agentAuthPayload struct {
	Token string `json:"token"`
}

type agentL4Payload struct {
	Token string `json:"token"`
	store.L4Config
}

type agentL4AddWhiteIPPayload struct {
	Token string `json:"token"`
	IP    string `json:"ip"`
}

type L4Options struct {
	Interfaces             []string            `json:"interfaces"`
	AttachModes            []string            `json:"attachModes"`
	AttachModesByInterface map[string][]string `json:"attachModesByInterface"`
}

func (client *AgentClient) PushL4(ctx context.Context, serverIP string, token string, payload store.L4Config) error {
	serverIP = strings.TrimSpace(serverIP)
	if serverIP == "" {
		return fmt.Errorf("server IP is empty")
	}

	payloadToken := strings.TrimSpace(token)
	if payloadToken == "" {
		payloadToken = strings.TrimSpace(client.token)
	}

	body, err := json.Marshal(agentL4Payload{
		Token:    payloadToken,
		L4Config: payload,
	})
	if err != nil {
		return fmt.Errorf("encode payload: %w", err)
	}

	targetHost := serverIP
	if client.port != "" {
		targetHost = net.JoinHostPort(serverIP, client.port)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, client.scheme+"://"+targetHost+client.l4Path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if client.token != "" {
		req.Header.Set("Authorization", "Bearer "+client.token)
	}

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("agent request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return AgentResponseError{
			StatusCode: resp.StatusCode,
			Body:       strings.TrimSpace(string(limited)),
		}
	}

	return nil
}

func (client *AgentClient) FetchL4Options(ctx context.Context, serverIP string, token string) (L4Options, error) {
	serverIP = strings.TrimSpace(serverIP)
	if serverIP == "" {
		return L4Options{}, fmt.Errorf("server IP is empty")
	}

	payloadToken := strings.TrimSpace(token)
	if payloadToken == "" {
		payloadToken = strings.TrimSpace(client.token)
	}

	body, err := json.Marshal(agentAuthPayload{Token: payloadToken})
	if err != nil {
		return L4Options{}, fmt.Errorf("encode payload: %w", err)
	}

	targetHost := serverIP
	if client.port != "" {
		targetHost = net.JoinHostPort(serverIP, client.port)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, client.scheme+"://"+targetHost+client.optionsPath, bytes.NewReader(body))
	if err != nil {
		return L4Options{}, fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if client.token != "" {
		req.Header.Set("Authorization", "Bearer "+client.token)
	}

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return L4Options{}, fmt.Errorf("agent request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return L4Options{}, AgentResponseError{
			StatusCode: resp.StatusCode,
			Body:       strings.TrimSpace(string(limited)),
		}
	}

	var options L4Options
	if err := json.NewDecoder(resp.Body).Decode(&options); err != nil {
		return L4Options{}, fmt.Errorf("decode response: %w", err)
	}

	return options, nil
}

func (client *AgentClient) AddL4WhitelistIP(ctx context.Context, serverIP string, token string, ip string) error {
	serverIP = strings.TrimSpace(serverIP)
	if serverIP == "" {
		return fmt.Errorf("server IP is empty")
	}

	payloadToken := strings.TrimSpace(token)
	if payloadToken == "" {
		payloadToken = strings.TrimSpace(client.token)
	}

	ip = strings.TrimSpace(ip)
	if ip == "" {
		return fmt.Errorf("ip is empty")
	}

	body, err := json.Marshal(agentL4AddWhiteIPPayload{
		Token: payloadToken,
		IP:    ip,
	})
	if err != nil {
		return fmt.Errorf("encode payload: %w", err)
	}

	targetHost := serverIP
	if client.port != "" {
		targetHost = net.JoinHostPort(serverIP, client.port)
	}

	// Hard-coded path for add_white_ip, follows existing agent L4 API convention.
	const addWhiteIPPath = "/API/L4/add_white_ip"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, client.scheme+"://"+targetHost+addWhiteIPPath, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if client.token != "" {
		req.Header.Set("Authorization", "Bearer "+client.token)
	}

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("agent request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return AgentResponseError{
			StatusCode: resp.StatusCode,
			Body:       strings.TrimSpace(string(limited)),
		}
	}

	return nil
}

func (client *AgentClient) AddL4BlacklistIP(ctx context.Context, serverIP string, token string, ip string) error {
	serverIP = strings.TrimSpace(serverIP)
	if serverIP == "" {
		return fmt.Errorf("server IP is empty")
	}
	payloadToken := strings.TrimSpace(token)
	if payloadToken == "" {
		payloadToken = strings.TrimSpace(client.token)
	}
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return fmt.Errorf("ip is empty")
	}
	body, err := json.Marshal(agentL4AddWhiteIPPayload{Token: payloadToken, IP: ip})
	if err != nil {
		return fmt.Errorf("encode payload: %w", err)
	}
	targetHost := serverIP
	if client.port != "" {
		targetHost = net.JoinHostPort(serverIP, client.port)
	}
	const addBlackIPPath = "/API/L4/add_block_ip"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, client.scheme+"://"+targetHost+addBlackIPPath, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if client.token != "" {
		req.Header.Set("Authorization", "Bearer "+client.token)
	}
	resp, err := client.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("agent request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return AgentResponseError{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(limited))}
	}
	return nil
}

func (client *AgentClient) RemoveL4BlacklistIP(ctx context.Context, serverIP string, token string, ip string) error {
	serverIP = strings.TrimSpace(serverIP)
	if serverIP == "" {
		return fmt.Errorf("server IP is empty")
	}
	payloadToken := strings.TrimSpace(token)
	if payloadToken == "" {
		payloadToken = strings.TrimSpace(client.token)
	}
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return fmt.Errorf("ip is empty")
	}
	body, err := json.Marshal(agentL4AddWhiteIPPayload{Token: payloadToken, IP: ip})
	if err != nil {
		return fmt.Errorf("encode payload: %w", err)
	}
	targetHost := serverIP
	if client.port != "" {
		targetHost = net.JoinHostPort(serverIP, client.port)
	}
	const removeBlackIPPath = "/API/L4/remove_block_ip"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, client.scheme+"://"+targetHost+removeBlackIPPath, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if client.token != "" {
		req.Header.Set("Authorization", "Bearer "+client.token)
	}
	resp, err := client.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("agent request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return AgentResponseError{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(limited))}
	}
	return nil
}

func (client *AgentClient) ClearL4Blacklist(ctx context.Context, serverIP string, token string) error {
	serverIP = strings.TrimSpace(serverIP)
	if serverIP == "" {
		return fmt.Errorf("server IP is empty")
	}
	payloadToken := strings.TrimSpace(token)
	if payloadToken == "" {
		payloadToken = strings.TrimSpace(client.token)
	}
	body, err := json.Marshal(agentAuthPayload{Token: payloadToken})
	if err != nil {
		return fmt.Errorf("encode payload: %w", err)
	}
	targetHost := serverIP
	if client.port != "" {
		targetHost = net.JoinHostPort(serverIP, client.port)
	}
	const clearBlackIPPath = "/API/L4/remove_block_ip_all"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, client.scheme+"://"+targetHost+clearBlackIPPath, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if client.token != "" {
		req.Header.Set("Authorization", "Bearer "+client.token)
	}
	resp, err := client.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("agent request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return AgentResponseError{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(limited))}
	}
	return nil
}

func (client *AgentClient) RemoveL4WhitelistIP(ctx context.Context, serverIP string, token string, ip string) error {
	serverIP = strings.TrimSpace(serverIP)
	if serverIP == "" {
		return fmt.Errorf("server IP is empty")
	}

	payloadToken := strings.TrimSpace(token)
	if payloadToken == "" {
		payloadToken = strings.TrimSpace(client.token)
	}

	ip = strings.TrimSpace(ip)
	if ip == "" {
		return fmt.Errorf("ip is empty")
	}

	body, err := json.Marshal(agentL4AddWhiteIPPayload{
		Token: payloadToken,
		IP:    ip,
	})
	if err != nil {
		return fmt.Errorf("encode payload: %w", err)
	}

	targetHost := serverIP
	if client.port != "" {
		targetHost = net.JoinHostPort(serverIP, client.port)
	}

	const removeWhiteIPPath = "/API/L4/remove_white_ip"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, client.scheme+"://"+targetHost+removeWhiteIPPath, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if client.token != "" {
		req.Header.Set("Authorization", "Bearer "+client.token)
	}

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("agent request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return AgentResponseError{
			StatusCode: resp.StatusCode,
			Body:       strings.TrimSpace(string(limited)),
		}
	}

	return nil
}

func (client *AgentClient) ClearL4Whitelist(ctx context.Context, serverIP string, token string) error {
	serverIP = strings.TrimSpace(serverIP)
	if serverIP == "" {
		return fmt.Errorf("server IP is empty")
	}

	payloadToken := strings.TrimSpace(token)
	if payloadToken == "" {
		payloadToken = strings.TrimSpace(client.token)
	}

	body, err := json.Marshal(agentAuthPayload{Token: payloadToken})
	if err != nil {
		return fmt.Errorf("encode payload: %w", err)
	}

	targetHost := serverIP
	if client.port != "" {
		targetHost = net.JoinHostPort(serverIP, client.port)
	}

	const clearWhiteIPPath = "/API/L4/remove_white_ip_all"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, client.scheme+"://"+targetHost+clearWhiteIPPath, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if client.token != "" {
		req.Header.Set("Authorization", "Bearer "+client.token)
	}

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("agent request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return AgentResponseError{
			StatusCode: resp.StatusCode,
			Body:       strings.TrimSpace(string(limited)),
		}
	}

	return nil
}
