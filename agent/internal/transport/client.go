package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
)

var (
	ErrUnauthorizedPayload = errors.New("agent authentication failed: invalid secret or server ID")
	ErrServerError         = errors.New("caelus API server returned an error")
)

type Client interface {
	SendReport(ctx context.Context, payload *AgentReportPayload) ([]AgentAction, error)
}

type HTTPClient struct {
	httpClient  *http.Client
	apiEndpoint string
	serverID    uuid.UUID
	agentSecret string
	maxRetries  int
}

func NewHTTPClient(apiEndpoint string, serverID uuid.UUID, agentSecret string, tlsSkipVerify bool) *HTTPClient {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: tlsSkipVerify,
		},
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: false,
	}

	return &HTTPClient{
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
		apiEndpoint: apiEndpoint,
		serverID:    serverID,
		agentSecret: agentSecret,
		maxRetries:  3,
	}
}

func (c *HTTPClient) SendReport(ctx context.Context, payload *AgentReportPayload) ([]AgentAction, error) {
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal agent payload: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/telemetry/report", c.apiEndpoint)

	var lastErr error
	backoff := 500 * time.Millisecond

	for attempt := 1; attempt <= c.maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, fmt.Errorf("failed to create http request: %w", err)
		}

		c.applyHeaders(req)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(backoff)
			backoff *= 2
			continue
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			var respPayload AgentReportResponse
			_ = json.NewDecoder(resp.Body).Decode(&respPayload)
			_ = resp.Body.Close()
			return respPayload.Data.Actions, nil
		}

		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			_ = resp.Body.Close()
			return nil, ErrUnauthorizedPayload
		}

		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		_ = resp.Body.Close()
		lastErr = fmt.Errorf("%w: status %d, body: %s", ErrServerError, resp.StatusCode, string(respBody))
		time.Sleep(backoff)
		backoff *= 2
	}

	return nil, fmt.Errorf("failed to send telemetry report after %d attempts: %w", c.maxRetries, lastErr)
}

func (c *HTTPClient) applyHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.agentSecret))
	req.Header.Set("X-Server-ID", c.serverID.String())
	req.Header.Set("User-Agent", "caelus-agent/1.0.0")
}
