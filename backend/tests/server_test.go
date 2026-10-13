package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	deliveryHttp "github.com/havilz/caelus-cloud/backend/internal/delivery/http"
	"github.com/havilz/caelus-cloud/backend/internal/delivery/http/response"
	v1 "github.com/havilz/caelus-cloud/backend/internal/delivery/http/v1"
	"github.com/havilz/caelus-cloud/backend/internal/domain"
	provFactory "github.com/havilz/caelus-cloud/backend/internal/provider"
	"github.com/havilz/caelus-cloud/backend/internal/usecase/server"
	"github.com/havilz/caelus-cloud/backend/pkg/config"
	"github.com/havilz/caelus-cloud/backend/pkg/jwt"
)

type mockServerRepo struct {
	servers map[uuid.UUID]*domain.Server
}

func newMockServerRepo() *mockServerRepo {
	return &mockServerRepo{servers: make(map[uuid.UUID]*domain.Server)}
}

func (m *mockServerRepo) Create(ctx context.Context, s *domain.Server) error {
	m.servers[s.ID] = s
	return nil
}

func (m *mockServerRepo) GetByID(ctx context.Context, id uuid.UUID) (*domain.Server, error) {
	if s, exists := m.servers[id]; exists {
		return s, nil
	}
	return nil, domain.ErrNotFound
}

func (m *mockServerRepo) ListByOrg(ctx context.Context, orgID uuid.UUID, page, limit int) ([]domain.Server, int64, error) {
	var list []domain.Server
	for _, s := range m.servers {
		if s.OrganizationID == orgID {
			list = append(list, *s)
		}
	}
	return list, int64(len(list)), nil
}

func (m *mockServerRepo) ListAllRunning(ctx context.Context) ([]domain.Server, error) {
	var list []domain.Server
	for _, s := range m.servers {
		if s.Status == domain.ServerStatusRunning {
			list = append(list, *s)
		}
	}
	return list, nil
}

func (m *mockServerRepo) Update(ctx context.Context, s *domain.Server) error {
	if _, exists := m.servers[s.ID]; !exists {
		return domain.ErrNotFound
	}
	m.servers[s.ID] = s
	return nil
}

func (m *mockServerRepo) UpdateStatus(ctx context.Context, id uuid.UUID, status domain.ServerStatus) error {
	s, exists := m.servers[id]
	if !exists {
		return domain.ErrNotFound
	}
	s.Status = status
	return nil
}

func (m *mockServerRepo) Delete(ctx context.Context, id uuid.UUID) error {
	if _, exists := m.servers[id]; !exists {
		return domain.ErrNotFound
	}
	delete(m.servers, id)
	return nil
}

func (m *mockServerRepo) SetAgentSecret(ctx context.Context, serverID uuid.UUID, secretHash, secretPrefix string) error {
	if srv, exists := m.servers[serverID]; exists {
		srv.AgentSecretHash = &secretHash
		srv.AgentSecretPrefix = &secretPrefix
	}
	return nil
}

func (m *mockServerRepo) GetByIDWithSecret(ctx context.Context, id uuid.UUID) (*domain.Server, error) {
	if srv, exists := m.servers[id]; exists {
		return srv, nil
	}
	return nil, domain.ErrNotFound
}

func (m *mockServerRepo) UpdateSSHHardened(ctx context.Context, id uuid.UUID, hardened bool) error {
	return nil
}

func (m *mockServerRepo) GetSSHHardened(ctx context.Context, id uuid.UUID) (bool, error) {
	return false, nil
}

func setupServerUsecaseTest() (server.ServerUsecase, *mockServerRepo, *mockProviderRepo, uuid.UUID, uuid.UUID) {
	serverRepo := newMockServerRepo()
	provRepo := newMockProviderRepo()
	credRepo := newMockCredRepo()
	factory := provFactory.NewDriverFactory()

	providerID := uuid.New()
	provRepo.providers[providerID] = &domain.Provider{
		ID:       providerID,
		Name:     "Mock Cloud",
		Slug:     "mock",
		IsActive: true,
	}

	orgID := uuid.New()
	uc := server.NewServerUsecase(serverRepo, provRepo, credRepo, factory)
	return uc, serverRepo, provRepo, orgID, providerID
}

func TestServerUsecase_CreateAndGet(t *testing.T) {
	uc, _, _, orgID, provID := setupServerUsecaseTest()
	ctx := context.Background()

	input := server.CreateServerInput{
		OrganizationID: orgID,
		ProviderID:     provID,
		Name:           "api-server-1",
		Region:         "ap-southeast-1",
		OSType:         "ubuntu-22.04",
		PlanID:         "std-2vcpu-4gb",
		CPUCores:       2,
		MemoryMB:       4096,
		DiskGB:         50,
	}

	created, err := uc.CreateServer(ctx, input)
	if err != nil {
		t.Fatalf("gagal membuat server: %v", err)
	}

	if created.ID == uuid.Nil || created.IPAddress == nil || created.Status != domain.ServerStatusRunning {
		t.Errorf("data server yang dibuat tidak sesuai: %+v", created)
	}

	fetched, err := uc.GetServer(ctx, orgID, created.ID)
	if err != nil || fetched.Name != "api-server-1" {
		t.Fatalf("gagal mengambil data server: %v", err)
	}
}

func TestServerUsecase_ListServers(t *testing.T) {
	uc, _, _, orgID, provID := setupServerUsecaseTest()
	ctx := context.Background()

	_, _ = uc.CreateServer(ctx, server.CreateServerInput{
		OrganizationID: orgID,
		ProviderID:     provID,
		Name:           "worker-server",
		Region:         "ap-southeast-1",
		OSType:         "ubuntu-22.04",
		PlanID:         "std-1vcpu-2gb",
		CPUCores:       1,
		MemoryMB:       2048,
		DiskGB:         25,
	})

	list, total, err := uc.ListServers(ctx, orgID, 1, 10)
	if err != nil || total != 1 || len(list) != 1 {
		t.Fatalf("gagal mengambil daftar server: %v", err)
	}
}

func TestServerUsecase_PowerControls(t *testing.T) {
	uc, _, _, orgID, provID := setupServerUsecaseTest()
	ctx := context.Background()

	srv, _ := uc.CreateServer(ctx, server.CreateServerInput{
		OrganizationID: orgID,
		ProviderID:     provID,
		Name:           "power-test",
		Region:         "ap-southeast-1",
		OSType:         "ubuntu-22.04",
		CPUCores:       1,
		MemoryMB:       1024,
		DiskGB:         20,
	})

	if err := uc.ShutdownServer(ctx, orgID, srv.ID); err != nil {
		t.Fatalf("gagal shutdown server: %v", err)
	}
	s1, _ := uc.GetServer(ctx, orgID, srv.ID)
	if s1.Status != domain.ServerStatusStopped {
		t.Errorf("status harus stopped, didapat: %s", s1.Status)
	}

	if err := uc.StartServer(ctx, orgID, srv.ID); err != nil {
		t.Fatalf("gagal start server: %v", err)
	}
	s2, _ := uc.GetServer(ctx, orgID, srv.ID)
	if s2.Status != domain.ServerStatusRunning {
		t.Errorf("status harus running, didapat: %s", s2.Status)
	}

	if err := uc.RebootServer(ctx, orgID, srv.ID); err != nil {
		t.Fatalf("gagal reboot server: %v", err)
	}
}

func TestServerUsecase_Resize(t *testing.T) {
	uc, _, _, orgID, provID := setupServerUsecaseTest()
	ctx := context.Background()

	srv, _ := uc.CreateServer(ctx, server.CreateServerInput{
		OrganizationID: orgID,
		ProviderID:     provID,
		Name:           "resize-test",
		Region:         "ap-southeast-1",
		OSType:         "ubuntu-22.04",
		CPUCores:       1,
		MemoryMB:       1024,
		DiskGB:         20,
	})

	resizeInput := server.ResizeServerInput{
		CPUCores: 4,
		MemoryMB: 8192,
		DiskGB:   100,
	}

	if err := uc.ResizeServer(ctx, orgID, srv.ID, resizeInput); err != nil {
		t.Fatalf("gagal resize server: %v", err)
	}

	updated, _ := uc.GetServer(ctx, orgID, srv.ID)
	if updated.CPUCores != 4 || updated.MemoryMB != 8192 || updated.DiskGB != 100 {
		t.Errorf("spesifikasi resize tidak sesuai: %+v", updated)
	}
}

func TestServerUsecase_Delete(t *testing.T) {
	uc, _, _, orgID, provID := setupServerUsecaseTest()
	ctx := context.Background()

	srv, _ := uc.CreateServer(ctx, server.CreateServerInput{
		OrganizationID: orgID,
		ProviderID:     provID,
		Name:           "delete-test",
		Region:         "ap-southeast-1",
		OSType:         "ubuntu-22.04",
		CPUCores:       1,
		MemoryMB:       1024,
		DiskGB:         20,
	})

	if err := uc.DeleteServer(ctx, orgID, srv.ID); err != nil {
		t.Fatalf("gagal menghapus server: %v", err)
	}

	_, err := uc.GetServer(ctx, orgID, srv.ID)
	if err != domain.ErrNotFound {
		t.Errorf("server yang telah dihapus harus mengembalikan ErrNotFound, didapat: %v", err)
	}
}

func setupServerHTTPTest() (http.Handler, string, uuid.UUID) {
	serverRepo := newMockServerRepo()
	provRepo := newMockProviderRepo()
	credRepo := newMockCredRepo()
	auditRepo := newMockAuditRepo()
	factory := provFactory.NewDriverFactory()

	providerID := uuid.New()
	provRepo.providers[providerID] = &domain.Provider{
		ID:       providerID,
		Name:     "Mock Cloud",
		Slug:     "mock",
		IsActive: true,
	}

	serverUc := server.NewServerUsecase(serverRepo, provRepo, credRepo, factory)

	jwtCfg := &config.JWTConfig{
		Secret:            "test_secret_key_at_least_32_characters_long_12345",
		AccessExpiration:  15 * time.Minute,
		RefreshExpiration: 7 * 24 * time.Hour,
	}
	jwtManager := jwt.NewJWTManager(jwtCfg, "caelus-test")

	router := deliveryHttp.NewRouter(deliveryHttp.RouterConfig{
		Config:     &config.Config{App: config.AppConfig{Name: "test-api", Env: "test"}},
		JWTManager: jwtManager,
		AuditRepo:  auditRepo,
		Handlers: deliveryHttp.Handlers{
			ServerHandler: v1.NewServerHandler(serverUc),
		},
	})

	orgID := uuid.New()
	user := &domain.User{ID: uuid.New(), Email: "dev@example.com", FullName: "Dev User", IsActive: true}
	tokens, _ := jwtManager.GenerateTokenPair(user, &orgID)
	authHeader := "Bearer " + tokens.AccessToken

	return router, authHeader, providerID
}

func executeServerRequest(handler http.Handler, method, path, authHeader string, body []byte) *httptest.ResponseRecorder {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	req.Header.Set("Authorization", authHeader)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func createServerViaHTTP(handler http.Handler, authHeader string, provID uuid.UUID) string {
	body, _ := json.Marshal(server.CreateServerInput{
		ProviderID: provID,
		Name:       "e2e-server",
		Region:     "ap-southeast-1",
		OSType:     "ubuntu-22.04",
		CPUCores:   2,
		MemoryMB:   4096,
		DiskGB:     50,
	})
	rec := executeServerRequest(handler, http.MethodPost, "/api/v1/servers", authHeader, body)
	var resp response.APIResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	dataMap := resp.Data.(map[string]any)
	return dataMap["id"].(string)
}

func TestServerHTTP_CreateAndGet(t *testing.T) {
	router, authHeader, provID := setupServerHTTPTest()
	serverID := createServerViaHTTP(router, authHeader, provID)

	rec := executeServerRequest(router, http.MethodGet, "/api/v1/servers/"+serverID, authHeader, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status code harus %d, didapat: %d", http.StatusOK, rec.Code)
	}
}

func TestServerHTTP_ListServers(t *testing.T) {
	router, authHeader, provID := setupServerHTTPTest()
	_ = createServerViaHTTP(router, authHeader, provID)

	rec := executeServerRequest(router, http.MethodGet, "/api/v1/servers", authHeader, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status code harus %d, didapat: %d", http.StatusOK, rec.Code)
	}
}

func TestServerHTTP_PowerControls(t *testing.T) {
	router, authHeader, provID := setupServerHTTPTest()
	serverID := createServerViaHTTP(router, authHeader, provID)

	recReboot := executeServerRequest(router, http.MethodPost, "/api/v1/servers/"+serverID+"/reboot", authHeader, nil)
	if recReboot.Code != http.StatusOK {
		t.Errorf("reboot status code harus %d, didapat: %d", http.StatusOK, recReboot.Code)
	}

	recShutdown := executeServerRequest(router, http.MethodPost, "/api/v1/servers/"+serverID+"/shutdown", authHeader, nil)
	if recShutdown.Code != http.StatusOK {
		t.Errorf("shutdown status code harus %d, didapat: %d", http.StatusOK, recShutdown.Code)
	}

	recStart := executeServerRequest(router, http.MethodPost, "/api/v1/servers/"+serverID+"/start", authHeader, nil)
	if recStart.Code != http.StatusOK {
		t.Errorf("start status code harus %d, didapat: %d", http.StatusOK, recStart.Code)
	}
}

func TestServerHTTP_ResizeAndDelete(t *testing.T) {
	router, authHeader, provID := setupServerHTTPTest()
	serverID := createServerViaHTTP(router, authHeader, provID)

	resizeBody, _ := json.Marshal(server.ResizeServerInput{CPUCores: 4, MemoryMB: 8192, DiskGB: 100})
	recResize := executeServerRequest(router, http.MethodPatch, "/api/v1/servers/"+serverID+"/resize", authHeader, resizeBody)
	if recResize.Code != http.StatusOK {
		t.Errorf("resize status code harus %d, didapat: %d", http.StatusOK, recResize.Code)
	}

	recDelete := executeServerRequest(router, http.MethodDelete, "/api/v1/servers/"+serverID, authHeader, nil)
	if recDelete.Code != http.StatusOK {
		t.Errorf("delete status code harus %d, didapat: %d", http.StatusOK, recDelete.Code)
	}
}
