package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	deliveryHttp "github.com/havilz/caelus-cloud/backend/internal/delivery/http"
	v1 "github.com/havilz/caelus-cloud/backend/internal/delivery/http/v1"
	"github.com/havilz/caelus-cloud/backend/internal/domain"
	"github.com/havilz/caelus-cloud/backend/internal/sentinel"
	securityUcPkg "github.com/havilz/caelus-cloud/backend/internal/usecase/security"
	"github.com/havilz/caelus-cloud/backend/pkg/config"
	"github.com/havilz/caelus-cloud/backend/pkg/jwt"
)

func TestRiskEngine_CalculateScoreAndGrades(t *testing.T) {
	engine := sentinel.NewRiskEngine()

	score, crit, high, med, low := engine.CalculateScore([]domain.SecurityFinding{})
	if score != 100 || crit != 0 || high != 0 || med != 0 || low != 0 {
		t.Fatalf("skor awal tanpa temuan harus 100, dapat: %d", score)
	}
	if grade := engine.CalculateGrade(score); grade != "A" {
		t.Fatalf("grade harus A, dapat: %s", grade)
	}

	findings := []domain.SecurityFinding{
		{Severity: domain.SeverityCritical, Status: domain.FindingStatusOpen},
		{Severity: domain.SeverityHigh, Status: domain.FindingStatusOpen},
		{Severity: domain.SeverityMedium, Status: domain.FindingStatusAcknowledged},
		{Severity: domain.SeverityLow, Status: domain.FindingStatusOpen},
		{Severity: domain.SeverityCritical, Status: domain.FindingStatusResolved},
	}

	score, crit, high, med, low = engine.CalculateScore(findings)
	expectedScore := 100 - 20 - 10 - 5 - 2
	if score != expectedScore {
		t.Fatalf("skor diharapkan %d, dapat %d", expectedScore, score)
	}
	if crit != 1 || high != 1 || med != 1 || low != 1 {
		t.Fatalf("jumlah temuan per severity salah: c=%d, h=%d, m=%d, l=%d", crit, high, med, low)
	}
	if grade := engine.CalculateGrade(score); grade != "D" {
		t.Fatalf("grade harus D untuk skor 63, dapat: %s", grade)
	}
}

type mockSecurityRepo struct {
	scans     map[uuid.UUID]*domain.SecurityScan
	findings  map[uuid.UUID]*domain.SecurityFinding
	incidents map[uuid.UUID]*domain.SecurityIncident
}

func newMockSecurityRepo() *mockSecurityRepo {
	return &mockSecurityRepo{
		scans:     make(map[uuid.UUID]*domain.SecurityScan),
		findings:  make(map[uuid.UUID]*domain.SecurityFinding),
		incidents: make(map[uuid.UUID]*domain.SecurityIncident),
	}
}

func (m *mockSecurityRepo) CreateScan(ctx context.Context, s *domain.SecurityScan) error {
	m.scans[s.ID] = s
	return nil
}

func (m *mockSecurityRepo) UpdateScan(ctx context.Context, s *domain.SecurityScan) error {
	m.scans[s.ID] = s
	return nil
}

func (m *mockSecurityRepo) GetScanByID(ctx context.Context, orgID, scanID uuid.UUID) (*domain.SecurityScan, error) {
	if s, exists := m.scans[scanID]; exists && s.OrganizationID == orgID {
		return s, nil
	}
	return nil, domain.ErrNotFound
}

func (m *mockSecurityRepo) ListScans(ctx context.Context, orgID uuid.UUID, serverID *uuid.UUID, page, limit int) ([]domain.SecurityScan, int, error) {
	var list []domain.SecurityScan
	for _, s := range m.scans {
		if s.OrganizationID == orgID {
			list = append(list, *s)
		}
	}
	return list, len(list), nil
}

func (m *mockSecurityRepo) UpsertFinding(ctx context.Context, f *domain.SecurityFinding) error {
	for id, existing := range m.findings {
		if existing.OrganizationID == f.OrganizationID &&
			existing.Fingerprint == f.Fingerprint &&
			((existing.ServerID == nil && f.ServerID == nil) || (existing.ServerID != nil && f.ServerID != nil && *existing.ServerID == *f.ServerID)) {
			if existing.Status == domain.FindingStatusResolved || existing.Status == domain.FindingStatusFalsePositive {
				f.Status = existing.Status
			}
			f.ID = id
			m.findings[id] = f
			return nil
		}
	}
	m.findings[f.ID] = f
	return nil
}

func (m *mockSecurityRepo) GetFindingByID(ctx context.Context, orgID, id uuid.UUID) (*domain.SecurityFinding, error) {
	if f, exists := m.findings[id]; exists && f.OrganizationID == orgID {
		return f, nil
	}
	return nil, domain.ErrNotFound
}

func (m *mockSecurityRepo) ListFindings(ctx context.Context, orgID uuid.UUID, serverID *uuid.UUID, category *domain.FindingCategory, severity *domain.FindingSeverity, status *domain.FindingStatus, page, limit int) ([]domain.SecurityFinding, int, error) {
	var list []domain.SecurityFinding
	for _, f := range m.findings {
		if f.OrganizationID == orgID {
			list = append(list, *f)
		}
	}
	return list, len(list), nil
}

func (m *mockSecurityRepo) UpdateFindingStatus(ctx context.Context, orgID, findingID uuid.UUID, status domain.FindingStatus) error {
	if f, exists := m.findings[findingID]; exists && f.OrganizationID == orgID {
		f.Status = status
		return nil
	}
	return domain.ErrNotFound
}

func (m *mockSecurityRepo) ReopenFinding(ctx context.Context, orgID, findingID uuid.UUID) error {
	if f, exists := m.findings[findingID]; exists && f.OrganizationID == orgID {
		f.Status = domain.FindingStatusOpen
		f.ResolvedAt = nil
		return nil
	}
	return domain.ErrNotFound
}

func (m *mockSecurityRepo) GetPostureOverview(ctx context.Context, orgID uuid.UUID) (*domain.SecurityPostureOverview, error) {
	return &domain.SecurityPostureOverview{
		OverallScore:    95,
		Grade:           "A",
		TotalScans:      len(m.scans),
		OpenFindings:    len(m.findings),
		CategorySummary: make(map[domain.FindingCategory]int),
	}, nil
}

func (m *mockSecurityRepo) CreateIncident(ctx context.Context, inc *domain.SecurityIncident) error {
	m.incidents[inc.ID] = inc
	return nil
}

func (m *mockSecurityRepo) ListIncidents(ctx context.Context, orgID uuid.UUID, status *domain.IncidentStatus, page, limit int) ([]domain.SecurityIncident, int, error) {
	var list []domain.SecurityIncident
	for _, i := range m.incidents {
		if i.OrganizationID == orgID {
			list = append(list, *i)
		}
	}
	return list, len(list), nil
}

func (m *mockSecurityRepo) UpdateIncidentStatus(ctx context.Context, orgID, incidentID uuid.UUID, status domain.IncidentStatus, notes string) error {
	if i, exists := m.incidents[incidentID]; exists && i.OrganizationID == orgID {
		i.Status = status
		i.MitigationNotes = notes
		return nil
	}
	return domain.ErrNotFound
}

func TestSecurityHTTP_Endpoints(t *testing.T) {
	jwtManager := jwt.NewJWTManager(&config.JWTConfig{
		Secret:            "test_secret_key_at_least_32_characters_long_12345",
		AccessExpiration:  15 * time.Minute,
		RefreshExpiration: 7 * 24 * time.Hour,
	}, "caelus-test")

	orgID := uuid.New()
	user := &domain.User{ID: uuid.New(), Email: "secadmin@caelus.cloud", FullName: "Security Admin", IsActive: true}

	tokenPair, err := jwtManager.GenerateTokenPair(user, &orgID)
	if err != nil {
		t.Fatalf("failed to generate token pair: %v", err)
	}
	token := tokenPair.AccessToken

	secRepo := newMockSecurityRepo()
	srvRepo := newMockServerRepo()
	metRepo := &mockMetricRepo{}
	orchestrator := sentinel.NewOrchestrator(secRepo, nil)

	secUc := securityUcPkg.NewSecurityUsecase(secRepo, srvRepo, metRepo, orchestrator, nil, nil)
	handler := v1.NewSecurityHandler(secUc)

	routerConfig := deliveryHttp.RouterConfig{
		JWTManager: jwtManager,
		Handlers: deliveryHttp.Handlers{
			SecurityHandler: handler,
		},
	}
	router := deliveryHttp.NewRouter(routerConfig)

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/security/overview", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/security/overview expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	scanBody := `{"scan_type":"full"}`
	req, _ = http.NewRequest(http.MethodPost, "/api/v1/security/scans", strings.NewReader(scanBody))
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("POST /api/v1/security/scans expected 202, got %d: %s", rr.Code, rr.Body.String())
	}

	time.Sleep(200 * time.Millisecond)

	req, _ = http.NewRequest(http.MethodGet, "/api/v1/security/scans", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/security/scans expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var res struct {
		Data []domain.SecurityScan `json:"data"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &res)
	if len(res.Data) == 0 {
		t.Fatalf("seharusnya ada minimal 1 scan pada riwayat")
	}

	testFindingID := uuid.New()
	secRepo.findings[testFindingID] = &domain.SecurityFinding{
		ID:             testFindingID,
		OrganizationID: orgID,
		Title:          "Port Terbuka: 6379 (Redis)",
		Category:       domain.CategoryNetwork,
		Severity:       domain.SeverityCritical,
		Status:         domain.FindingStatusOpen,
		Evidence:       []byte(`{"port": 6379, "service": "Redis"}`),
	}

	remediateReq, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/security/findings/%s/remediate", testFindingID.String()), nil)
	remediateReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	rrRemediate := httptest.NewRecorder()
	router.ServeHTTP(rrRemediate, remediateReq)

	if rrRemediate.Code != http.StatusOK {
		t.Fatalf("POST /api/v1/security/findings/{id}/remediate expected 200, got %d: %s", rrRemediate.Code, rrRemediate.Body.String())
	}

	if secRepo.findings[testFindingID].Status != domain.FindingStatusResolved {
		t.Fatalf("status temuan setelah remediasi harus resolved, dapat: %s", secRepo.findings[testFindingID].Status)
	}
}

func TestFindingDeduplication_PreservesResolvedStatus(t *testing.T) {
	secRepo := &mockSecurityRepo{
		scans:     make(map[uuid.UUID]*domain.SecurityScan),
		findings:  make(map[uuid.UUID]*domain.SecurityFinding),
		incidents: make(map[uuid.UUID]*domain.SecurityIncident),
	}

	orgID := uuid.New()
	serverID := uuid.New()
	fingerprint := "test-port-5432"

	f1 := &domain.SecurityFinding{
		ID:             uuid.New(),
		OrganizationID: orgID,
		ServerID:       &serverID,
		Fingerprint:    fingerprint,
		Title:          "Exposed Postgres Port 5432",
		Status:         domain.FindingStatusOpen,
	}
	_ = secRepo.UpsertFinding(context.Background(), f1)

	_ = secRepo.UpdateFindingStatus(context.Background(), orgID, f1.ID, domain.FindingStatusResolved)

	f2 := &domain.SecurityFinding{
		ID:             uuid.New(),
		OrganizationID: orgID,
		ServerID:       &serverID,
		Fingerprint:    fingerprint,
		Title:          "Exposed Postgres Port 5432",
		Status:         domain.FindingStatusOpen,
	}
	_ = secRepo.UpsertFinding(context.Background(), f2)

	list, _, _ := secRepo.ListFindings(context.Background(), orgID, &serverID, nil, nil, nil, 1, 10)
	if len(list) != 1 {
		t.Fatalf("jumlah temuan harus tetap 1 (tidak duplikat), dapat: %d", len(list))
	}
	if list[0].Status != domain.FindingStatusResolved {
		t.Fatalf("status temuan harus tetap resolved dan tidak otomatis kembali open, dapat: %s", list[0].Status)
	}
}
