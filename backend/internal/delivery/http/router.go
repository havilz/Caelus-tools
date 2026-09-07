package http

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	customMiddleware "github.com/havilz/caelus-cloud/backend/internal/delivery/http/middleware"
	"github.com/havilz/caelus-cloud/backend/internal/delivery/http/helper"
	"github.com/havilz/caelus-cloud/backend/internal/delivery/http/response"
	v1 "github.com/havilz/caelus-cloud/backend/internal/delivery/http/v1"
	"github.com/havilz/caelus-cloud/backend/internal/delivery/ws"
	"github.com/havilz/caelus-cloud/backend/internal/domain"
	"github.com/havilz/caelus-cloud/backend/pkg/config"
	"github.com/havilz/caelus-cloud/backend/pkg/jwt"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Handlers struct {
	AuthHandler       *v1.AuthHandler
	ServerHandler     *v1.ServerHandler
	ProviderHandler   *v1.ProviderHandler
	CredentialHandler *v1.CredentialHandler
	TelemetryHandler  *v1.TelemetryHandler
	AlertHandler      *v1.AlertHandler
	StorageHandler    *v1.StorageHandler
	BackupHandler     *v1.BackupHandler
	AutomationHandler *v1.AutomationHandler
	SecurityHandler   *v1.SecurityHandler
	IaCHandler        *v1.IaCHandler
	DeploymentHandler *v1.DeploymentHandler
	NetworkHandler    *v1.NetworkHandler
	VolumeHandler     *v1.VolumeHandler
	DomainHandler     *v1.DomainHandler
	SettingsHandler   *v1.SettingsHandler
	WSHandler         *ws.Handler
}

type RouterConfig struct {
	Config     *config.Config
	JWTManager jwt.Manager
	AuditRepo  domain.AuditLogRepository
	ServerRepo domain.ServerRepository
	OrgRepo    domain.OrganizationRepository

	PgxPool  *pgxpool.Pool
	Logger   *slog.Logger
	Handlers Handlers
}

func NewRouter(rc RouterConfig) *chi.Mux {
	r := chi.NewRouter()

	var trustedProxies []string
	if rc.Config != nil {
		trustedProxies = rc.Config.App.TrustedProxies
	}
	customMiddleware.SetTrustedProxies(trustedProxies)
	ipValidator := customMiddleware.NewIPValidator(trustedProxies)

	r.Use(chimiddleware.RequestID)
	r.Use(customMiddleware.ClientIPMiddleware(ipValidator))
	r.Use(chimiddleware.Recoverer)
	if rc.Config != nil {
		r.Use(customMiddleware.CORS(rc.Config.App.CorsOrigins))
	}
	r.Use(customMiddleware.RequestLogger())

	registerHealthRoutes(r, rc.Config)
	registerAPIRoutes(r, rc)

	return r
}

func registerHealthRoutes(r *chi.Mux, cfg *config.Config) {
	serviceName := "caelus-cloud-api"
	envName := "development"
	if cfg != nil {
		serviceName = cfg.App.Name
		envName = cfg.App.Env
	}

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		response.Success(w, http.StatusOK, "Caelus Cloud API is healthy", map[string]string{
			"status":  "ok",
			"service": serviceName,
			"env":     envName,
		})
	})

	r.Get("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		response.Success(w, http.StatusOK, "API v1 is operational", map[string]string{
			"status":  "ok",
			"version": "v1",
		})
	})

	r.Get("/agent-bin", helper.HandleAgentBinDownload)
	r.Get("/install.sh", helper.HandleAgentInstallScript)
}

func registerAPIRoutes(r *chi.Mux, rc RouterConfig) {
	r.Route("/api/v1", func(apiRouter chi.Router) {
		if rc.Handlers.AuthHandler != nil {

			authLimiter := customMiddleware.NewAuthRateLimiter(5, 1*time.Minute)
			apiRouter.With(authLimiter.Limit()).Post("/auth/register", rc.Handlers.AuthHandler.Register)
			apiRouter.With(authLimiter.Limit()).Post("/auth/login", rc.Handlers.AuthHandler.Login)
			apiRouter.Post("/auth/refresh", rc.Handlers.AuthHandler.RefreshToken)
		}

		if rc.Handlers.ProviderHandler != nil {
			apiRouter.Get("/providers", rc.Handlers.ProviderHandler.ListProviders)
		}

		if rc.Handlers.TelemetryHandler != nil {

			if rc.ServerRepo != nil {
				apiRouter.With(customMiddleware.RequireAgentAuth(rc.ServerRepo)).Post("/telemetry/report", rc.Handlers.TelemetryHandler.IngestReport)
			}
		}

		if rc.Handlers.WSHandler != nil {
			apiRouter.Get("/ws", rc.Handlers.WSHandler.HandleWebSocket)
		}

		if rc.JWTManager != nil {
			apiRouter.Group(func(protectedRouter chi.Router) {
				protectedRouter.Use(customMiddleware.Authenticate(rc.JWTManager))

				protectedRouter.Use(customMiddleware.InjectOrgContext())
				if rc.AuditRepo != nil {
					protectedRouter.Use(customMiddleware.AuditLogInterceptor(rc.AuditRepo, rc.Logger))
				}

				if rc.Handlers.ServerHandler != nil || rc.Handlers.TelemetryHandler != nil {
					registerServerRoutes(protectedRouter, rc.Handlers.ServerHandler, rc.Handlers.TelemetryHandler, rc.OrgRepo)
				}

				if rc.Handlers.WSHandler != nil {
					protectedRouter.Get("/telemetry/stream/{server_id}", rc.Handlers.WSHandler.HandleSSE)
				}

				if rc.Handlers.CredentialHandler != nil {
					registerCredentialRoutes(protectedRouter, rc.Handlers.CredentialHandler, rc.OrgRepo)
				}

				if rc.Handlers.AlertHandler != nil {
					registerAlertRoutes(protectedRouter, rc.Handlers.AlertHandler)
				}

				if rc.Handlers.StorageHandler != nil {
					registerStorageRoutes(protectedRouter, rc.Handlers.StorageHandler)
				}

				if rc.Handlers.BackupHandler != nil {
					registerBackupRoutes(protectedRouter, rc.Handlers.BackupHandler)
				}

				if rc.Handlers.AutomationHandler != nil {
					registerAutomationRoutes(protectedRouter, rc.Handlers.AutomationHandler)
				}

				if rc.Handlers.SecurityHandler != nil {
					registerSecurityRoutes(protectedRouter, rc.Handlers.SecurityHandler)
				}

				if rc.Handlers.IaCHandler != nil {
					registerIaCRoutes(protectedRouter, rc.Handlers.IaCHandler, rc.OrgRepo)
				}

				if rc.Handlers.DeploymentHandler != nil {
					registerDeploymentRoutes(protectedRouter, rc.Handlers.DeploymentHandler, rc.OrgRepo)
				}

				if rc.Handlers.NetworkHandler != nil {
					registerNetworkRoutes(protectedRouter, rc.Handlers.NetworkHandler, rc.OrgRepo)
				}

				if rc.Handlers.VolumeHandler != nil {
					registerVolumeRoutes(protectedRouter, rc.Handlers.VolumeHandler, rc.OrgRepo)
				}

				if rc.Handlers.DomainHandler != nil {
					registerDomainRoutes(protectedRouter, rc.Handlers.DomainHandler)
				}

				if rc.Handlers.SettingsHandler != nil {
					registerSettingsRoutes(protectedRouter, rc.Handlers.SettingsHandler, rc.OrgRepo)
				}
			})
		}
	})
}

func registerSettingsRoutes(r chi.Router, sh *v1.SettingsHandler, orgRepo domain.OrganizationRepository) {
	r.Route("/settings", func(sr chi.Router) {
		sr.Get("/profile", sh.GetProfile)
		sr.Put("/profile", sh.UpdateProfile)
		sr.Post("/change-password", sh.ChangePassword)

		sr.Get("/organization", sh.GetOrganization)
		if orgRepo != nil {
			adminOnly := customMiddleware.RequireOrganizationRole(orgRepo, domain.RoleAdmin)
			ownerOnly := customMiddleware.RequireOrganizationRole(orgRepo, domain.RoleOwner)

			sr.With(adminOnly).Put("/organization", sh.UpdateOrganization)

			sr.Get("/members", sh.ListMembers)
			sr.With(adminOnly).Post("/members/invite", sh.InviteMember)
			sr.With(ownerOnly).Put("/members/{user_id}/role", sh.UpdateMemberRole)
			sr.With(adminOnly).Delete("/members/{user_id}", sh.RemoveMember)
			sr.With(adminOnly).Delete("/invitations/{invitation_id}", sh.DeleteInvitation)

			sr.Get("/api-keys", sh.ListAPIKeys)
			sr.With(adminOnly).Post("/api-keys", sh.CreateAPIKey)
			sr.With(adminOnly).Delete("/api-keys/{key_id}", sh.DeleteAPIKey)

			sr.Get("/webhooks", sh.ListWebhooks)
			sr.With(adminOnly).Post("/webhooks", sh.CreateWebhook)
			sr.With(adminOnly).Put("/webhooks/{webhook_id}", sh.UpdateWebhook)
			sr.With(adminOnly).Post("/webhooks/{webhook_id}/test", sh.TestWebhook)
			sr.With(adminOnly).Delete("/webhooks/{webhook_id}", sh.DeleteWebhook)

			sr.Get("/audit-logs", sh.ListAuditLogs)
		} else {
			sr.Put("/organization", sh.UpdateOrganization)

			sr.Get("/members", sh.ListMembers)
			sr.Post("/members/invite", sh.InviteMember)
			sr.Put("/members/{user_id}/role", sh.UpdateMemberRole)
			sr.Delete("/members/{user_id}", sh.RemoveMember)
			sr.Delete("/invitations/{invitation_id}", sh.DeleteInvitation)

			sr.Get("/api-keys", sh.ListAPIKeys)
			sr.Post("/api-keys", sh.CreateAPIKey)
			sr.Delete("/api-keys/{key_id}", sh.DeleteAPIKey)

			sr.Get("/webhooks", sh.ListWebhooks)
			sr.Post("/webhooks", sh.CreateWebhook)
			sr.Put("/webhooks/{webhook_id}", sh.UpdateWebhook)
			sr.Post("/webhooks/{webhook_id}/test", sh.TestWebhook)
			sr.Delete("/webhooks/{webhook_id}", sh.DeleteWebhook)

			sr.Get("/audit-logs", sh.ListAuditLogs)
		}
	})
}

func registerDomainRoutes(r chi.Router, dh *v1.DomainHandler) {
	r.Route("/domains", func(domainRouter chi.Router) {
		domainRouter.Get("/", dh.ListDomains)
		domainRouter.Post("/", dh.CreateDomain)
		domainRouter.Get("/{id}", dh.GetDomain)
		domainRouter.Delete("/{id}", dh.DeleteDomain)
		domainRouter.Post("/{id}/verify", dh.VerifyDomain)
	})
}

func registerVolumeRoutes(r chi.Router, volH *v1.VolumeHandler, orgRepo domain.OrganizationRepository) {
	r.Route("/volumes", func(volRouter chi.Router) {
		volRouter.Get("/stats", volH.GetStoragePoolStats)
		volRouter.Get("/", volH.ListVolumes)
		if orgRepo != nil {
			adminOnly := customMiddleware.RequireOrganizationRole(orgRepo, domain.RoleAdmin)
			volRouter.With(adminOnly).Post("/", volH.CreateVolume)
			volRouter.With(adminOnly).Delete("/{id}", volH.DeleteVolume)
		} else {
			volRouter.Post("/", volH.CreateVolume)
			volRouter.Delete("/{id}", volH.DeleteVolume)
		}
	})
}

func registerIaCRoutes(r chi.Router, iacH *v1.IaCHandler, orgRepo domain.OrganizationRepository) {
	r.Route("/iac", func(iacRouter chi.Router) {
		iacRouter.Post("/validate", iacH.ValidateYAML)
		iacRouter.Get("/configs", iacH.ListConfigs)
		iacRouter.Get("/configs/{id}", iacH.GetConfig)
		iacRouter.Get("/configs/{id}/plan", iacH.GetLatestPlan)
		iacRouter.Get("/configs/{id}/states", iacH.ListStates)

		if orgRepo != nil {
			adminOnly := customMiddleware.RequireOrganizationRole(orgRepo, domain.RoleAdmin)
			iacRouter.With(adminOnly).Post("/configs", iacH.CreateConfig)
			iacRouter.With(adminOnly).Put("/configs/{id}", iacH.UpdateConfig)
			iacRouter.With(adminOnly).Delete("/configs/{id}", iacH.DeleteConfig)
			iacRouter.With(adminOnly).Post("/configs/{id}/plan", iacH.GeneratePlan)
			iacRouter.With(adminOnly).Post("/plans/{id}/apply", iacH.ApplyPlan)
			iacRouter.With(adminOnly).Post("/configs/{id}/rollback", iacH.RollbackState)
		} else {
			iacRouter.Post("/configs", iacH.CreateConfig)
			iacRouter.Put("/configs/{id}", iacH.UpdateConfig)
			iacRouter.Delete("/configs/{id}", iacH.DeleteConfig)
			iacRouter.Post("/configs/{id}/plan", iacH.GeneratePlan)
			iacRouter.Post("/plans/{id}/apply", iacH.ApplyPlan)
			iacRouter.Post("/configs/{id}/rollback", iacH.RollbackState)
		}
	})
}

func registerDeploymentRoutes(r chi.Router, depH *v1.DeploymentHandler, orgRepo domain.OrganizationRepository) {
	r.Route("/deployments", func(depRouter chi.Router) {
		depRouter.Get("/", depH.ListDeployments)
		depRouter.Get("/{id}", depH.GetDeployment)
		depRouter.Get("/{id}/logs", depH.GetLogs)
		depRouter.Get("/{id}/logs/stream", depH.StreamLogsSSE)

		if orgRepo != nil {
			adminOnly := customMiddleware.RequireOrganizationRole(orgRepo, domain.RoleAdmin)
			depRouter.With(adminOnly).Post("/", depH.CreateDeployment)
			depRouter.With(adminOnly).Post("/{id}/stop", depH.StopDeployment)
			depRouter.With(adminOnly).Post("/{id}/redeploy", depH.RedeployDeployment)
			depRouter.With(adminOnly).Post("/{id}/rollback", depH.RollbackDeployment)
			depRouter.With(adminOnly).Delete("/{id}", depH.DeleteDeployment)
		} else {
			depRouter.Post("/", depH.CreateDeployment)
			depRouter.Post("/{id}/stop", depH.StopDeployment)
			depRouter.Post("/{id}/redeploy", depH.RedeployDeployment)
			depRouter.Post("/{id}/rollback", depH.RollbackDeployment)
			depRouter.Delete("/{id}", depH.DeleteDeployment)
		}
	})
}

func registerNetworkRoutes(r chi.Router, netH *v1.NetworkHandler, orgRepo domain.OrganizationRepository) {
	r.Route("/networks", func(netRouter chi.Router) {
		netRouter.Get("/", netH.ListNetworks)
		if orgRepo != nil {
			adminOnly := customMiddleware.RequireOrganizationRole(orgRepo, domain.RoleAdmin)
			netRouter.With(adminOnly).Post("/", netH.CreateNetwork)
			netRouter.With(adminOnly).Delete("/{id}", netH.DeleteNetwork)
		} else {
			netRouter.Post("/", netH.CreateNetwork)
			netRouter.Delete("/{id}", netH.DeleteNetwork)
		}
	})

	r.Route("/firewall-rules", func(fwRouter chi.Router) {
		fwRouter.Get("/", netH.ListFirewallRules)
		if orgRepo != nil {
			adminOnly := customMiddleware.RequireOrganizationRole(orgRepo, domain.RoleAdmin)
			fwRouter.With(adminOnly).Post("/", netH.CreateFirewallRule)
			fwRouter.With(adminOnly).Delete("/{id}", netH.DeleteFirewallRule)
		} else {
			fwRouter.Post("/", netH.CreateFirewallRule)
			fwRouter.Delete("/{id}", netH.DeleteFirewallRule)
		}
	})
}

func registerSecurityRoutes(r chi.Router, secH *v1.SecurityHandler) {
	r.Route("/security", func(secRouter chi.Router) {
		secRouter.Get("/overview", secH.GetPostureOverview)
		secRouter.Post("/scans", secH.TriggerScan)
		secRouter.Get("/scans", secH.ListScans)
		secRouter.Get("/scans/{id}", secH.GetScan)

		secRouter.Get("/findings", secH.ListFindings)
		secRouter.Get("/findings/{id}", secH.GetFinding)
		secRouter.Patch("/findings/{id}/status", secH.UpdateFindingStatus)
		secRouter.Post("/findings/{id}/remediate", secH.RemediateFinding)
		secRouter.Post("/findings/{id}/reopen", secH.ReopenFinding)
		secRouter.Post("/findings/{id}/reverify", secH.ReverifyFinding)

		secRouter.Get("/incidents", secH.ListIncidents)
		secRouter.Post("/incidents", secH.CreateIncident)
		secRouter.Patch("/incidents/{id}/status", secH.UpdateIncidentStatus)
	})
}

func registerServerRoutes(r chi.Router, h *v1.ServerHandler, th *v1.TelemetryHandler, orgRepo domain.OrganizationRepository) {
	r.Route("/servers", func(serverRouter chi.Router) {
		if h != nil {
			serverRouter.Get("/", h.ListServers)
			serverRouter.Get("/{id}", h.GetServer)

			if orgRepo != nil {
				adminOnly := customMiddleware.RequireOrganizationRole(orgRepo, domain.RoleAdmin)
				serverRouter.With(adminOnly).Post("/", h.CreateServer)
				serverRouter.With(adminOnly).Patch("/{id}/resize", h.ResizeServer)
				serverRouter.With(adminOnly).Delete("/{id}", h.DeleteServer)
				serverRouter.With(adminOnly).Post("/{id}/reboot", h.RebootServer)
				serverRouter.With(adminOnly).Post("/{id}/shutdown", h.ShutdownServer)
				serverRouter.With(adminOnly).Post("/{id}/start", h.StartServer)
			} else {
				serverRouter.Post("/", h.CreateServer)
				serverRouter.Patch("/{id}/resize", h.ResizeServer)
				serverRouter.Delete("/{id}", h.DeleteServer)
				serverRouter.Post("/{id}/reboot", h.RebootServer)
				serverRouter.Post("/{id}/shutdown", h.ShutdownServer)
				serverRouter.Post("/{id}/start", h.StartServer)
			}
		}

		if th != nil {
			serverRouter.Get("/{id}/metrics/live", th.GetLiveMetrics)
			serverRouter.Get("/{id}/metrics/history", th.GetMetricHistory)
		}
	})
}

func registerAlertRoutes(r chi.Router, ah *v1.AlertHandler) {
	r.Route("/alerts", func(alertRouter chi.Router) {
		alertRouter.Get("/", ah.ListAlerts)
		alertRouter.Post("/{id}/acknowledge", ah.AcknowledgeAlert)
		alertRouter.Post("/{id}/resolve", ah.ResolveAlert)
		alertRouter.Get("/rules", ah.ListRules)
		alertRouter.Post("/rules", ah.CreateRule)
		alertRouter.Delete("/rules/{id}", ah.DeleteRule)
	})
}

func registerStorageRoutes(r chi.Router, sh *v1.StorageHandler) {
	r.Route("/storage", func(storageRouter chi.Router) {
		storageRouter.Get("/buckets", sh.ListBuckets)
		storageRouter.Post("/buckets", sh.CreateBucket)
		storageRouter.Post("/sync", sh.SyncBuckets)
		storageRouter.Get("/buckets/{name}", sh.GetBucket)
		storageRouter.Delete("/buckets/{name}", sh.DeleteBucket)

		storageRouter.Get("/buckets/{name}/objects", sh.ListObjects)
		storageRouter.Post("/buckets/{name}/objects", sh.UploadObject)
		storageRouter.Get("/buckets/{name}/objects/download", sh.DownloadObject)
		storageRouter.Delete("/buckets/{name}/objects", sh.DeleteObject)
		storageRouter.Post("/buckets/{name}/objects/signed-url", sh.GenerateSignedURL)
	})
}

func registerBackupRoutes(r chi.Router, bh *v1.BackupHandler) {
	r.Route("/backups", func(backupRouter chi.Router) {
		backupRouter.Get("/policies", bh.ListPolicies)
		backupRouter.Post("/policies", bh.CreatePolicy)
		backupRouter.Delete("/policies/{id}", bh.DeletePolicy)

		backupRouter.Post("/trigger/{server_id}", bh.TriggerBackup)
		backupRouter.Get("/records", bh.ListRecords)
		backupRouter.Delete("/records/{id}", bh.DeleteRecord)
	})
}

func registerAutomationRoutes(r chi.Router, autoH *v1.AutomationHandler) {
	r.Route("/automation", func(autoRouter chi.Router) {
		autoRouter.Get("/rules", autoH.ListRules)
		autoRouter.Post("/rules", autoH.CreateRule)
		autoRouter.Get("/rules/{id}", autoH.GetRule)
		autoRouter.Put("/rules/{id}", autoH.UpdateRule)
		autoRouter.Delete("/rules/{id}", autoH.DeleteRule)
		autoRouter.Post("/rules/{id}/test", autoH.TestRule)

		autoRouter.Get("/logs", autoH.ListLogs)
	})
}

func registerCredentialRoutes(r chi.Router, ch *v1.CredentialHandler, orgRepo domain.OrganizationRepository) {
	r.Route("/credentials", func(credRouter chi.Router) {
		if orgRepo != nil {
			credRouter.Use(customMiddleware.RequireOrganizationRole(orgRepo, domain.RoleAdmin))
		}
		credRouter.Get("/", ch.ListCredentials)
		credRouter.Post("/", ch.CreateCredential)
		credRouter.Get("/{id}", ch.GetCredential)
		credRouter.Put("/{id}", ch.UpdateCredential)
		credRouter.Delete("/{id}", ch.DeleteCredential)
		credRouter.Post("/{id}/test", ch.TestCredential)
	})
}
