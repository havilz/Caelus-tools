import { useAuthStore } from "@/stores/useAuthStore";
import { OrganizationRole } from "@/types/settings";

export function useRoleGuard() {
  const organization = useAuthStore((state) => state.organization);
  const currentRole: OrganizationRole = (organization?.role as OrganizationRole) || "owner";

  const isOwner = currentRole === "owner";
  const isAdmin = isOwner || currentRole === "admin";
  const isMember = currentRole === "member";
  const isViewer = currentRole === "viewer";

  const canManageCredentials = isAdmin;
  const canManageServers = isAdmin;
  const canDeleteServer = isAdmin;
  const canManageTeam = isAdmin;
  const canChangeRoles = isOwner;
  const canDeploy = isAdmin;

  return {
    role: currentRole,
    isOwner,
    isAdmin,
    isMember,
    isViewer,
    canManageCredentials,
    canManageServers,
    canDeleteServer,
    canManageTeam,
    canChangeRoles,
    canDeploy,
  };
}
