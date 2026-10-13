"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import {
  Server as ServerIcon,
  Plus,
  RefreshCw,
  Search,
  Sliders,
  Power,
  PowerOff,
  Trash2,
  Copy,
  Check,
  ExternalLink,
  RotateCcw,
  Terminal,
} from "lucide-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ServerStatusBadge } from "@/components/server/ServerStatusBadge";
import { CreateServerModal } from "@/components/server/CreateServerModal";
import { ResizeServerModal } from "@/components/server/ResizeServerModal";
import { ConnectAgentModal } from "@/components/server/ConnectAgentModal";
import { useServerStore } from "@/stores/useServerStore";
import { Server } from "@/types/server";
import { AppContainers, AppText } from "@/core/theme";
import { useRoleGuard } from "@/hooks/useRoleGuard";

export default function VPSManagementPage() {
  const { canManageServers, canDeleteServer } = useRoleGuard();
  const {
    servers,
    totalServers,
    currentPage,
    totalPages,
    isLoading,
    fetchServers,
    rebootServer,
    shutdownServer,
    startServer,
    deleteServer,
  } = useServerStore();

  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [resizeTarget, setResizeTarget] = useState<Server | null>(null);
  const [connectTarget, setConnectTarget] = useState<Server | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [copiedIP, setCopiedIP] = useState<string | null>(null);
  const [activeActionID, setActiveActionID] = useState<string | null>(null);

  useEffect(() => {
    fetchServers(1);
  }, [fetchServers]);

  const handleCopyIP = (ip?: string) => {
    if (!ip) return;
    navigator.clipboard.writeText(ip);
    setCopiedIP(ip);
    setTimeout(() => setCopiedIP(null), 2000);
  };

  const filteredServers = servers.filter((s) => {
    const matchesSearch =
      s.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      Boolean(s.ip_address?.includes(searchQuery));
    const matchesStatus = statusFilter === "all" || s.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  const handleAction = async (id: string, actionFn: (id: string) => Promise<void>) => {
    setActiveActionID(id);
    try {
      await actionFn(id);
    } finally {
      setActiveActionID(null);
    }
  };

  return (
    <div className={AppContainers.pageWrapper}>
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h2 className={AppText.h2}>
            VPS & Virtual Servers Management
          </h2>
          <p className={AppText.subtitle}>
            Manage, monitor, and orchestrate all VPS server instances from a unified control panel.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            size="sm"
            onClick={() => fetchServers(currentPage)}
            isLoading={isLoading}
            className="cursor-pointer"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            <span>Refresh</span>
          </Button>

          {canManageServers && (
            <Button
              size="sm"
              onClick={() => setIsCreateOpen(true)}
              className="cursor-pointer"
            >
              <Plus className="h-4 w-4" />
              <span>Add / Connect Server</span>
            </Button>
          )}
        </div>
      </div>

      <div className="flex flex-col sm:flex-row items-center gap-3">
        <div className="relative flex-1 w-full">
          <Search className="h-3.5 w-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-[#707070]" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by server name or IP address..."
            className="w-full pl-9 pr-4 py-2 text-xs rounded-lg border border-[#262626] dark:border-[#262626] light:border-[#d1d5db] bg-[#121212] dark:bg-[#121212] light:bg-[#ffffff] text-[#ededed] dark:text-[#ededed] light:text-[#111827] placeholder-[#707070] focus:border-emerald-500 focus:outline-none transition-colors"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-2 text-xs rounded-lg border border-[#262626] dark:border-[#262626] light:border-[#d1d5db] bg-[#121212] dark:bg-[#121212] light:bg-[#ffffff] text-[#ededed] dark:text-[#ededed] light:text-[#111827] focus:border-emerald-500 focus:outline-none"
          >
            <option value="all">All Statuses</option>
            <option value="running">Running</option>
            <option value="stopped">Stopped</option>
            <option value="restarting">Restarting</option>
          </select>
        </div>
      </div>

      <Card className="overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-[#ededed] dark:text-[#ededed] light:text-[#111827]">
            <thead className="border-b border-[#262626] dark:border-[#262626] light:border-[#e5e7eb] bg-[#141414] dark:bg-[#141414] light:bg-[#f4f4f5] text-[11px] font-semibold uppercase tracking-wider text-[#a1a1a1]">
              <tr>
                <th className="px-5 py-3.5">Instance Name</th>
                <th className="px-5 py-3.5">Status</th>
                <th className="px-5 py-3.5">Provider</th>
                <th className="px-5 py-3.5">IP Address</th>
                <th className="px-5 py-3.5">Specifications</th>
                <th className="px-5 py-3.5">Region & OS</th>
                <th className="px-5 py-3.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#262626] dark:divide-[#262626] light:divide-[#e5e7eb]">
              {filteredServers.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center py-12 text-[#707070]">
                    <ServerIcon className="h-8 w-8 mx-auto text-[#404040] mb-2" />
                    <p className="text-sm text-zinc-400 font-medium">
                      {searchQuery
                        ? "No servers matching search criteria"
                        : "No servers registered yet."}
                    </p>
                    {!searchQuery && canManageServers && (
                      <div className="mt-4">
                        <Button
                          size="sm"
                          onClick={() => setIsCreateOpen(true)}
                          className="cursor-pointer inline-flex items-center gap-1.5"
                        >
                          <Plus className="h-4 w-4" />
                          <span>Add / Connect Server</span>
                        </Button>
                      </div>
                    )}
                  </td>
                </tr>
              ) : (
                filteredServers.map((server) => {
                  const isActionLoading = activeActionID === server.id;

                  return (
                    <tr key={server.id} className="hover:bg-[#1a1a1a] dark:hover:bg-[#1a1a1a] light:hover:bg-[#f3f4f6] transition-colors">
                      <td className="px-5 py-4 font-medium">
                        <Link
                          href={`/infrastructure/vps/${server.id}`}
                          className="hover:text-emerald-400 transition-colors flex items-center gap-1.5 font-semibold text-xs text-[#ededed] dark:text-[#ededed] light:text-[#111827]"
                        >
                          <span>{server.name}</span>
                          <ExternalLink className="h-3 w-3 text-[#707070]" />
                        </Link>
                        <span className={AppText.caption}>
                          ID: {server.id.slice(0, 8)}...
                        </span>
                      </td>

                      <td className="px-5 py-4">
                        <ServerStatusBadge status={server.status} />
                      </td>

                      <td className="px-5 py-4">
                        <Badge variant="outline" className="text-[10px] py-0 px-2">
                          {server.provider?.name || "Mock Provider"}
                        </Badge>
                      </td>

                      <td className="px-5 py-4 font-mono">
                        {server.ip_address ? (
                          <button
                            type="button"
                            onClick={() => handleCopyIP(server.ip_address)}
                            className="flex items-center gap-1.5 text-[#a1a1a1] hover:text-emerald-400 transition-colors cursor-pointer"
                            title="Copy IP Address"
                          >
                            <span>{server.ip_address}</span>
                            {copiedIP === server.ip_address ? (
                              <Check className="h-3 w-3 text-emerald-400" />
                            ) : (
                              <Copy className="h-3 w-3 text-[#707070]" />
                            )}
                          </button>
                        ) : (
                          <span className="text-[#707070] text-[11px]">-</span>
                        )}
                      </td>

                      <td className="px-5 py-4">
                        <div className="font-medium text-[#ededed] dark:text-[#ededed] light:text-[#111827]">
                          {server.cpu_cores} vCPU • {(server.memory_mb / 1024).toFixed(0)} GB RAM
                        </div>
                        <span className={AppText.caption}>{server.disk_gb} GB SSD</span>
                      </td>

                      <td className="px-5 py-4">
                        <div className="text-[#ededed] dark:text-[#ededed] light:text-[#111827]">{server.region}</div>
                        <span className={AppText.caption}>{server.os_type}</span>
                      </td>

                      <td className="px-5 py-4 text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            type="button"
                            onClick={() => setConnectTarget(server)}
                            className="p-1.5 rounded-md text-emerald-400 hover:bg-emerald-950/40 border border-emerald-500/20 transition-colors cursor-pointer"
                            title="Connect Agent Instructions"
                          >
                            <Terminal className="h-3.5 w-3.5" />
                          </button>

                          {canManageServers ? (
                            <>
                              <button
                                type="button"
                                disabled={isActionLoading || server.status !== "running"}
                                onClick={() => handleAction(server.id, rebootServer)}
                                className="p-1.5 rounded-md text-[#a1a1a1] hover:text-emerald-400 hover:bg-[#202020] disabled:opacity-30 disabled:cursor-not-allowed transition-colors cursor-pointer"
                                title="Reboot Server"
                              >
                                <RotateCcw className="h-3.5 w-3.5" />
                              </button>

                              {server.status === "running" ? (
                                <button
                                  type="button"
                                  disabled={isActionLoading}
                                  onClick={() => handleAction(server.id, shutdownServer)}
                                  className="p-1.5 rounded-md text-[#a1a1a1] hover:text-amber-400 hover:bg-[#202020] disabled:opacity-30 transition-colors cursor-pointer"
                                  title="Shutdown Server"
                                >
                                  <PowerOff className="h-3.5 w-3.5" />
                                </button>
                              ) : (
                                <button
                                  type="button"
                                  disabled={isActionLoading}
                                  onClick={() => handleAction(server.id, startServer)}
                                  className="p-1.5 rounded-md text-[#a1a1a1] hover:text-emerald-400 hover:bg-[#202020] disabled:opacity-30 transition-colors cursor-pointer"
                                  title="Start Server"
                                >
                                  <Power className="h-3.5 w-3.5" />
                                </button>
                              )}

                              <button
                                type="button"
                                disabled={isActionLoading}
                                onClick={() => setResizeTarget(server)}
                                className="p-1.5 rounded-md text-[#a1a1a1] hover:text-[#ededed] hover:bg-[#202020] transition-colors cursor-pointer"
                                title="Resize Specifications"
                              >
                                <Sliders className="h-3.5 w-3.5" />
                              </button>

                              {canDeleteServer && (
                                <button
                                  type="button"
                                  disabled={isActionLoading}
                                  onClick={() => {
                                    if (confirm(`Are you sure you want to terminate server ${server.name}?`)) {
                                      handleAction(server.id, deleteServer);
                                    }
                                  }}
                                  className="p-1.5 rounded-md text-[#a1a1a1] hover:text-rose-400 hover:bg-rose-950/40 transition-colors cursor-pointer"
                                  title="Delete / Terminate Server"
                                >
                                  <Trash2 className="h-3.5 w-3.5" />
                                </button>
                              )}
                            </>
                          ) : (
                            <span className="text-[11px] text-[#707070] italic font-mono px-2">Read-only</span>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {totalPages > 1 && (
          <div className="flex items-center justify-between p-4 border-t border-[#262626] dark:border-[#262626] light:border-[#e5e7eb] bg-[#141414] dark:bg-[#141414] light:bg-[#f4f4f5] text-xs text-[#a1a1a1]">
            <span>
              Showing page {currentPage} of {totalPages} ({totalServers} total servers)
            </span>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                disabled={currentPage <= 1 || isLoading}
                onClick={() => fetchServers(currentPage - 1)}
              >
                Previous
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={currentPage >= totalPages || isLoading}
                onClick={() => fetchServers(currentPage + 1)}
              >
                Next
              </Button>
            </div>
          </div>
        )}
      </Card>

      <CreateServerModal isOpen={isCreateOpen} onClose={() => setIsCreateOpen(false)} />
      <ResizeServerModal
        server={resizeTarget}
        isOpen={Boolean(resizeTarget)}
        onClose={() => setResizeTarget(null)}
      />
      <ConnectAgentModal
        server={connectTarget}
        isOpen={Boolean(connectTarget)}
        onClose={() => setConnectTarget(null)}
      />
    </div>
  );
}
