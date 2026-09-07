'use client';

import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  Box,
  Play,
  RotateCcw,
  Terminal,
  StopCircle,
  Plus,
  RefreshCw,
  Search,
  Copy,
  Trash2,
  Check,
  CheckCircle2,
  AlertCircle,
  Clock,
  Layers,
  ArrowRight,
  Filter,
  ExternalLink,
  HardDrive,
} from 'lucide-react';
import { AppTheme } from '@/core/theme';
import { Deployment, DeploymentLog, DeploymentRequest, VolumeBinding } from '@/types/deployment';
import { deploymentService } from '@/services/deployment.service';
import { networkService, VirtualNetwork } from '@/services/network.service';
import { volumeService, StorageVolume } from '@/services/volume.service';
import { getApiBaseURL } from '@/services/api';

const QUICK_IMAGES = [
  { name: 'Nginx Web Server', tag: 'nginx:alpine', port: 80 },
  { name: 'Redis In-Memory Store', tag: 'redis:7-alpine', port: 6379 },
  { name: 'PostgreSQL Database', tag: 'postgres:16-alpine', port: 5432 },
  { name: 'Node.js Runtime', tag: 'node:20-alpine', port: 3000 },
];

export default function ContainersOrchestrationPage() {
  const [deployments, setDeployments] = useState<Deployment[]>([]);
  const [selectedDeployment, setSelectedDeployment] = useState<Deployment | null>(null);
  const [availableNetworks, setAvailableNetworks] = useState<VirtualNetwork[]>([]);
  const [availableVolumes, setAvailableVolumes] = useState<StorageVolume[]>([]);
  const [servers, setServers] = useState<any[]>([]);
  const [selectedServerFilter, setSelectedServerFilter] = useState<string>('all');
  const [logs, setLogs] = useState<DeploymentLog[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);
  const [isStreaming, setIsStreaming] = useState<boolean>(false);
  const [streamFilter, setStreamFilter] = useState<'all' | 'stdout' | 'stderr' | 'system'>('all');
  const [autoScroll, setAutoScroll] = useState<boolean>(true);
  const [copied, setCopied] = useState<boolean>(false);

  const [targetServerId, setTargetServerId] = useState<string>('');
  const [appName, setAppName] = useState<string>('');
  const [imageTag, setImageTag] = useState<string>('nginx:alpine');
  const [containerName, setContainerName] = useState<string>('');
  const [command, setCommand] = useState<string>('');
  const [selectedNetwork, setSelectedNetwork] = useState<string>('');
  const [hostPort, setHostPort] = useState<string>('');
  const [containerPort, setContainerPort] = useState<string>('');
  const [selectedVolName, setSelectedVolName] = useState<string>('');
  const [volMountDest, setVolMountDest] = useState<string>('');
  const [volumeMounts, setVolumeMounts] = useState<VolumeBinding[]>([]);
  const [envKey, setEnvKey] = useState<string>('');
  const [envVal, setEnvVal] = useState<string>('');
  const [envVars, setEnvVars] = useState<{ [key: string]: string }>({});
  const [restartPolicy, setRestartPolicy] = useState<string>('unless-stopped');
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);

  const terminalEndRef = useRef<HTMLDivElement>(null);

  const fetchDeployments = useCallback(async () => {
    try {
      setIsLoading(true);
      const data = await deploymentService.listDeployments();
      setDeployments(data);
      if (data.length > 0 && !selectedDeployment) {
        setSelectedDeployment(data[0]);
      }
    } catch (err) {
      console.error('Failed to list deployments:', err);
    } finally {
      setIsLoading(false);
    }
  }, [selectedDeployment]);

  useEffect(() => {
    fetchDeployments();
    networkService.listNetworks().then(setAvailableNetworks).catch(console.error);
    volumeService.listVolumes().then(setAvailableVolumes).catch(console.error);
    import('@/services/server.service').then((m) =>
      m.serverService.listServers().then((res) => {
        if (res && res.data) setServers(res.data);
      }).catch(console.error)
    );
  }, [fetchDeployments]);

  useEffect(() => {
    if (!selectedDeployment) return;

    deploymentService
      .getLogs(selectedDeployment.id, 200)
      .then((data) => {
        if (data) setLogs(data);
      })
      .catch(console.error);

    const sseUrl = `${getApiBaseURL()}/deployments/${selectedDeployment.id}/logs/stream`;

    let eventSource: EventSource | null = null;
    try {
      setIsStreaming(true);
      eventSource = new EventSource(sseUrl);

      eventSource.onmessage = (event) => {
        try {
          const newLog: DeploymentLog = JSON.parse(event.data);
          setLogs((prev) => {
            if (prev.some((l) => l.id === newLog.id || (l.message === newLog.message && l.timestamp === newLog.timestamp))) return prev;
            return [...prev, newLog];
          });
        } catch (e) {
          console.error('Failed to parse log line', e);
        }
      };

      eventSource.addEventListener('complete', () => {
        setIsStreaming(false);
      });

      eventSource.onerror = () => {
        setIsStreaming(false);
      };
    } catch (err) {
      console.error('SSE initialization error:', err);
      setIsStreaming(false);
    }

    const pollInterval = setInterval(() => {
      deploymentService
        .getLogs(selectedDeployment.id, 200)
        .then((data) => {
          if (data && data.length > 0) {
            setLogs((prev) => {
              if (prev.length !== data.length) {
                return data;
              }
              return prev;
            });
          }
        })
        .catch(() => {});
    }, 3000);

    return () => {
      if (eventSource) {
        eventSource.close();
      }
      clearInterval(pollInterval);
      setIsStreaming(false);
    };
  }, [selectedDeployment]);

  useEffect(() => {
    if (autoScroll && terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, autoScroll]);

  const handleAddEnv = () => {
    if (envKey.trim()) {
      setEnvVars((prev) => ({ ...prev, [envKey.trim()]: envVal }));
      setEnvKey('');
      setEnvVal('');
    }
  };

  const handleRemoveEnv = (key: string) => {
    setEnvVars((prev) => {
      const copy = { ...prev };
      delete copy[key];
      return copy;
    });
  };

  const handleAddVolumeMount = () => {
    if (!selectedVolName.trim() || !volMountDest.trim()) return;
    setVolumeMounts((prev) => [
      ...prev,
      {
        host_path: selectedVolName.trim(),
        container_path: volMountDest.trim(),
        mode: 'rw',
      },
    ]);
    setSelectedVolName('');
    setVolMountDest('');
  };

  const handleRemoveVolumeMount = (index: number) => {
    setVolumeMounts((prev) => prev.filter((_, i) => i !== index));
  };

  const handleDeploy = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!appName.trim() || !imageTag.trim()) return;

    try {
      setIsSubmitting(true);
      const req: DeploymentRequest = {
        server_id: targetServerId ? targetServerId : undefined,
        app_name: appName.trim(),
        image_tag: imageTag.trim(),
        container_name: containerName.trim() || undefined,
        command: command.trim() || undefined,
        port_bindings: (hostPort && containerPort && Number(hostPort) > 0 && Number(containerPort) > 0) ? [
          {
            host_port: Number(hostPort),
            container_port: Number(containerPort),
            protocol: 'tcp',
          },
        ] : [],
        volume_bindings: volumeMounts.length > 0 ? volumeMounts : undefined,
        environment_variables: envVars,
        restart_policy: restartPolicy,
        network_name: selectedNetwork || undefined,
      };

      const created = await deploymentService.createDeployment(req);
      setDeployments((prev) => [created, ...prev]);
      setSelectedDeployment(created);
      setIsModalOpen(false);
      
      setAppName('');
      setImageTag('nginx:alpine');
      setContainerName('');
      setCommand('');
      setEnvVars({});
      setVolumeMounts([]);
      setSelectedVolName('');
      setVolMountDest('');
    } catch (err: any) {
      alert(`Deployment failed: ${err?.response?.data?.message || err.message}`);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleStopDeployment = async (id: string) => {
    if (!confirm('Are you sure you want to stop this container?')) return;
    try {
      await deploymentService.stopDeployment(id);
      fetchDeployments();
    } catch (err: any) {
      alert(`Failed to stop: ${err?.response?.data?.message || err.message}`);
    }
  };

  const handleRedeploy = async (id: string) => {
    if (!confirm('Are you sure you want to redeploy this container?')) return;
    try {
      const redeployed = await deploymentService.redeployDeployment(id);
      fetchDeployments();
      setSelectedDeployment(redeployed);
    } catch (err: any) {
      alert(`Redeploy failed: ${err?.response?.data?.message || err.message}`);
    }
  };

  const handleDeleteDeployment = async (id: string) => {
    if (!confirm('Are you sure you want to permanently delete this container and remove its container instance?')) return;
    try {
      await deploymentService.deleteDeployment(id);
      setDeployments((prev) => prev.filter((d) => d.id !== id));
      if (selectedDeployment?.id === id) {
        setSelectedDeployment(null);
        setLogs([]);
      }
      fetchDeployments();
    } catch (err: any) {
      alert(`Delete failed: ${err?.response?.data?.message || err.message}`);
    }
  };

  const handleRollback = async (id: string) => {
    if (!confirm('Are you sure you want to rollback this container?')) return;
    try {
      const rolled = await deploymentService.rollbackDeployment(id);
      fetchDeployments();
      setSelectedDeployment(rolled);
    } catch (err: any) {
      alert(`Rollback failed: ${err?.response?.data?.message || err.message}`);
    }
  };

  const handleCopyLogs = () => {
    const text = logs.map((l) => `[${l.timestamp}] [${l.stream}] ${l.message}`).join('\n');
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'running':
        return (
          <span className="flex items-center gap-1.5 px-2 py-0.5 text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 rounded">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400"></span> RUNNING
          </span>
        );
      case 'pulling':
      case 'deploying':
      case 'building':
        return (
          <span className="flex items-center gap-1.5 px-2 py-0.5 text-[10px] font-semibold bg-sky-500/10 text-sky-400 border border-sky-500/30 rounded">
            <RefreshCw className="h-2.5 w-2.5 animate-spin" /> {status.toUpperCase()}
          </span>
        );
      case 'stopped':
        return (
          <span className="flex items-center gap-1.5 px-2 py-0.5 text-[10px] font-semibold bg-zinc-500/10 text-zinc-400 border border-zinc-500/30 rounded">
            STOPPED
          </span>
        );
      case 'failed':
        return (
          <span className="flex items-center gap-1.5 px-2 py-0.5 text-[10px] font-semibold bg-red-500/10 text-red-400 border border-red-500/30 rounded">
            FAILED
          </span>
        );
      default:
        return (
          <span className="flex items-center gap-1.5 px-2 py-0.5 text-[10px] font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30 rounded">
            {status.toUpperCase()}
          </span>
        );
    }
  };

  const filteredLogs = logs.filter((l) => {
    if (streamFilter === 'all') return true;
    return l.stream === streamFilter;
  });

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#262626] pb-5">
          <div>
            <h1 className="text-xl font-bold tracking-tight text-[#ededed]">Container Orchestration & Deployments</h1>
            <p className="text-xs text-[#a1a1a1] mt-1">
              Build, pull, deploy, and monitor containerized applications with live streaming log terminals.
            </p>
          </div>

        <button
          onClick={() => setIsModalOpen(true)}
          className="flex items-center gap-1.5 px-4 py-2 text-xs font-semibold bg-emerald-500 hover:bg-emerald-400 text-zinc-950 rounded-lg shadow-sm transition-colors cursor-pointer"
        >
          <Plus className="h-3.5 w-3.5" />
          Deploy New Container
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-5 space-y-4">
          <div className="bg-[#171717] border border-[#262626] rounded-xl p-4 space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <span className="text-xs font-bold text-[#ededed] uppercase tracking-wider">Active Deployments</span>
              
              <div className="flex items-center gap-2">
                <select
                  value={selectedServerFilter}
                  onChange={(e) => setSelectedServerFilter(e.target.value)}
                  className="bg-[#121212] border border-[#2e2e2e] rounded-lg px-2.5 py-1 text-[11px] text-[#ededed] focus:outline-none focus:border-purple-500 font-mono cursor-pointer"
                >
                  <option value="all">All Nodes ({deployments.length})</option>
                  <option value="local">Local Host ({deployments.filter(d => !d.server_id).length})</option>
                  {servers.map((s: any) => (
                    <option key={s.id} value={s.id}>
                      {s.name} ({deployments.filter(d => d.server_id === s.id).length})
                    </option>
                  ))}
                </select>
                <button onClick={fetchDeployments} className="text-[#707070] hover:text-[#ededed] p-1 cursor-pointer" title="Refresh">
                  <RefreshCw className={`h-3.5 w-3.5 ${isLoading ? 'animate-spin' : ''}`} />
                </button>
              </div>
            </div>

            <div className="space-y-2 max-h-[600px] overflow-y-auto">
              {deployments
                .filter((d) => {
                  if (selectedServerFilter === 'all') return true;
                  if (selectedServerFilter === 'local') return !d.server_id;
                  return d.server_id === selectedServerFilter;
                })
                .map((d) => {
                  const srv = servers.find((s: any) => s.id === d.server_id);

                  return (
                    <div
                      key={d.id}
                      onClick={() => setSelectedDeployment(d)}
                      className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
                        selectedDeployment?.id === d.id
                          ? 'bg-purple-950/10 border-purple-500/40 shadow-sm'
                          : 'bg-[#121212] border-[#262626] hover:border-[#383838]'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Box className="h-4 w-4 text-purple-400" />
                          <span className="text-xs font-bold text-[#ededed] font-mono">{d.app_name}</span>
                        </div>
                        {getStatusBadge(d.status)}
                      </div>

                      <div className="flex items-center gap-2 mt-1.5 flex-wrap">
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300 border border-zinc-700">
                          {srv ? srv.name : 'Local Host'}
                        </span>
                        <p className="text-[11px] font-mono text-[#a1a1a1] truncate">{d.image_tag}</p>
                        {d.network_name && (
                          <span className="px-1.5 py-0.5 text-[9px] font-mono bg-cyan-950/60 text-cyan-400 border border-cyan-500/30 rounded">
                            VPC: {d.network_name}
                          </span>
                        )}
                      </div>

                      <div className="mt-2 pt-2 border-t border-[#222222] flex items-center justify-between text-[10px] text-[#707070]">
                        <span>Port: {d.port_bindings?.[0]?.host_port || 80}:{d.port_bindings?.[0]?.container_port || 80}</span>
                        <div className="flex items-center gap-1.5">
                          {d.status === 'running' && (
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                handleStopDeployment(d.id);
                              }}
                              className="px-2 py-0.5 text-[10px] font-medium text-amber-400 hover:text-amber-300 bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 rounded transition-colors"
                            >
                              Stop
                            </button>
                          )}
                          {(d.status === 'stopped' || d.status === 'failed') && (
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                handleRedeploy(d.id);
                              }}
                              className="px-2 py-0.5 text-[10px] font-medium text-emerald-400 hover:text-emerald-300 bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 rounded transition-colors"
                            >
                              Redeploy
                            </button>
                          )}
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleDeleteDeployment(d.id);
                            }}
                            className="px-2 py-0.5 text-[10px] font-medium text-red-400 hover:text-red-300 bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 rounded transition-colors flex items-center gap-1"
                            title="Delete container"
                          >
                            <Trash2 className="h-2.5 w-2.5" />
                            Delete
                          </button>
                        </div>
                      </div>
                    </div>
                  );
                })}

              {deployments.filter((d) => {
                if (selectedServerFilter === 'all') return true;
                if (selectedServerFilter === 'local') return !d.server_id;
                return d.server_id === selectedServerFilter;
              }).length === 0 && !isLoading && (
                <div className="p-8 text-center text-xs text-[#707070]">
                  No containers deployed on this node yet. Click &quot;Deploy New Container&quot; to begin.
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="lg:col-span-7 space-y-4">
          <div className="bg-[#0f1218] border border-[#22272e] rounded-xl overflow-hidden shadow-lg flex flex-col h-[650px]">
            <div className="bg-[#13171f] border-b border-[#22272e] flex flex-col">
              <div className="px-4 py-2.5 flex items-center justify-between border-b border-[#1c2128]">
                <div className="flex items-center gap-2.5">
                  <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-800/80 border border-slate-700/60">
                    <Terminal className="h-3.5 w-3.5 text-emerald-400" />
                    <span className="text-xs font-mono font-semibold text-slate-200">
                      {selectedDeployment ? selectedDeployment.app_name : 'Terminal Logs'}
                    </span>
                  </div>
                  {selectedDeployment && (
                    <span className="text-[11px] font-mono text-slate-500 hidden sm:inline truncate max-w-[200px]">
                      {selectedDeployment.image_tag}
                    </span>
                  )}
                </div>

                <div className="flex items-center gap-2.5">
                  {selectedDeployment && selectedDeployment.port_bindings?.[0]?.host_port && (
                    <a
                      href={`http://localhost:${selectedDeployment.port_bindings[0].host_port}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-2.5 py-1 text-[11px] font-medium bg-purple-500/15 hover:bg-purple-500/25 text-purple-300 border border-purple-500/40 rounded-lg flex items-center gap-1.5 transition-all shadow-sm cursor-pointer"
                      title="Open Application in New Tab"
                    >
                      <ExternalLink className="h-3 w-3" />
                      <span>:{selectedDeployment.port_bindings[0].host_port}</span>
                    </a>
                  )}
                  {selectedDeployment && (
                    <span className="text-[10px] font-mono text-zinc-500">
                      ID: {selectedDeployment.id.slice(0, 8)}
                    </span>
                  )}
                </div>
              </div>

              <div className="px-4 py-2 flex items-center justify-between bg-[#0d1117]">
                <div className="flex items-center gap-1">
                  {(['all', 'stdout', 'stderr', 'system'] as const).map((filter) => (
                    <button
                      key={filter}
                      onClick={() => setStreamFilter(filter)}
                      className={`px-2.5 py-0.5 text-[11px] font-medium rounded-md transition-colors cursor-pointer ${
                        streamFilter === filter
                          ? 'bg-zinc-800 text-zinc-100 font-semibold'
                          : 'text-zinc-500 hover:text-zinc-300'
                      }`}
                    >
                      {filter.toUpperCase()}
                    </button>
                  ))}
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setAutoScroll(!autoScroll)}
                    className={`text-[10px] px-2 py-0.5 rounded border transition-colors cursor-pointer ${
                      autoScroll
                        ? 'border-emerald-500/40 text-emerald-400 bg-emerald-500/10'
                        : 'border-zinc-700 text-zinc-500 hover:text-zinc-300'
                    }`}
                  >
                    Auto-Scroll: {autoScroll ? 'ON' : 'OFF'}
                  </button>
                  <button
                    onClick={handleCopyLogs}
                    className="p-1 text-zinc-400 hover:text-zinc-100 rounded transition-colors cursor-pointer"
                    title="Copy Logs"
                  >
                    {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                  </button>
                </div>
              </div>
            </div>

            <div className="flex-1 p-4 font-mono text-xs overflow-y-auto bg-[#0a0c10] text-[#c9d1d9] space-y-1">
              {filteredLogs.map((log) => {
                let colorClass = 'text-zinc-300';
                if (log.stream === 'stderr') colorClass = 'text-rose-400';
                if (log.stream === 'system') colorClass = 'text-cyan-400 font-semibold';

                return (
                  <div key={log.id} className="leading-relaxed flex items-start gap-2 break-all hover:bg-slate-900/40 py-0.5 px-1 rounded">
                    <span className="text-[10px] text-zinc-600 select-none shrink-0 font-mono">
                      {new Date(log.timestamp).toLocaleTimeString()}
                    </span>
                    <span className={`text-[10px] uppercase font-bold shrink-0 ${
                      log.stream === 'stderr' ? 'text-rose-500' : log.stream === 'system' ? 'text-cyan-500' : 'text-zinc-500'
                    }`}>
                      [{log.stream}]
                    </span>
                    <span className={colorClass}>{log.message}</span>
                  </div>
                );
              })}
              {filteredLogs.length === 0 && (
                <div className="flex flex-col items-center justify-center h-full text-zinc-600 space-y-2">
                  <Terminal className="h-8 w-8 opacity-40" />
                  <p className="text-xs font-mono">Waiting for container log output...</p>
                </div>
              )}
              <div ref={terminalEndRef} />
            </div>
          </div>
        </div>
      </div>

      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4">
          <div className="bg-[#171717] border border-[#262626] rounded-2xl w-full max-w-xl max-h-[90vh] overflow-y-auto shadow-2xl p-6 space-y-5">
            <div className="flex items-center justify-between border-b border-[#262626] pb-4">
              <div className="flex items-center gap-2">
                <Box className="h-5 w-5 text-emerald-400" />
                <h3 className="text-sm font-bold text-[#ededed]">Deploy New Container</h3>
              </div>
              <button
                onClick={() => setIsModalOpen(false)}
                className="text-[#707070] hover:text-[#ededed] text-lg font-bold cursor-pointer"
              >
                &times;
              </button>
            </div>

            <form onSubmit={handleDeploy} className="space-y-4">
              <div>
                <label className="text-[11px] font-medium text-[#a1a1a1]">Target Server / Host Node</label>
                <select
                  value={targetServerId}
                  onChange={(e) => {
                    setTargetServerId(e.target.value);
                    setVolumeMounts([]);
                    setSelectedVolName('');
                    setVolMountDest('');
                  }}
                  className="w-full bg-[#121212] border border-[#2e2e2e] rounded-lg px-3 py-1.5 text-xs text-[#ededed] focus:outline-none focus:border-purple-500 font-mono mt-1 cursor-pointer"
                >
                  <option value="">Local Host (Current Machine)</option>
                  {servers.map((s: any) => (
                    <option key={s.id} value={s.id}>
                      {s.name} ({s.ip_address || s.ipAddress || "Agent Node"} - {s.status})
                    </option>
                  ))}
                </select>
              </div>

              <div className="space-y-1.5">
                <label className="text-[11px] font-medium text-[#a1a1a1]">Quick Image Presets</label>
                <div className="grid grid-cols-2 gap-2">
                  {QUICK_IMAGES.map((img) => (
                    <button
                      key={img.tag}
                      type="button"
                      onClick={() => {
                        setImageTag(img.tag);
                        setContainerPort(String(img.port));
                        if (!appName) setAppName(img.name.toLowerCase().replace(/\s+/g, '-'));
                      }}
                      className="p-2 text-left bg-[#121212] hover:bg-[#1f1f1f] border border-[#262626] hover:border-purple-500/40 rounded-lg text-xs transition-colors cursor-pointer"
                    >
                      <p className="font-semibold text-[#ededed]">{img.name}</p>
                      <p className="text-[10px] text-[#707070] font-mono">{img.tag}</p>
                    </button>
                  ))}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[11px] font-medium text-[#a1a1a1]">App Name *</label>
                  <input
                    type="text"
                    required
                    value={appName}
                    onChange={(e) => setAppName(e.target.value)}
                    placeholder="e.g. backend-api"
                    className="w-full bg-[#121212] border border-[#2e2e2e] rounded-lg px-3 py-1.5 text-xs text-[#ededed] focus:outline-none focus:border-purple-500"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-medium text-[#a1a1a1]">Docker Image *</label>
                  <input
                    type="text"
                    required
                    value={imageTag}
                    onChange={(e) => setImageTag(e.target.value)}
                    placeholder="e.g. nginx:alpine"
                    className="w-full bg-[#121212] border border-[#2e2e2e] rounded-lg px-3 py-1.5 text-xs text-[#ededed] font-mono focus:outline-none focus:border-purple-500"
                  />
                </div>
              </div>

              <div>
                <label className="text-[11px] font-medium text-[#a1a1a1]">Command / Arguments (Opsional)</label>
                <input
                  type="text"
                  value={command}
                  onChange={(e) => setCommand(e.target.value)}
                  placeholder="e.g. tunnel --url http://caelus-frontend:3000"
                  className="w-full bg-[#121212] border border-[#2e2e2e] rounded-lg px-3 py-1.5 text-xs text-[#ededed] font-mono focus:outline-none focus:border-purple-500"
                />
              </div>

              <div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="text-[11px] font-medium text-[#a1a1a1]">Host Port (Opsional)</label>
                    <input
                      type="number"
                      placeholder="e.g. 8081 (Kosong jika tunnel/worker)"
                      value={hostPort}
                      onChange={(e) => setHostPort(e.target.value)}
                      className="w-full bg-[#121212] border border-[#2e2e2e] rounded-lg px-3 py-1.5 text-xs text-[#ededed] font-mono focus:outline-none focus:border-purple-500"
                    />
                  </div>
                  <div>
                    <label className="text-[11px] font-medium text-[#a1a1a1]">Container Port (Opsional)</label>
                    <input
                      type="number"
                      placeholder="e.g. 80"
                      value={containerPort}
                      onChange={(e) => setContainerPort(e.target.value)}
                      className="w-full bg-[#121212] border border-[#2e2e2e] rounded-lg px-3 py-1.5 text-xs text-[#ededed] font-mono focus:outline-none focus:border-purple-500"
                    />
                  </div>
                </div>
                <p className="text-[10px] text-[#707070] mt-1">
                  Leave both ports blank if the container does not require public exposure (e.g., Cloudflare Tunnel / background jobs).
                </p>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <label className="text-[11px] font-medium text-[#a1a1a1]">Persistent Storage Volumes (Optional)</label>
                  <span className="text-[10px] text-zinc-500 font-mono">
                    {availableVolumes.filter(v => (v.server_id || '') === (targetServerId || '')).length} volumes available on this node
                  </span>
                </div>

                <div className="grid grid-cols-12 gap-2">
                  <div className="col-span-6">
                    <select
                      value={selectedVolName}
                      onChange={(e) => {
                        const name = e.target.value;
                        setSelectedVolName(name);
                        const found = availableVolumes.find(v => v.name === name);
                        if (found && !volMountDest) {
                          setVolMountDest(found.mount_path || '/mnt/data');
                        }
                      }}
                      className="w-full bg-[#121212] border border-[#2e2e2e] rounded-lg px-2.5 py-1.5 text-xs text-[#ededed] font-mono focus:outline-none focus:border-purple-500 cursor-pointer"
                    >
                      <option value="">-- Select Registered Volume --</option>
                      {availableVolumes
                        .filter(v => (v.server_id || '') === (targetServerId || ''))
                        .map((v) => (
                          <option key={v.id} value={v.name}>
                            {v.name} ({v.size_gb || v.sizeGB} GB - {v.type})
                          </option>
                        ))}
                    </select>
                  </div>
                  <div className="col-span-4">
                    <input
                      type="text"
                      value={volMountDest}
                      onChange={(e) => setVolMountDest(e.target.value)}
                      placeholder="Container Mount Path (/mnt/data)"
                      className="w-full bg-[#121212] border border-[#2e2e2e] rounded-lg px-2.5 py-1.5 text-xs text-[#ededed] font-mono focus:outline-none focus:border-purple-500"
                    />
                  </div>
                  <div className="col-span-2">
                    <button
                      type="button"
                      onClick={handleAddVolumeMount}
                      disabled={!selectedVolName || !volMountDest}
                      className="w-full h-full py-1.5 text-xs bg-purple-600/20 hover:bg-purple-600/30 text-purple-300 border border-purple-500/40 rounded-lg font-medium disabled:opacity-40 disabled:cursor-not-allowed transition-colors cursor-pointer"
                    >
                      + Mount
                    </button>
                  </div>
                </div>

                {volumeMounts.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    {volumeMounts.map((vm, idx) => (
                      <span
                        key={idx}
                        className="inline-flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-mono bg-purple-950/40 text-purple-300 border border-purple-500/40 rounded-lg shadow-xs"
                      >
                        <HardDrive className="w-3 h-3 text-purple-400" />
                        <span>{vm.host_path}</span>
                        <span className="text-zinc-500">➔</span>
                        <span className="text-emerald-400">{vm.container_path}</span>
                        <button
                          type="button"
                          onClick={() => handleRemoveVolumeMount(idx)}
                          className="hover:text-red-400 ml-1 font-bold cursor-pointer"
                          title="Remove mount"
                        >
                          &times;
                        </button>
                      </span>
                    ))}
                  </div>
                )}
              </div>

              <div>
                <label className="text-[11px] font-medium text-[#a1a1a1]">VPC Network / Isolation</label>
                <select
                  value={selectedNetwork}
                  onChange={(e) => setSelectedNetwork(e.target.value)}
                  className="w-full bg-[#121212] border border-[#2e2e2e] rounded-lg px-3 py-1.5 text-xs text-[#ededed] focus:outline-none focus:border-purple-500 cursor-pointer"
                >
                  <option value="">Default Host Bridge (caelus-network)</option>
                  {availableNetworks.map((net) => (
                    <option key={net.id} value={net.name}>
                      {net.name} ({net.cidr} - {net.region})
                    </option>
                  ))}
                </select>
              </div>

              <div className="space-y-2">
                <label className="text-[11px] font-medium text-[#a1a1a1]">Environment Variables</label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={envKey}
                    onChange={(e) => setEnvKey(e.target.value)}
                    placeholder="KEY (e.g. NODE_ENV)"
                    className="flex-1 bg-[#121212] border border-[#2e2e2e] rounded-lg px-3 py-1 text-xs text-[#ededed] font-mono"
                  />
                  <input
                    type="text"
                    value={envVal}
                    onChange={(e) => setEnvVal(e.target.value)}
                    placeholder="VALUE"
                    className="flex-1 bg-[#121212] border border-[#2e2e2e] rounded-lg px-3 py-1 text-xs text-[#ededed] font-mono"
                  />
                  <button
                    type="button"
                    onClick={handleAddEnv}
                    className="px-3 py-1 text-xs bg-zinc-800 hover:bg-zinc-700 text-[#ededed] rounded-lg border border-zinc-700 cursor-pointer"
                  >
                    Add
                  </button>
                </div>

                {Object.keys(envVars).length > 0 && (
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    {Object.entries(envVars).map(([k, v]) => (
                      <span
                        key={k}
                        className="inline-flex items-center gap-1.5 px-2 py-0.5 text-[10px] font-mono bg-[#1f1f1f] text-emerald-400 border border-[#333333] rounded"
                      >
                        {k}={v}
                        <button type="button" onClick={() => handleRemoveEnv(k)} className="hover:text-red-400 cursor-pointer">
                          &times;
                        </button>
                      </span>
                    ))}
                  </div>
                )}
              </div>

              <div className="flex items-center justify-end gap-3 pt-4 border-t border-[#262626] sticky bottom-0 bg-[#171717]/95 backdrop-blur-xs pb-1">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="px-4 py-2 text-xs font-medium text-[#a1a1a1] hover:text-[#ededed] rounded-lg transition-colors cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-5 py-2 text-xs font-semibold bg-emerald-500 hover:bg-emerald-400 text-zinc-950 rounded-lg shadow-lg cursor-pointer disabled:opacity-50 transition-all"
                >
                  {isSubmitting ? 'Deploying Container...' : 'Launch Container Now'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
