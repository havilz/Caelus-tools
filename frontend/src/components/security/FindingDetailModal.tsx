"use client";

import React, { useState } from "react";
import { AppTheme } from "@/core/theme";
import { SecurityFinding, FindingStatus } from "@/types/security";
import {
  X,
  ShieldAlert,
  Terminal,
  CheckCircle2,
  AlertTriangle,
  Copy,
  Check,
  Server,
  Layers,
  Wrench,
  Loader2,
  RotateCw,
} from "lucide-react";

interface FindingDetailModalProps {
  finding: SecurityFinding | null;
  isOpen: boolean;
  onClose: () => void;
  onUpdateStatus: (findingId: string, status: FindingStatus) => Promise<void>;
  onRemediate?: (findingId: string) => Promise<void>;
  onReopen?: (findingId: string) => Promise<void>;
  onReverify?: (findingId: string) => Promise<void>;
}

export const FindingDetailModal: React.FC<FindingDetailModalProps> = ({
  finding,
  isOpen,
  onClose,
  onUpdateStatus,
  onRemediate,
  onReopen,
  onReverify,
}) => {
  const [copied, setCopied] = useState(false);
  const [isUpdating, setIsUpdating] = useState(false);
  const [isRemediating, setIsRemediating] = useState(false);
  const [isReverifying, setIsReverifying] = useState(false);
  const [remediationSuccess, setRemediationSuccess] = useState(false);

  if (!isOpen || !finding) return null;

  const handleCopyCommand = () => {
    if (finding.remediation_command) {
      navigator.clipboard.writeText(finding.remediation_command);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleRemediate = async () => {
    if (!onRemediate || !finding) return;
    setIsRemediating(true);
    try {
      await onRemediate(finding.id);
      setRemediationSuccess(true);
      setTimeout(() => {
        setRemediationSuccess(false);
        onClose();
      }, 1500);
    } catch (err) {
      console.error("Auto remediation failed:", err);
    } finally {
      setIsRemediating(false);
    }
  };

  const handleReopen = async () => {
    if (!onReopen || !finding) return;
    setIsUpdating(true);
    try {
      await onReopen(finding.id);
      onClose();
    } catch (err) {
      console.error("Failed to reopen finding:", err);
    } finally {
      setIsUpdating(false);
    }
  };

  const handleReverify = async () => {
    if (!onReverify || !finding) return;
    setIsReverifying(true);
    try {
      await onReverify(finding.id);
      onClose();
    } catch (err) {
      console.error("Failed to reverify finding:", err);
    } finally {
      setIsReverifying(false);
    }
  };

  const handleStatusChange = async (newStatus: FindingStatus) => {
    setIsUpdating(true);
    try {
      await onUpdateStatus(finding.id, newStatus);
      onClose();
    } finally {
      setIsUpdating(false);
    }
  };

  const getSeverityBadge = () => {
    switch (finding.severity) {
      case "critical":
        return "bg-rose-950/80 text-rose-400 border-rose-800/60";
      case "high":
        return "bg-orange-950/80 text-orange-400 border-orange-800/60";
      case "medium":
        return "bg-amber-950/80 text-amber-400 border-amber-800/60";
      case "low":
        return "bg-emerald-950/80 text-emerald-400 border-emerald-800/60";
      default:
        return "bg-zinc-900 text-zinc-400 border-zinc-800";
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 animate-in fade-in duration-150">
      <div className="relative w-full max-w-2xl bg-[#111111] border border-[#262626] rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        <div className="p-6 border-b border-[#262626] flex items-start justify-between gap-4">
          <div className="space-y-2">
            <div className="flex items-center gap-2 flex-wrap">
              <span
                className={`px-2.5 py-0.5 rounded-md text-[11px] font-bold uppercase tracking-wider border ${getSeverityBadge()}`}
              >
                {finding.severity}
              </span>
              <span className={AppTheme.controls.badgeMono}>
                {finding.category.toUpperCase()}
              </span>
              <span className="text-xs text-zinc-500 font-mono">
                ID: {finding.fingerprint.slice(0, 8)}
              </span>
            </div>
            <h3 className="text-lg font-bold text-zinc-100">{finding.title}</h3>
          </div>
          <button onClick={onClose} className={AppTheme.controls.iconButton}>
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 space-y-5 overflow-y-auto">
          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="p-3 rounded-lg bg-[#161616] border border-[#262626] flex items-center gap-2.5">
              <Server className="w-4 h-4 text-emerald-400 shrink-0" />
              <div>
                <p className="text-zinc-500 text-[10px] uppercase font-medium">Target Server</p>
                <p className="text-zinc-200 font-mono">{finding.server_name || "All Servers"}</p>
              </div>
            </div>
            <div className="p-3 rounded-lg bg-[#161616] border border-[#262626] flex items-center gap-2.5">
              <Layers className="w-4 h-4 text-cyan-400 shrink-0" />
              <div>
                <p className="text-zinc-500 text-[10px] uppercase font-medium">Remediation Status</p>
                <p className="text-zinc-200 capitalize">{finding.status.replace("_", " ")}</p>
              </div>
            </div>
          </div>

          <div className="space-y-1.5">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-400 flex items-center gap-1.5">
              <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
              Vulnerability Description
            </h4>
            <p className="text-sm text-zinc-300 leading-relaxed bg-[#161616] p-3.5 rounded-lg border border-[#262626]">
              {finding.description}
            </p>
          </div>

          {finding.remediation_command && (
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-400 flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-emerald-400" />
                  Remediation Command (1-Click Remediation)
                </h4>
                <button
                  onClick={handleCopyCommand}
                  className={AppTheme.controls.buttonGhost}
                >
                  {copied ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      <span className="text-emerald-400 text-xs">Copied!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span className="text-xs">Copy Command</span>
                    </>
                  )}
                </button>
              </div>
              <div className={AppTheme.controls.codeBox}>
                <code>{finding.remediation_command}</code>
              </div>
            </div>
          )}

          {finding.evidence && Object.keys(finding.evidence).length > 0 && (
            <div className="space-y-1.5">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-400 flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5 text-cyan-400" />
                Evidence Logs
              </h4>
              <pre className="p-3 rounded-lg bg-[#0d0d0d] border border-[#222222] text-xs font-mono text-zinc-400 overflow-x-auto">
                {JSON.stringify(finding.evidence, null, 2)}
              </pre>
            </div>
          )}
        </div>

        <div className="p-4 border-t border-[#262626] bg-[#0d0d0d] flex items-center justify-between gap-3">
          <div className="flex items-center gap-2 flex-wrap">
            {onRemediate && finding.status !== "resolved" && (
              <button
                disabled={isUpdating || isRemediating}
                onClick={handleRemediate}
                className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold bg-emerald-500 hover:bg-emerald-400 text-slate-950 transition-colors disabled:opacity-50 shadow-sm"
              >
                {isRemediating ? (
                  <>
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    <span>Memperbaiki...</span>
                  </>
                ) : remediationSuccess ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-slate-950" />
                    <span>Telah Diperbaiki</span>
                  </>
                ) : (
                  <>
                    <Wrench className="w-3.5 h-3.5 text-slate-950" />
                    <span>Perbaiki Otomatis (1-Click Auto-Remediate)</span>
                  </>
                )}
              </button>
            )}
            {finding.status !== "resolved" && (
              <button
                disabled={isUpdating || isRemediating}
                onClick={() => handleStatusChange("resolved")}
                className={AppTheme.controls.buttonPrimary}
              >
                <CheckCircle2 className="w-4 h-4" />
                Mark as Resolved
              </button>
            )}
            {finding.status === "open" && (
              <button
                disabled={isUpdating || isRemediating}
                onClick={() => handleStatusChange("acknowledged")}
                className={AppTheme.controls.buttonSecondary}
              >
                Acknowledge Finding
              </button>
            )}
            {finding.status !== "false_positive" && (
              <button
                disabled={isUpdating || isRemediating}
                onClick={() => handleStatusChange("false_positive")}
                className={AppTheme.controls.buttonGhost}
              >
                False Positive
              </button>
            )}
            {finding.status === "resolved" && onReverify && (
              <button
                disabled={isUpdating || isRemediating || isReverifying}
                onClick={handleReverify}
                className={AppTheme.controls.buttonPrimary}
              >
                <RotateCw className={`w-3.5 h-3.5 ${isReverifying ? "animate-spin" : ""}`} />
                <span>{isReverifying ? "Memverifikasi..." : "Verifikasi Ulang"}</span>
              </button>
            )}
            {finding.status === "resolved" && onReopen && (
              <button
                disabled={isUpdating || isRemediating || isReverifying}
                onClick={handleReopen}
                className={AppTheme.controls.buttonSecondary}
              >
                Buka Kembali
              </button>
            )}
          </div>
          <button onClick={onClose} className={AppTheme.controls.buttonSecondary}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
