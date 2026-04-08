import { clsx } from "clsx";
import type { Severity, ScanStatus } from "../lib/api";

// ─── Severity Badge ───────────────────────────────────────────────────────────

const SEV_STYLES: Record<Severity, string> = {
  critical: "bg-red-600 text-white",
  high:     "bg-orange-500 text-black",
  medium:   "bg-yellow-400 text-black",
  low:      "bg-green-600 text-white",
  info:     "bg-gray-600 text-white",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={clsx(
      "inline-flex items-center px-2 py-0.5 rounded text-xs font-bold uppercase tracking-wide",
      SEV_STYLES[severity]
    )}>
      {severity}
    </span>
  );
}

// ─── Status Badge ─────────────────────────────────────────────────────────────

const STATUS_STYLES: Record<ScanStatus, string> = {
  pending:   "bg-gray-700 text-gray-300",
  running:   "bg-blue-700 text-blue-200",
  completed: "bg-green-800 text-green-300",
  failed:    "bg-red-800 text-red-300",
  cancelled: "bg-gray-800 text-gray-500",
};

const STATUS_EMOJI: Record<ScanStatus, string> = {
  pending: "⏳", running: "🔄", completed: "✅", failed: "❌", cancelled: "🚫",
};

export function StatusBadge({ status }: { status: ScanStatus }) {
  return (
    <span className={clsx(
      "inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium",
      STATUS_STYLES[status]
    )}>
      {STATUS_EMOJI[status]} {status}
    </span>
  );
}

// ─── Stat Card ────────────────────────────────────────────────────────────────

export function StatCard({
  label,
  value,
  accent,
}: {
  label: string;
  value: number | string;
  accent?: string;
}) {
  return (
    <div className="bg-bg-secondary border border-border rounded-lg p-5 flex flex-col gap-1">
      <span className={clsx("text-3xl font-bold font-mono", accent || "text-accent")}>
        {value}
      </span>
      <span className="text-xs text-text-secondary uppercase tracking-widest">{label}</span>
    </div>
  );
}

// ─── Table ────────────────────────────────────────────────────────────────────

export function Table({
  headers,
  children,
}: {
  headers: string[];
  children: React.ReactNode;
}) {
  return (
    <div className="overflow-x-auto rounded-lg border border-border">
      <table className="w-full text-sm text-text-primary">
        <thead className="bg-bg-tertiary text-text-secondary text-xs uppercase tracking-wider">
          <tr>
            {headers.map(h => (
              <th key={h} className="px-4 py-3 text-left font-medium">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-border">{children}</tbody>
      </table>
    </div>
  );
}

export function Td({ children, mono }: { children: React.ReactNode; mono?: boolean }) {
  return (
    <td className={clsx("px-4 py-3 text-text-primary", mono && "font-mono text-xs")}>
      {children}
    </td>
  );
}

// ─── Loading Spinner ─────────────────────────────────────────────────────────

export function Spinner({ size = 6 }: { size?: number }) {
  return (
    <div
      className={clsx(
        `w-${size} h-${size} border-2 border-accent border-t-transparent rounded-full animate-spin`
      )}
    />
  );
}

// ─── Empty State ─────────────────────────────────────────────────────────────

export function EmptyState({ message }: { message: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-20 text-text-secondary gap-3">
      <span className="text-5xl">🔍</span>
      <p className="text-sm">{message}</p>
    </div>
  );
}

// ─── Progress Bar ────────────────────────────────────────────────────────────

export function ProgressBar({
  completed,
  total,
  label,
}: {
  completed: number;
  total: number;
  label?: string;
}) {
  const pct = total > 0 ? Math.min(100, Math.round((completed / total) * 100)) : 0;
  return (
    <div className="w-full">
      {label && (
        <div className="flex justify-between text-xs text-text-secondary mb-1">
          <span>{label}</span>
          <span>{pct}%</span>
        </div>
      )}
      <div className="w-full bg-bg-tertiary rounded-full h-2">
        <div
          className="bg-accent rounded-full h-2 transition-all duration-500"
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}

// ─── Code Block ──────────────────────────────────────────────────────────────

export function CodeBlock({ code }: { code: string }) {
  return (
    <pre className="bg-bg-primary border border-border rounded-lg p-4 overflow-x-auto text-xs font-mono text-green-400 whitespace-pre-wrap">
      {code}
    </pre>
  );
}

// ─── Section Header ──────────────────────────────────────────────────────────

export function SectionHeader({ title, subtitle }: { title: string; subtitle?: string }) {
  return (
    <div className="mb-6">
      <h1 className="text-2xl font-bold text-text-primary">{title}</h1>
      {subtitle && <p className="text-sm text-text-secondary mt-1">{subtitle}</p>}
    </div>
  );
}
