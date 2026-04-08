import { useEffect, useState } from "react";
import { useRouter } from "next/router";
import Link from "next/link";
import Layout from "../../components/Layout";
import {
  SectionHeader, StatusBadge, SeverityBadge, ProgressBar,
  Table, Td, Spinner, EmptyState, CodeBlock,
} from "../../components/ui";
import { apiClient, Scan, Finding, AttackPath } from "../../lib/api";
import { formatDistanceToNow } from "date-fns";

type Tab = "overview" | "findings" | "paths" | "logs";

export default function ScanDetail() {
  const router = useRouter();
  const { id } = router.query as { id: string };
  const [tab, setTab] = useState<Tab>("overview");
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [paths, setPaths] = useState<AttackPath[]>([]);
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!id) return;
    const load = async () => {
      try {
        const [s, f, p, l] = await Promise.all([
          apiClient.getScan(id),
          apiClient.getFindings({ scan_id: id, limit: 200 }),
          apiClient.getPaths({ scan_id: id }),
          apiClient.getScanLogs(id),
        ]);
        setScan(s); setFindings(f); setPaths(p); setLogs(l);
      } finally {
        setLoading(false);
      }
    };
    load();
    // Poll while running
    const interval = setInterval(() => {
      if (scan?.status === "running" || scan?.status === "pending") load();
    }, 5000);
    return () => clearInterval(interval);
  }, [id, scan?.status]);

  const TABS: Tab[] = ["overview", "findings", "paths", "logs"];

  if (loading) return <Layout><div className="flex justify-center pt-20"><Spinner size={8} /></div></Layout>;
  if (!scan)   return <Layout><p className="text-red-400">Scan not found</p></Layout>;

  return (
    <Layout>
      <div className="mb-6 flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <h1 className="text-xl font-bold font-mono text-text-primary">{scan.id.slice(0, 16)}...</h1>
            <StatusBadge status={scan.status} />
          </div>
          <p className="text-sm text-text-secondary">
            Started {formatDistanceToNow(new Date(scan.created_at), { addSuffix: true })}
            {scan.completed_at && ` · Completed ${formatDistanceToNow(new Date(scan.completed_at), { addSuffix: true })}`}
          </p>
        </div>
        <div className="flex gap-2">
          <Link
            href={`${process.env.NEXT_PUBLIC_API_URL}/api/v1/reports/${id}?fmt=html`}
            target="_blank"
            className="px-4 py-2 text-xs font-medium border border-border rounded-md text-text-secondary hover:text-text-primary hover:border-accent transition-colors"
          >
            HTML Report ↗
          </Link>
          <Link
            href={`${process.env.NEXT_PUBLIC_API_URL}/api/v1/reports/${id}?fmt=json`}
            target="_blank"
            className="px-4 py-2 text-xs font-medium border border-border rounded-md text-text-secondary hover:text-text-primary hover:border-accent transition-colors"
          >
            JSON Report ↗
          </Link>
        </div>
      </div>

      {/* Progress (if running) */}
      {(scan.status === "running" || scan.status === "pending") && (
        <div className="mb-6 bg-bg-secondary border border-border rounded-lg p-4">
          <ProgressBar
            completed={scan.steps_completed}
            total={scan.steps_total || 8}
            label={scan.current_step ? `Running: ${scan.current_step}` : "Starting..."}
          />
        </div>
      )}

      {/* Error */}
      {scan.status === "failed" && scan.error_message && (
        <div className="mb-6 bg-red-900/20 border border-red-700 rounded-lg p-4">
          <p className="text-red-400 text-sm">❌ {scan.error_message}</p>
        </div>
      )}

      {/* Quick stats */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: "Assets", value: scan.assets_found },
          { label: "Findings", value: scan.findings_count },
          { label: "Attack Paths", value: paths.length },
          { label: "Logs", value: logs.length },
        ].map(s => (
          <div key={s.label} className="bg-bg-secondary border border-border rounded-lg p-4 text-center">
            <div className="text-2xl font-bold font-mono text-accent">{s.value}</div>
            <div className="text-xs text-text-secondary uppercase tracking-wider mt-1">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-border mb-6">
        {TABS.map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm capitalize transition-colors border-b-2 -mb-px ${
              tab === t
                ? "border-accent text-accent"
                : "border-transparent text-text-secondary hover:text-text-primary"
            }`}
          >
            {t}
            {t === "findings" && findings.length > 0 && (
              <span className="ml-2 bg-bg-tertiary px-1.5 py-0.5 rounded text-xs">{findings.length}</span>
            )}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === "overview" && <OverviewTab scan={scan} findings={findings} paths={paths} />}
      {tab === "findings" && <FindingsTab findings={findings} scanId={id} />}
      {tab === "paths"    && <PathsTab paths={paths} />}
      {tab === "logs"     && <LogsTab logs={logs} />}
    </Layout>
  );
}

function OverviewTab({ scan, findings, paths }: { scan: Scan; findings: Finding[]; paths: AttackPath[] }) {
  const sevCounts = findings.reduce((acc, f) => {
    if (!f.false_positive) acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  return (
    <div className="grid grid-cols-2 gap-6">
      <div className="bg-bg-secondary border border-border rounded-lg p-5">
        <h3 className="text-xs font-semibold text-text-secondary uppercase tracking-wider mb-4">Severity Breakdown</h3>
        {Object.entries(sevCounts).length === 0 ? (
          <p className="text-text-muted text-sm">No findings recorded.</p>
        ) : (
          Object.entries(sevCounts).map(([sev, count]) => (
            <div key={sev} className="flex justify-between items-center py-2 border-b border-border last:border-0">
              <SeverityBadge severity={sev as any} />
              <span className="font-mono text-sm text-text-primary">{count}</span>
            </div>
          ))
        )}
      </div>
      <div className="bg-bg-secondary border border-border rounded-lg p-5">
        <h3 className="text-xs font-semibold text-text-secondary uppercase tracking-wider mb-4">Attack Paths</h3>
        {paths.length === 0 ? (
          <p className="text-text-muted text-sm">No attack paths identified.</p>
        ) : (
          paths.map(p => (
            <div key={p.id} className="py-2 border-b border-border last:border-0">
              <p className="text-sm text-text-primary">{p.title}</p>
              <p className="text-xs text-text-secondary mt-0.5">
                Confidence: {Math.round(p.confidence * 100)}% · {p.impact}
              </p>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function FindingsTab({ findings, scanId }: { findings: Finding[]; scanId: string }) {
  const [selected, setSelected] = useState<Finding | null>(null);
  const [validation, setValidation] = useState<any>(null);
  const [notes, setNotes] = useState("");
  const [saving, setSaving] = useState(false);

  const loadValidation = async (f: Finding) => {
    setSelected(f);
    setNotes(f.analyst_notes || "");
    setValidation(null);
    const v = await apiClient.getValidationCommands(f.id);
    setValidation(v);
  };

  const saveNotes = async () => {
    if (!selected) return;
    setSaving(true);
    await apiClient.updateFinding(selected.id, { analyst_notes: notes, is_validated: true });
    setSaving(false);
  };

  if (findings.length === 0) return <EmptyState message="No findings for this scan." />;

  return (
    <div className="grid grid-cols-5 gap-4">
      {/* List */}
      <div className="col-span-2 flex flex-col gap-2 max-h-[70vh] overflow-y-auto pr-1">
        {findings.map(f => (
          <button
            key={f.id}
            onClick={() => loadValidation(f)}
            className={`w-full text-left p-3 rounded-lg border transition-colors ${
              selected?.id === f.id
                ? "border-accent bg-bg-tertiary"
                : "border-border bg-bg-secondary hover:border-accent/50"
            }`}
          >
            <div className="flex items-center gap-2 mb-1">
              <SeverityBadge severity={f.severity} />
              {f.is_validated && <span className="text-green-400 text-xs">✓ validated</span>}
              {f.false_positive && <span className="text-gray-500 text-xs line-through">FP</span>}
            </div>
            <p className="text-xs text-text-primary truncate">{f.title}</p>
            <p className="text-xs text-text-muted font-mono truncate mt-0.5">{f.url}</p>
          </button>
        ))}
      </div>

      {/* Detail */}
      <div className="col-span-3">
        {!selected ? (
          <div className="flex items-center justify-center h-40 text-text-muted text-sm">
            Select a finding to view details
          </div>
        ) : (
          <div className="bg-bg-secondary border border-border rounded-lg p-5 space-y-4">
            <div className="flex items-start justify-between gap-3">
              <h3 className="text-sm font-semibold text-text-primary">{selected.title}</h3>
              <SeverityBadge severity={selected.severity} />
            </div>
            {selected.url && (
              <div>
                <p className="text-xs text-text-muted uppercase tracking-wider mb-1">URL</p>
                <p className="text-xs font-mono text-accent break-all">{selected.url}</p>
              </div>
            )}
            {selected.description && (
              <div>
                <p className="text-xs text-text-muted uppercase tracking-wider mb-1">Description</p>
                <p className="text-xs text-text-secondary">{selected.description}</p>
              </div>
            )}
            {validation && (
              <div>
                <p className="text-xs text-text-muted uppercase tracking-wider mb-2">Suggested Validation</p>
                {validation.risk_note && (
                  <p className="text-xs text-yellow-400 mb-2">{validation.risk_note}</p>
                )}
                <CodeBlock code={validation.commands.join("\n")} />
                <p className="text-xs text-text-muted mt-2 italic">{validation.notes}</p>
              </div>
            )}
            {/* Analyst notes */}
            <div>
              <p className="text-xs text-text-muted uppercase tracking-wider mb-1">Analyst Notes</p>
              <textarea
                className="w-full bg-bg-tertiary border border-border rounded-md p-3 text-xs text-text-primary
                           placeholder-text-muted focus:outline-none focus:border-accent resize-none"
                rows={3}
                placeholder="Record validation results, false positive rationale, etc."
                value={notes}
                onChange={e => setNotes(e.target.value)}
              />
              <div className="flex gap-2 mt-2">
                <button
                  onClick={saveNotes}
                  disabled={saving}
                  className="px-3 py-1.5 bg-accent text-bg-primary text-xs font-medium rounded-md hover:bg-accent-hover disabled:opacity-50"
                >
                  {saving ? "Saving..." : "Mark Validated"}
                </button>
                <button
                  onClick={() => apiClient.updateFinding(selected.id, { false_positive: true })}
                  className="px-3 py-1.5 border border-border text-xs font-medium rounded-md text-text-secondary hover:text-text-primary"
                >
                  Mark False Positive
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function PathsTab({ paths }: { paths: AttackPath[] }) {
  if (paths.length === 0) return <EmptyState message="No attack paths identified for this scan." />;

  return (
    <div className="flex flex-col gap-4">
      {paths.map(p => (
        <div key={p.id} className="bg-bg-secondary border border-border rounded-lg p-5">
          <div className="flex items-start justify-between mb-3">
            <h3 className="text-sm font-semibold text-text-primary">{p.title}</h3>
            <span className="text-xs text-text-secondary bg-bg-tertiary px-2 py-1 rounded">
              {Math.round(p.confidence * 100)}% confidence
            </span>
          </div>
          {p.impact && <p className="text-xs text-orange-400 mb-2">Impact: {p.impact}</p>}
          <p className="text-xs text-text-secondary mb-4">{p.description}</p>
          <div>
            <p className="text-xs text-text-muted uppercase tracking-wider mb-2">Steps for analyst review:</p>
            <ol className="space-y-2">
              {p.steps.map((step, i) => (
                <li key={i} className="flex gap-2 text-xs text-text-primary">
                  <span className="text-accent font-mono">{String(i + 1).padStart(2, "0")}.</span>
                  <span>{step}</span>
                </li>
              ))}
            </ol>
          </div>
          {p.nodes.length > 0 && (
            <div className="mt-4">
              <p className="text-xs text-text-muted uppercase tracking-wider mb-2">Validation Commands</p>
              {p.nodes.filter(n => n.validation_command).map(n => (
                <div key={n.id} className="mb-3">
                  <p className="text-xs text-text-secondary mb-1">Step: {n.label}</p>
                  <CodeBlock code={n.validation_command!} />
                </div>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function LogsTab({ logs }: { logs: any[] }) {
  const LEVEL_COLORS: Record<string, string> = {
    info: "text-blue-400", warning: "text-yellow-400",
    error: "text-red-400", debug: "text-text-muted",
  };

  if (logs.length === 0) return <EmptyState message="No logs recorded." />;

  return (
    <div className="bg-bg-primary border border-border rounded-lg p-4 font-mono text-xs space-y-1 max-h-[60vh] overflow-y-auto">
      {logs.map(log => (
        <div key={log.id} className="flex gap-3">
          <span className="text-text-muted shrink-0">
            {new Date(log.created_at).toISOString().slice(11, 19)}
          </span>
          <span className={`uppercase shrink-0 w-14 ${LEVEL_COLORS[log.level] || "text-text-primary"}`}>
            {log.level}
          </span>
          {log.step && <span className="text-text-muted shrink-0">[{log.step}]</span>}
          <span className="text-text-primary">{log.message}</span>
        </div>
      ))}
    </div>
  );
}
