import { useState, useEffect } from "react";
import Layout from "../components/Layout";
import { SectionHeader, SeverityBadge, Table, Td, Spinner, EmptyState, CodeBlock } from "../components/ui";
import { apiClient, Finding, Severity, FindingCategory } from "../lib/api";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const CATEGORIES: FindingCategory[] = [
  "xss", "sqli", "lfi", "ssrf", "rce", "idor",
  "misconfiguration", "sensitive_data", "open_redirect", "other",
];

export default function FindingsPage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [validation, setValidation] = useState<any>(null);

  // Filters
  const [severityFilter, setSeverityFilter] = useState<Severity[]>([]);
  const [categoryFilter, setCategoryFilter] = useState<string>("");
  const [showFP, setShowFP] = useState(false);

  useEffect(() => {
    setLoading(true);
    const params: any = { limit: 300 };
    if (severityFilter.length > 0) params.severity = severityFilter;
    if (!showFP) params.false_positive = false;

    apiClient.getFindings(params)
      .then(data => {
        let d = data;
        if (categoryFilter) d = d.filter(f => f.category === categoryFilter);
        setFindings(d);
      })
      .finally(() => setLoading(false));
  }, [severityFilter, categoryFilter, showFP]);

  const selectFinding = async (f: Finding) => {
    setSelected(f);
    setValidation(null);
    const v = await apiClient.getValidationCommands(f.id);
    setValidation(v);
  };

  const toggleSeverity = (s: Severity) => {
    setSeverityFilter(prev =>
      prev.includes(s) ? prev.filter(x => x !== s) : [...prev, s]
    );
  };

  return (
    <Layout>
      <SectionHeader title="Findings" subtitle="All vulnerability findings across scans" />

      {/* Filters */}
      <div className="bg-bg-secondary border border-border rounded-lg p-4 mb-6 flex flex-wrap gap-4 items-center">
        <div>
          <p className="text-xs text-text-muted mb-2 uppercase tracking-wider">Severity</p>
          <div className="flex gap-1">
            {SEVERITIES.map(s => (
              <button
                key={s}
                onClick={() => toggleSeverity(s)}
                className={`px-2 py-1 rounded text-xs font-bold uppercase transition-opacity ${
                  severityFilter.length === 0 || severityFilter.includes(s)
                    ? "opacity-100" : "opacity-30"
                }`}
              >
                <SeverityBadge severity={s} />
              </button>
            ))}
          </div>
        </div>
        <div>
          <p className="text-xs text-text-muted mb-2 uppercase tracking-wider">Category</p>
          <select
            className="bg-bg-tertiary border border-border text-text-primary text-xs rounded-md px-3 py-1.5 focus:outline-none focus:border-accent"
            value={categoryFilter}
            onChange={e => setCategoryFilter(e.target.value)}
          >
            <option value="">All categories</option>
            {CATEGORIES.map(c => <option key={c} value={c}>{c.toUpperCase()}</option>)}
          </select>
        </div>
        <div className="flex items-center gap-2 self-end pb-0.5">
          <input
            type="checkbox"
            id="show-fp"
            checked={showFP}
            onChange={e => setShowFP(e.target.checked)}
            className="accent-accent"
          />
          <label htmlFor="show-fp" className="text-xs text-text-secondary cursor-pointer">
            Show false positives
          </label>
        </div>
        <div className="self-end pb-0.5 ml-auto">
          <span className="text-xs text-text-muted">{findings.length} results</span>
        </div>
      </div>

      <div className="grid grid-cols-5 gap-4">
        {/* Table */}
        <div className="col-span-3">
          {loading ? (
            <div className="flex justify-center pt-10"><Spinner /></div>
          ) : findings.length === 0 ? (
            <EmptyState message="No findings match current filters." />
          ) : (
            <div className="overflow-auto max-h-[70vh]">
              <Table headers={["Severity", "Category", "Title", "URL"]}>
                {findings.map(f => (
                  <tr
                    key={f.id}
                    onClick={() => selectFinding(f)}
                    className={`cursor-pointer transition-colors ${
                      selected?.id === f.id
                        ? "bg-bg-tertiary"
                        : "hover:bg-bg-tertiary/50"
                    } ${f.false_positive ? "opacity-40" : ""}`}
                  >
                    <Td><SeverityBadge severity={f.severity} /></Td>
                    <Td mono>{f.category}</Td>
                    <Td>
                      <span className="text-xs">{f.title}</span>
                      {f.is_validated && <span className="ml-2 text-green-400 text-xs">✓</span>}
                    </Td>
                    <Td mono>{f.url ? f.url.slice(0, 40) + (f.url.length > 40 ? "…" : "") : "—"}</Td>
                  </tr>
                ))}
              </Table>
            </div>
          )}
        </div>

        {/* Side panel */}
        <div className="col-span-2">
          {!selected ? (
            <div className="flex items-center justify-center h-40 bg-bg-secondary border border-border rounded-lg text-text-muted text-sm">
              Click a finding to view details
            </div>
          ) : (
            <div className="bg-bg-secondary border border-border rounded-lg p-5 space-y-4 sticky top-4">
              <div className="flex items-start gap-3 justify-between">
                <h3 className="text-sm font-semibold text-text-primary">{selected.title}</h3>
                <SeverityBadge severity={selected.severity} />
              </div>
              {selected.url && (
                <a
                  href={selected.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs font-mono text-accent hover:underline break-all block"
                >
                  {selected.url}
                </a>
              )}
              {selected.parameter && (
                <p className="text-xs text-text-secondary">
                  Parameter: <span className="font-mono text-accent">{selected.parameter}</span>
                </p>
              )}
              {selected.template_id && (
                <p className="text-xs text-text-muted font-mono">
                  Template: {selected.template_id}
                </p>
              )}
              {selected.description && (
                <p className="text-xs text-text-secondary">{selected.description}</p>
              )}
              {validation ? (
                <div>
                  <p className="text-xs text-text-muted uppercase tracking-wider mb-2">Validation</p>
                  {validation.risk_note && (
                    <p className="text-xs text-yellow-400 mb-2">{validation.risk_note}</p>
                  )}
                  <CodeBlock code={validation.commands.join("\n")} />
                </div>
              ) : (
                <div className="flex items-center gap-2 text-text-muted text-xs">
                  <Spinner size={3} /> Loading validation commands...
                </div>
              )}
              {selected.analyst_notes && (
                <div className="bg-bg-tertiary rounded-md p-3">
                  <p className="text-xs text-text-muted uppercase tracking-wider mb-1">Analyst Notes</p>
                  <p className="text-xs text-text-secondary">{selected.analyst_notes}</p>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </Layout>
  );
}
