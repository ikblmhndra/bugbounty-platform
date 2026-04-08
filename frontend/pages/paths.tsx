import { useState, useEffect } from "react";
import Layout from "../components/Layout";
import { SectionHeader, Spinner, EmptyState, CodeBlock } from "../components/ui";
import { apiClient, AttackPath } from "../lib/api";

function ConfidenceMeter({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const color = pct >= 70 ? "bg-red-500" : pct >= 40 ? "bg-yellow-400" : "bg-green-500";
  return (
    <div className="flex items-center gap-2">
      <div className="w-24 bg-bg-tertiary rounded-full h-1.5">
        <div className={`${color} h-1.5 rounded-full`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-text-secondary font-mono">{pct}%</span>
    </div>
  );
}

export default function PathsPage() {
  const [paths, setPaths] = useState<AttackPath[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<AttackPath | null>(null);
  const [minConf, setMinConf] = useState(0);

  useEffect(() => {
    apiClient.getPaths({ min_confidence: minConf })
      .then(setPaths)
      .finally(() => setLoading(false));
  }, [minConf]);

  return (
    <Layout>
      <SectionHeader
        title="Attack Paths"
        subtitle="Correlated finding chains for analyst review. No automatic exploitation."
      />

      {/* Filter */}
      <div className="bg-bg-secondary border border-border rounded-lg p-4 mb-6 flex items-center gap-6">
        <div>
          <p className="text-xs text-text-muted uppercase tracking-wider mb-1">Min Confidence</p>
          <div className="flex items-center gap-3">
            <input
              type="range" min={0} max={1} step={0.1}
              value={minConf}
              onChange={e => setMinConf(parseFloat(e.target.value))}
              className="w-32 accent-accent"
            />
            <span className="text-xs font-mono text-accent">{Math.round(minConf * 100)}%</span>
          </div>
        </div>
        <span className="text-xs text-text-muted ml-auto">{paths.length} paths</span>
      </div>

      {loading ? (
        <div className="flex justify-center pt-10"><Spinner /></div>
      ) : paths.length === 0 ? (
        <EmptyState message="No attack paths identified. Run a scan first." />
      ) : (
        <div className="grid grid-cols-5 gap-4">
          {/* List */}
          <div className="col-span-2 flex flex-col gap-2 max-h-[70vh] overflow-y-auto pr-1">
            {paths.map(p => (
              <button
                key={p.id}
                onClick={() => setSelected(p)}
                className={`w-full text-left p-4 rounded-lg border transition-colors ${
                  selected?.id === p.id
                    ? "border-accent bg-bg-tertiary"
                    : "border-border bg-bg-secondary hover:border-accent/40"
                }`}
              >
                <p className="text-sm font-medium text-text-primary mb-2 leading-snug">{p.title}</p>
                <ConfidenceMeter value={p.confidence} />
                {p.impact && (
                  <p className="text-xs text-orange-400 mt-1.5">{p.impact}</p>
                )}
                <p className="text-xs text-text-muted mt-1">{p.nodes.length} steps</p>
              </button>
            ))}
          </div>

          {/* Detail */}
          <div className="col-span-3">
            {!selected ? (
              <div className="flex items-center justify-center h-40 bg-bg-secondary border border-border rounded-lg text-text-muted text-sm">
                Select a path to view details
              </div>
            ) : (
              <div className="bg-bg-secondary border border-border rounded-lg p-5 space-y-5">
                <div>
                  <h2 className="text-base font-bold text-text-primary mb-1">{selected.title}</h2>
                  <div className="flex items-center gap-4">
                    <ConfidenceMeter value={selected.confidence} />
                    {selected.impact && (
                      <span className="text-xs text-orange-400">Impact: {selected.impact}</span>
                    )}
                  </div>
                </div>

                <div className="bg-bg-tertiary rounded-md p-4">
                  <p className="text-xs text-text-secondary leading-relaxed">{selected.description}</p>
                </div>

                <div>
                  <p className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-3">
                    Analysis Steps
                  </p>
                  <div className="space-y-2">
                    {selected.steps.map((step, i) => (
                      <div key={i} className="flex gap-3 items-start">
                        <span className="text-accent font-mono text-xs shrink-0 mt-0.5">
                          {String(i + 1).padStart(2, "0")}
                        </span>
                        <p className="text-xs text-text-primary">{step}</p>
                      </div>
                    ))}
                  </div>
                </div>

                {selected.nodes.filter(n => n.validation_command).length > 0 && (
                  <div>
                    <p className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-3">
                      Suggested Validation Commands
                    </p>
                    <div className="space-y-4">
                      {selected.nodes.filter(n => n.validation_command).map(node => (
                        <div key={node.id}>
                          <p className="text-xs text-text-secondary mb-1.5">
                            <span className="font-mono text-accent">[{node.order + 1}]</span> {node.label}
                          </p>
                          {node.description && (
                            <p className="text-xs text-text-muted mb-1.5 italic">{node.description}</p>
                          )}
                          <CodeBlock code={node.validation_command!} />
                        </div>
                      ))}
                    </div>
                    <div className="mt-3 p-3 bg-yellow-900/20 border border-yellow-700/40 rounded-md">
                      <p className="text-xs text-yellow-400">
                        ⚠️ These commands are for manual analyst use only in authorized environments.
                        Do not automate without explicit authorization.
                      </p>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </Layout>
  );
}
