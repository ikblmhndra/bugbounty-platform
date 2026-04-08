import { useState, useEffect } from "react";
import Layout from "../components/Layout";
import { SectionHeader, Table, Td, Spinner, EmptyState } from "../components/ui";
import { apiClient, Target } from "../lib/api";
import { formatDistanceToNow } from "date-fns";
import Link from "next/link";

export default function TargetsPage() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [loading, setLoading] = useState(true);
  const [domain, setDomain] = useState("");
  const [description, setDescription] = useState("");
  const [adding, setAdding] = useState(false);
  const [error, setError] = useState("");

  const load = () => apiClient.getTargets().then(setTargets).finally(() => setLoading(false));
  useEffect(() => { load(); }, []);

  const addTarget = async () => {
    if (!domain.trim()) return;
    setAdding(true);
    setError("");
    try {
      await apiClient.createTarget(domain.trim(), description.trim() || undefined);
      setDomain(""); setDescription("");
      load();
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Failed to add target");
    } finally {
      setAdding(false);
    }
  };

  return (
    <Layout>
      <SectionHeader title="Targets" subtitle="Manage authorized scan targets" />

      {/* Add form */}
      <div className="bg-bg-secondary border border-border rounded-lg p-5 mb-6">
        <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider mb-3">
          Add Target
        </h2>
        <div className="flex gap-3">
          <input
            className="flex-1 bg-bg-tertiary border border-border rounded-md px-4 py-2 text-sm
                       text-text-primary placeholder-text-muted focus:outline-none focus:border-accent"
            placeholder="example.com"
            value={domain}
            onChange={e => setDomain(e.target.value)}
          />
          <input
            className="flex-1 bg-bg-tertiary border border-border rounded-md px-4 py-2 text-sm
                       text-text-primary placeholder-text-muted focus:outline-none focus:border-accent"
            placeholder="Description (optional)"
            value={description}
            onChange={e => setDescription(e.target.value)}
          />
          <button
            onClick={addTarget}
            disabled={adding || !domain.trim()}
            className="px-5 py-2 bg-accent text-bg-primary text-sm font-semibold rounded-md
                       hover:bg-accent-hover disabled:opacity-50 transition-colors"
          >
            {adding ? "Adding..." : "Add Target"}
          </button>
        </div>
        {error && <p className="text-red-400 text-xs mt-2">{error}</p>}
      </div>

      {loading ? (
        <div className="flex justify-center pt-10"><Spinner /></div>
      ) : targets.length === 0 ? (
        <EmptyState message="No targets added yet." />
      ) : (
        <Table headers={["Domain", "Description", "Status", "Added", "Actions"]}>
          {targets.map(t => (
            <tr key={t.id} className="hover:bg-bg-tertiary transition-colors">
              <Td mono>{t.domain}</Td>
              <Td>{t.description || "—"}</Td>
              <Td>
                <span className={`text-xs px-2 py-0.5 rounded ${t.is_active ? "bg-green-900/40 text-green-400" : "bg-gray-700 text-gray-400"}`}>
                  {t.is_active ? "Active" : "Inactive"}
                </span>
              </Td>
              <Td>{formatDistanceToNow(new Date(t.created_at), { addSuffix: true })}</Td>
              <Td>
                <div className="flex gap-3">
                  <Link
                    href={`/scans?target_id=${t.id}`}
                    className="text-accent text-xs hover:underline"
                  >
                    View Scans
                  </Link>
                  <button
                    onClick={async () => {
                      await apiClient.deleteTarget(t.id);
                      load();
                    }}
                    className="text-red-400 text-xs hover:underline"
                  >
                    Delete
                  </button>
                </div>
              </Td>
            </tr>
          ))}
        </Table>
      )}
    </Layout>
  );
}
