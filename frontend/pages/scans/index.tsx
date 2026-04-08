import { useState, useEffect } from "react";
import Link from "next/link";
import Layout from "../../components/Layout";
import {
  SectionHeader, StatusBadge, Table, Td, Spinner, EmptyState,
} from "../../components/ui";
import { apiClient, Scan } from "../../lib/api";
import { formatDistanceToNow } from "date-fns";

export default function ScansPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [domain, setDomain] = useState("");
  const [launching, setLaunching] = useState(false);
  const [error, setError] = useState("");

  const load = () => {
    apiClient.getScans({ limit: 50 }).then(setScans).finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
    const id = setInterval(load, 10000);
    return () => clearInterval(id);
  }, []);

  const launchScan = async () => {
    if (!domain.trim()) return;
    setLaunching(true);
    setError("");
    try {
      await apiClient.createScan(domain.trim(), {
        run_ffuf: false,
        run_gowitness: true,
        nuclei_severity: "medium,high,critical",
      });
      setDomain("");
      load();
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Failed to start scan");
    } finally {
      setLaunching(false);
    }
  };

  return (
    <Layout>
      <SectionHeader title="Scans" subtitle="Manage and monitor all reconnaissance scans" />

      {/* New Scan Form */}
      <div className="bg-bg-secondary border border-border rounded-lg p-5 mb-6">
        <h2 className="text-sm font-semibold text-text-secondary uppercase tracking-wider mb-3">
          Start New Scan
        </h2>
        <div className="flex gap-3">
          <input
            className="flex-1 bg-bg-tertiary border border-border rounded-md px-4 py-2 text-sm
                       text-text-primary placeholder-text-muted focus:outline-none focus:border-accent"
            placeholder="example.com"
            value={domain}
            onChange={e => setDomain(e.target.value)}
            onKeyDown={e => e.key === "Enter" && launchScan()}
          />
          <button
            onClick={launchScan}
            disabled={launching || !domain.trim()}
            className="px-5 py-2 bg-accent text-bg-primary text-sm font-semibold rounded-md
                       hover:bg-accent-hover disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {launching ? "Starting..." : "Launch Scan"}
          </button>
        </div>
        {error && <p className="text-red-400 text-xs mt-2">{error}</p>}
      </div>

      {/* Scans Table */}
      {loading ? (
        <div className="flex justify-center pt-10"><Spinner /></div>
      ) : scans.length === 0 ? (
        <EmptyState message="No scans yet. Start your first scan above." />
      ) : (
        <Table headers={["Scan ID", "Status", "Assets", "Findings", "Step", "Started", ""]}>
          {scans.map(scan => (
            <tr key={scan.id} className="hover:bg-bg-tertiary transition-colors">
              <Td mono>{scan.id.slice(0, 8)}...</Td>
              <Td><StatusBadge status={scan.status} /></Td>
              <Td>{scan.assets_found}</Td>
              <Td>{scan.findings_count}</Td>
              <Td mono>{scan.current_step || "—"}</Td>
              <Td>
                {formatDistanceToNow(new Date(scan.created_at), { addSuffix: true })}
              </Td>
              <Td>
                <Link
                  href={`/scans/${scan.id}`}
                  className="text-accent hover:underline text-xs"
                >
                  Details →
                </Link>
              </Td>
            </tr>
          ))}
        </Table>
      )}
    </Layout>
  );
}
