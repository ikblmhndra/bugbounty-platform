import { useEffect, useState } from "react";
import Link from "next/link";
import Layout from "../components/Layout";
import { StatCard, StatusBadge, SectionHeader, Spinner, EmptyState } from "../components/ui";
import { apiClient, DashboardStats } from "../lib/api";
import { formatDistanceToNow } from "date-fns";

export default function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    apiClient.getDashboard()
      .then(setStats)
      .catch(() => setError("Failed to load dashboard"))
      .finally(() => setLoading(false));

    // Auto-refresh every 15s if there are active scans
    const interval = setInterval(() => {
      apiClient.getDashboard().then(setStats).catch(() => {});
    }, 15000);
    return () => clearInterval(interval);
  }, []);

  if (loading) return <Layout><div className="flex justify-center pt-20"><Spinner size={8} /></div></Layout>;
  if (error)   return <Layout><p className="text-red-400 pt-10">{error}</p></Layout>;
  if (!stats)  return <Layout><EmptyState message="No data available." /></Layout>;

  const topCategories = Object.entries(stats.findings_by_category)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  const getScanProgress = (scan: (typeof stats.recent_scans)[number]) => {
    if (!scan.steps_total || scan.steps_total <= 0) return 0;
    return Math.min(100, Math.round((scan.steps_completed / scan.steps_total) * 100));
  };

  const formatStepName = (step?: string) =>
    step ? step.replace(/_/g, " ") : "pending";

  return (
    <Layout>
      <SectionHeader
        title="Dashboard"
        subtitle="Overview of all scan activity and findings"
      />

      {/* Stats grid */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-8">
        <StatCard label="Targets"       value={stats.total_targets}    accent="text-accent" />
        <StatCard label="Total Scans"   value={stats.total_scans}      accent="text-text-secondary" />
        <StatCard label="Active Scans"  value={stats.active_scans}     accent="text-blue-400" />
        <StatCard label="Total Assets"  value={stats.total_assets}      accent="text-cyan-400" />
        <StatCard label="Total Findings" value={stats.total_findings}  accent="text-text-primary" />
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <StatCard label="Critical" value={stats.critical_findings} accent="text-red-500" />
        <StatCard label="High"     value={stats.high_findings}     accent="text-orange-400" />
        <StatCard label="Medium"   value={stats.medium_findings}   accent="text-yellow-400" />
        <StatCard label="Low"      value={stats.low_findings}      accent="text-green-500" />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Recent Scans */}
        <div className="bg-bg-secondary border border-border rounded-lg p-5">
          <h2 className="text-sm font-semibold text-text-secondary uppercase tracking-wider mb-4">
            Recent Scans
          </h2>
          {stats.recent_scans.length === 0 ? (
            <p className="text-text-muted text-sm">No scans yet.</p>
          ) : (
            <div className="flex flex-col gap-3">
              {stats.recent_scans.map(scan => (
                <Link
                  key={scan.id}
                  href={`/scans/${scan.id}`}
                  className="p-3 rounded-md bg-bg-tertiary hover:border-accent border border-transparent transition-colors"
                >
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <p className="font-mono text-xs text-text-primary">{scan.id.slice(0, 12)}...</p>
                      <p className="text-xs text-text-secondary mt-0.5">
                        {formatDistanceToNow(new Date(scan.created_at), { addSuffix: true })}
                      </p>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="text-xs text-text-secondary">{scan.assets_found} assets</span>
                      <span className="text-xs text-text-secondary">{scan.findings_count} findings</span>
                      <StatusBadge status={scan.status} />
                    </div>
                  </div>

                  <div className="mt-3">
                    <div className="flex justify-between text-xs mb-1">
                      <span className="text-text-secondary capitalize">{formatStepName(scan.current_step)}</span>
                      <span className="text-text-secondary">
                        {scan.steps_completed}/{scan.steps_total || 0} ({getScanProgress(scan)}%)
                      </span>
                    </div>
                    <div className="w-full bg-bg-primary rounded-full h-2">
                      <div
                        className="bg-blue-400 h-2 rounded-full transition-all"
                        style={{ width: `${getScanProgress(scan)}%` }}
                      />
                    </div>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </div>

        {/* Top Categories */}
        <div className="bg-bg-secondary border border-border rounded-lg p-5">
          <h2 className="text-sm font-semibold text-text-secondary uppercase tracking-wider mb-4">
            Top Finding Categories
          </h2>
          {topCategories.length === 0 ? (
            <p className="text-text-muted text-sm">No findings yet.</p>
          ) : (
            <div className="flex flex-col gap-3">
              {topCategories.map(([cat, count]) => {
                const maxCount = topCategories[0][1];
                const pct = Math.round((count / maxCount) * 100);
                return (
                  <div key={cat}>
                    <div className="flex justify-between text-xs mb-1">
                      <span className="text-text-primary font-mono uppercase">{cat}</span>
                      <span className="text-text-secondary">{count}</span>
                    </div>
                    <div className="w-full bg-bg-tertiary rounded-full h-2">
                      <div className="bg-accent h-2 rounded-full" style={{ width: `${pct}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </Layout>
  );
}
