import { useEffect, useState } from "react";
import Link from "next/link";
import Layout from "../components/Layout";
import { StatCard, StatusBadge, SectionHeader, Spinner, EmptyState, SeverityBadge } from "../components/ui";
import { apiClient, DashboardStats } from "../lib/api";
import { formatDistanceToNow } from "date-fns";
import { Bar, BarChart, Line, LineChart, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis, Cell, Legend } from "recharts";

const SEVERITY_COLORS = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#6b7280"
};

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

  const severityChart = Object.entries(stats.findings_by_severity).map(([name, value]) => ({
    name: name.charAt(0).toUpperCase() + name.slice(1),
    value,
    color: SEVERITY_COLORS[name as keyof typeof SEVERITY_COLORS] || "#6b7280"
  }));

  const getScanProgress = (scan: (typeof stats.recent_scans)[number]) => {
    if (!scan.steps_total || scan.steps_total <= 0) return 0;
    return Math.min(100, Math.round((scan.steps_completed / scan.steps_total) * 100));
  };

  const formatStepName = (step?: string) =>
    step ? step.replace(/_/g, " ") : "pending";

  return (
    <Layout>
      <SectionHeader
        title="Security Operations Center"
        subtitle="Real-time offensive security monitoring & orchestration"
      />

      {/* Key Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-4 mb-8">
        <StatCard label="Targets"       value={stats.total_targets}    accent="text-cyan-400" />
        <StatCard label="Total Scans"   value={stats.total_scans}      accent="text-blue-400" />
        <StatCard label="Active Scans"  value={stats.active_scans}     accent="text-yellow-400" />
        <StatCard label="Total Assets"  value={stats.total_assets}     accent="text-purple-400" />
        <StatCard label="Total Findings" value={stats.total_findings}  accent="text-red-400" />
        <StatCard label="Critical Vulns" value={stats.critical_findings} accent="text-red-600" />
      </div>

      {/* Severity Breakdown */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
        <div className="bg-bg-secondary border border-border rounded-lg p-5">
          <h3 className="text-sm font-semibold text-text-secondary uppercase tracking-wider mb-4">
            Findings by Severity
          </h3>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie
                data={severityChart}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="50%"
                outerRadius={60}
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
              >
                {severityChart.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-bg-secondary border border-border rounded-lg p-5">
          <h3 className="text-sm font-semibold text-text-secondary uppercase tracking-wider mb-4">
            Top Categories
          </h3>
          <div className="space-y-3">
            {topCategories.map(([category, count]) => (
              <div key={category} className="flex justify-between items-center">
                <span className="text-sm text-text-primary capitalize">{category}</span>
                <span className="text-sm font-mono text-accent">{count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Active Scans Monitor */}
        <div className="bg-bg-secondary border border-border rounded-lg p-5">
          <h2 className="text-sm font-semibold text-text-secondary uppercase tracking-wider mb-4">
            Active Scan Monitor
          </h2>
          {stats.recent_scans.filter(s => s.status === 'running').length === 0 ? (
            <p className="text-text-muted text-sm">No active scans.</p>
          ) : (
            <div className="flex flex-col gap-4">
              {stats.recent_scans.filter(s => s.status === 'running').map(scan => {
                const progress = getScanProgress(scan);
                return (
                  <Link
                    key={scan.id}
                    href={`/scans/${scan.id}`}
                    className="p-4 rounded-md bg-bg-tertiary hover:border-accent border border-transparent transition-colors"
                  >
                    <div className="flex items-center justify-between gap-3 mb-2">
                      <div>
                        <p className="font-mono text-xs text-text-primary">{scan.id.slice(0, 12)}...</p>
                        <p className="text-xs text-text-secondary mt-0.5">
                          {formatDistanceToNow(new Date(scan.created_at), { addSuffix: true })}
                        </p>
                      </div>
                      <StatusBadge status={scan.status} />
                    </div>

                    <div className="mb-2">
                      <div className="flex justify-between text-xs mb-1">
                        <span className="text-text-secondary capitalize">{formatStepName(scan.current_step)}</span>
                        <span className="text-text-secondary">{progress}%</span>
                      </div>
                      <div className="w-full bg-bg-primary rounded-full h-2">
                        <div
                          className="bg-accent h-2 rounded-full transition-all duration-300"
                          style={{ width: `${progress}%` }}
                        />
                      </div>
                    </div>

                    <div className="flex justify-between text-xs text-text-secondary">
                      <span>Assets: {scan.assets_found}</span>
                      <span>Findings: {scan.findings_count}</span>
                    </div>
                  </Link>
                );
              })}
            </div>
          )}
        </div>

        {/* Recent Findings */}
        <div className="bg-bg-secondary border border-border rounded-lg p-5">
          <h2 className="text-sm font-semibold text-text-secondary uppercase tracking-wider mb-4">
            Recent Critical Findings
          </h2>
          {stats.recent_scans.length === 0 ? (
            <p className="text-text-muted text-sm">No recent findings.</p>
          ) : (
            <div className="space-y-3">
              {/* This would need to be added to the API response */}
              <p className="text-text-muted text-sm">Feature coming soon...</p>
            </div>
          )}
        </div>
      </div>
    </Layout>
  );
}
