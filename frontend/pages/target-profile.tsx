import { useEffect, useState } from "react";
import Layout from "../components/Layout";
import { apiClient, Scan, Target } from "../lib/api";

export default function TargetProfilePage() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);

  useEffect(() => {
    apiClient.getTargets().then(setTargets).catch(() => setTargets([]));
    apiClient.getScans({ limit: 100 }).then(setScans).catch(() => setScans([]));
  }, []);

  return (
    <Layout>
      <h1 className="text-2xl font-semibold mb-4">Target Profile</h1>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {targets.map((target) => {
          const tScans = scans.filter((s) => s.target_id === target.id);
          const totalFindings = tScans.reduce((acc, s) => acc + s.findings_count, 0);
          return (
            <div key={target.id} className="bg-bg-secondary border border-border rounded-lg p-4">
              <p className="font-semibold">{target.domain}</p>
              <p className="text-sm text-text-secondary mt-1">Scans: {tScans.length}</p>
              <p className="text-sm text-text-secondary">Findings: {totalFindings}</p>
            </div>
          );
        })}
      </div>
    </Layout>
  );
}
