import { useEffect, useState } from "react";
import Layout from "../components/Layout";
import { apiClient, Scan, ScanStage } from "../lib/api";

export default function ScanMonitorPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [stagesByScan, setStagesByScan] = useState<Record<string, ScanStage[]>>({});

  useEffect(() => {
    apiClient.getScans({ limit: 20 }).then(async (rows) => {
      setScans(rows);
      const map: Record<string, ScanStage[]> = {};
      await Promise.all(rows.slice(0, 10).map(async (s) => {
        map[s.id] = await apiClient.getScanStages(s.id).catch(() => []);
      }));
      setStagesByScan(map);
    });
  }, []);

  return (
    <Layout>
      <h1 className="text-2xl font-semibold mb-4">Scan Monitor</h1>
      <div className="space-y-3">
        {scans.map((scan) => (
          <div key={scan.id} className="bg-bg-secondary border border-border rounded-lg p-4">
            <p className="font-mono text-xs">{scan.id}</p>
            <p className="text-sm mt-1">Status: {scan.status}</p>
            <div className="mt-2 flex flex-wrap gap-2">
              {(stagesByScan[scan.id] || []).map((st) => (
                <span key={st.id} className="px-2 py-1 rounded bg-bg-tertiary text-xs">
                  {st.stage_type}:{st.status}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </Layout>
  );
}
