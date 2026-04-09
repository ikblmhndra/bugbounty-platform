import { useEffect, useState } from "react";
import Layout from "../components/Layout";
import { apiClient, Asset } from "../lib/api";

export default function AttackSurfacePage() {
  const [assets, setAssets] = useState<Asset[]>([]);

  useEffect(() => {
    apiClient.getAssets({ limit: 1000 }).then(setAssets).catch(() => setAssets([]));
  }, []);

  return (
    <Layout>
      <h1 className="text-2xl font-semibold mb-4">Attack Surface</h1>
      <div className="bg-bg-secondary border border-border rounded-lg p-4">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-text-secondary">
              <th className="text-left py-2">Type</th>
              <th className="text-left py-2">Value</th>
              <th className="text-left py-2">Alive</th>
              <th className="text-left py-2">Status</th>
            </tr>
          </thead>
          <tbody>
            {assets.map((a) => (
              <tr key={a.id} className="border-t border-border">
                <td className="py-2 uppercase">{a.asset_type}</td>
                <td className="py-2 font-mono">{a.value}</td>
                <td className="py-2">{String(a.is_alive ?? "-")}</td>
                <td className="py-2">{a.status_code ?? "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Layout>
  );
}
