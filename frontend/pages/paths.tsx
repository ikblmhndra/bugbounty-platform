import Layout from "../components/Layout";
import { SectionHeader } from "../components/ui";

export default function PathsPage() {
  return (
    <Layout>
      <SectionHeader
        title="Attack Paths (Deprecated)"
        subtitle="V2 replaces static path graphs with staged scan monitor and target profile analytics."
      />
      <div className="bg-bg-secondary border border-border rounded-lg p-6 text-sm text-text-secondary">
        Use <code>/scan-monitor</code> and <code>/target-profile</code> for V2 orchestration visibility.
      </div>
    </Layout>
  );
}
