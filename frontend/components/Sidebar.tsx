import Link from "next/link";
import { useRouter } from "next/router";
import { clsx } from "clsx";

const NAV_ITEMS = [
  { href: "/",          label: "Dashboard",    icon: "📊" },
  { href: "/attack-surface", label: "Attack Surface", icon: "🌐" },
  { href: "/scan-monitor", label: "Scan Monitor", icon: "🛰️" },
  { href: "/findings",  label: "Findings",     icon: "🔍" },
  { href: "/target-profile", label: "Target Profile", icon: "🎯" },
];

export default function Sidebar() {
  const router = useRouter();

  return (
    <aside className="w-56 bg-bg-secondary border-r border-border flex flex-col min-h-screen fixed left-0 top-0">
      {/* Logo */}
      <div className="px-5 py-5 border-b border-border">
        <div className="flex items-center gap-2">
          <span className="text-2xl">🔍</span>
          <div>
            <div className="text-sm font-bold text-text-primary leading-tight">Bug Bounty</div>
            <div className="text-xs text-text-secondary">Platform</div>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 flex flex-col gap-1">
        {NAV_ITEMS.map(item => {
          const active = router.pathname === item.href ||
            (item.href !== "/" && router.pathname.startsWith(item.href));
          return (
            <Link
              key={item.href}
              href={item.href}
              className={clsx(
                "flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors",
                active
                  ? "bg-bg-tertiary text-accent font-medium"
                  : "text-text-secondary hover:text-text-primary hover:bg-bg-tertiary"
              )}
            >
              <span>{item.icon}</span>
              <span>{item.label}</span>
            </Link>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="px-5 py-4 border-t border-border text-xs text-text-muted">
        Authorized use only
      </div>
    </aside>
  );
}
