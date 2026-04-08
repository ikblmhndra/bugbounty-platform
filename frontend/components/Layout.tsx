import Sidebar from "./Sidebar";

export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-bg-primary text-text-primary flex">
      <Sidebar />
      <main className="flex-1 ml-56 p-8 max-w-7xl">
        {children}
      </main>
    </div>
  );
}
