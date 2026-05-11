import { NavLink, Outlet } from "react-router-dom";
import { Shield, Zap, Activity, Lock, Sparkles } from "lucide-react";
import { cn } from "@/lib/utils";
import { useEffect, useState } from "react";
import { checkHealth } from "@/lib/scanner";

export default function Layout() {
  const [apiOnline, setApiOnline] = useState(false);
  const [aiEnabled, setAiEnabled] = useState(false);

  useEffect(() => {
    const check = () => checkHealth().then(({ online, aiEnabled }) => {
      setApiOnline(online);
      setAiEnabled(aiEnabled);
    });
    check();
    const interval = setInterval(check, 15000);
    return () => clearInterval(interval);
  }, []);

  const linkClass = ({ isActive }: { isActive: boolean }) =>
    cn(
      "flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm transition-colors",
      isActive ? "text-ink bg-surface-alt border border-border" : "text-muted hover:text-ink hover:bg-surface-alt border border-transparent"
    );

  return (
    <div className="min-h-screen flex">
      <aside className="fixed inset-y-0 left-0 w-64 bg-surface border-r border-border flex flex-col p-6 z-50">
        <div className="flex items-center gap-3 mb-10">
          <div className="w-9 h-9 rounded-lg bg-accent/20 flex items-center justify-center">
            <Shield className="w-5 h-5 text-accent" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-ink leading-tight">PromptGuard</h1>
            <p className="text-xs text-muted">Agent Firewall</p>
          </div>
        </div>

        <nav className="flex flex-col gap-1">
          <NavLink to="/" className={linkClass}>
            <Zap className="w-4 h-4" /> Scanner
          </NavLink>
          <NavLink to="/audit" className={linkClass}>
            <Activity className="w-4 h-4" /> Audit Trail
          </NavLink>
          <NavLink to="/policy" className={linkClass}>
            <Lock className="w-4 h-4" /> Policies
          </NavLink>
        </nav>

        <div className="mt-auto space-y-2">
          <div className="flex items-center gap-2 text-xs text-muted">
            <span className={cn("w-2 h-2 rounded-full", apiOnline ? "bg-emerald-400" : "bg-amber-500")} />
            {apiOnline ? "API Connected" : "Local Demo Mode"}
          </div>
          <div className="flex items-center gap-2 text-xs text-muted">
            <Sparkles className={cn("w-3 h-3", aiEnabled ? "text-violet-400" : "text-muted")} />
            {aiEnabled ? "Gemini AI Active" : "AI Inactive"}
          </div>
        </div>
      </aside>

      <main className="ml-64 flex-1 p-8">
        <Outlet />
      </main>
    </div>
  );
}
