import { NavLink, Outlet } from "react-router-dom";
import { Shield, Zap, Activity, Lock, Sparkles, Menu, X } from "lucide-react";
import { cn } from "@/lib/utils";
import { useEffect, useState } from "react";
import { checkHealth } from "@/lib/scanner";

export default function Layout() {
  const [apiOnline, setApiOnline] = useState(false);
  const [aiEnabled, setAiEnabled] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

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

  const mobileLinkClass = ({ isActive }: { isActive: boolean }) =>
    cn(
      "flex flex-col items-center gap-1 px-3 py-2 text-xs transition-colors",
      isActive ? "text-accent" : "text-muted"
    );

  return (
    <div className="min-h-screen flex flex-col lg:flex-row">
      {/* Desktop Sidebar */}
      <aside className="hidden lg:flex fixed inset-y-0 left-0 w-64 bg-surface border-r border-border flex-col p-6 z-50">
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

      {/* Mobile Header */}
      <header className="lg:hidden flex items-center justify-between px-4 py-3 bg-surface border-b border-border sticky top-0 z-50">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-lg bg-accent/20 flex items-center justify-center">
            <Shield className="w-4 h-4 text-accent" />
          </div>
          <span className="font-bold text-ink">PromptGuard</span>
        </div>
        <div className="flex items-center gap-3">
          <span className={cn("w-2 h-2 rounded-full", apiOnline ? "bg-emerald-400" : "bg-amber-500")} />
          {aiEnabled && <Sparkles className="w-3.5 h-3.5 text-violet-400" />}
          <button onClick={() => setMobileMenuOpen(!mobileMenuOpen)} className="p-1 cursor-pointer">
            {mobileMenuOpen ? <X className="w-5 h-5 text-muted" /> : <Menu className="w-5 h-5 text-muted" />}
          </button>
        </div>
      </header>

      {/* Mobile Dropdown Menu */}
      {mobileMenuOpen && (
        <div className="lg:hidden bg-surface border-b border-border px-4 py-3 space-y-1 z-40">
          <NavLink to="/" className={linkClass} onClick={() => setMobileMenuOpen(false)}>
            <Zap className="w-4 h-4" /> Scanner
          </NavLink>
          <NavLink to="/audit" className={linkClass} onClick={() => setMobileMenuOpen(false)}>
            <Activity className="w-4 h-4" /> Audit Trail
          </NavLink>
          <NavLink to="/policy" className={linkClass} onClick={() => setMobileMenuOpen(false)}>
            <Lock className="w-4 h-4" /> Policies
          </NavLink>
        </div>
      )}

      {/* Main Content */}
      <main className="lg:ml-64 flex-1 p-4 sm:p-6 lg:p-8 pb-20 lg:pb-8">
        <Outlet />
      </main>

      {/* Mobile Bottom Nav */}
      <nav className="lg:hidden fixed bottom-0 inset-x-0 bg-surface border-t border-border flex justify-around py-2 z-50 safe-bottom">
        <NavLink to="/" className={mobileLinkClass}>
          <Zap className="w-5 h-5" />
          <span>Scan</span>
        </NavLink>
        <NavLink to="/audit" className={mobileLinkClass}>
          <Activity className="w-5 h-5" />
          <span>Audit</span>
        </NavLink>
        <NavLink to="/policy" className={mobileLinkClass}>
          <Lock className="w-5 h-5" />
          <span>Policy</span>
        </NavLink>
      </nav>
    </div>
  );
}
