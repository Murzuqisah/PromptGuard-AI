import { useEffect, useState } from "react";
import { Shield } from "lucide-react";

export default function SplashScreen({ onComplete }: { onComplete: () => void }) {
  const [fadeOut, setFadeOut] = useState(false);

  useEffect(() => {
    const timer = setTimeout(() => setFadeOut(true), 1200);
    const done = setTimeout(onComplete, 1600);
    return () => { clearTimeout(timer); clearTimeout(done); };
  }, [onComplete]);

  return (
    <div className={`fixed inset-0 z-[100] bg-background flex flex-col items-center justify-center transition-opacity duration-400 ${fadeOut ? "opacity-0" : "opacity-100"}`}>
      <div className="w-20 h-20 rounded-2xl bg-accent/20 flex items-center justify-center mb-6 animate-pulse">
        <Shield className="w-10 h-10 text-accent" />
      </div>
      <h1 className="text-2xl font-bold text-ink">PromptGuard AI</h1>
      <p className="text-sm text-muted mt-2">Enterprise Agent Firewall</p>
      <div className="mt-8 w-32 h-1 rounded-full bg-surface-alt overflow-hidden">
        <div className="h-full bg-accent rounded-full animate-[loading_1.2s_ease-in-out]" />
      </div>
    </div>
  );
}
