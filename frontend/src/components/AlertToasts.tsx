import { useEffect, useState } from "react";
import { ShieldAlert, X } from "lucide-react";
import type { ScanResult } from "@/lib/scanner";

interface Toast {
  id: string;
  event: ScanResult;
}

export default function AlertToasts({ events }: { events: ScanResult[] }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  useEffect(() => {
    if (events.length === 0) return;
    const latest = events[0];
    if (latest.decision === "DENY") {
      const id = latest.event_id || crypto.randomUUID();
      setToasts((prev) => [{ id, event: latest }, ...prev].slice(0, 3));
      setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 5000);
    }
  }, [events]);

  if (toasts.length === 0) return null;

  return (
    <div className="fixed top-4 right-4 z-[200] space-y-2 w-80 max-w-[calc(100vw-2rem)]">
      {toasts.map((toast) => (
        <div
          key={toast.id}
          className="bg-red-500/10 border border-red-500/30 rounded-lg p-3 flex items-start gap-3 animate-[slideIn_0.3s_ease-out] backdrop-blur-sm"
        >
          <ShieldAlert className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div className="flex-1 min-w-0">
            <p className="text-sm font-semibold text-red-400">DENY</p>
            <p className="text-xs text-muted truncate">{toast.event.summary}</p>
          </div>
          <button onClick={() => setToasts((prev) => prev.filter((t) => t.id !== toast.id))} className="cursor-pointer">
            <X className="w-4 h-4 text-muted" />
          </button>
        </div>
      ))}
    </div>
  );
}
