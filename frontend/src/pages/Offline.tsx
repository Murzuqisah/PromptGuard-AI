import { WifiOff } from "lucide-react";
import { Button } from "@/components/ui/button";

export default function Offline() {
  return (
    <div className="min-h-[60vh] flex flex-col items-center justify-center text-center px-4">
      <div className="w-16 h-16 rounded-2xl bg-amber-500/10 flex items-center justify-center mb-6">
        <WifiOff className="w-8 h-8 text-amber-400" />
      </div>
      <h1 className="text-3xl font-bold text-ink mb-2">You're Offline</h1>
      <p className="text-muted mb-6 max-w-md">
        Unable to connect to the PromptGuard API. Check your network connection or verify the backend is running.
      </p>
      <Button variant="primary" onClick={() => window.location.reload()}>
        Retry Connection
      </Button>
    </div>
  );
}
