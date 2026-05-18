import { ShieldOff } from "lucide-react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";

export default function NotFound() {
  return (
    <div className="min-h-[60vh] flex flex-col items-center justify-center text-center px-4">
      <div className="w-16 h-16 rounded-2xl bg-red-500/10 flex items-center justify-center mb-6">
        <ShieldOff className="w-8 h-8 text-red-400" />
      </div>
      <h1 className="text-5xl font-bold text-ink mb-2">404</h1>
      <p className="text-lg text-muted mb-6">Page not found. This route doesn't exist.</p>
      <Link to="/">
        <Button variant="primary">Back to Scanner</Button>
      </Link>
    </div>
  );
}
