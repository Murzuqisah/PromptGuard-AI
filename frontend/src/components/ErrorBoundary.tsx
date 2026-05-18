import { Component, type ReactNode } from "react";
import { AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export default class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false, error: null };

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-background flex flex-col items-center justify-center text-center px-4">
          <div className="w-16 h-16 rounded-2xl bg-amber-500/10 flex items-center justify-center mb-6">
            <AlertTriangle className="w-8 h-8 text-amber-400" />
          </div>
          <h1 className="text-3xl font-bold text-ink mb-2">Something went wrong</h1>
          <p className="text-muted mb-2 max-w-md">An unexpected error occurred in the application.</p>
          <pre className="text-xs text-red-400 bg-surface border border-border rounded-lg p-3 mb-6 max-w-lg overflow-auto">
            {this.state.error?.message}
          </pre>
          <Button variant="primary" onClick={() => window.location.reload()}>
            Reload Page
          </Button>
        </div>
      );
    }
    return this.props.children;
  }
}
