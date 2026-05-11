import { useEffect, useState } from "react";
import { RefreshCw, Filter, AlertTriangle, ShieldCheck, ShieldAlert, Clock } from "lucide-react";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { checkHealth, fetchAudit, type Channel, type Decision, type ScanResult } from "@/lib/scanner";

const channelLabels: Record<Channel, string> = { prompt: "Prompt", output: "Model Output", file: "Uploaded Text", tool_call: "Tool Call" };
const decisions: Decision[] = ["ALLOW", "LOG", "HUMAN_REVIEW", "DENY"];

export default function AuditPage() {
  const [apiOnline, setApiOnline] = useState(false);
  const [events, setEvents] = useState<ScanResult[]>([]);
  const [filterDecision, setFilterDecision] = useState<Decision | "ALL">("ALL");
  const [filterChannel, setFilterChannel] = useState<Channel | "ALL">("ALL");
  const [selected, setSelected] = useState<ScanResult | null>(null);

  useEffect(() => {
    checkHealth().then(({ online }) => {
      setApiOnline(online);
      if (online) fetchAudit().then(setEvents);
    });
  }, []);

  const refresh = async () => {
    if (apiOnline) {
      const data = await fetchAudit();
      setEvents(data);
    }
  };

  const filtered = events.filter(e => {
    if (filterDecision !== "ALL" && e.decision !== filterDecision) return false;
    if (filterChannel !== "ALL" && e.channel !== filterChannel) return false;
    return true;
  });

  const stats = {
    total: events.length,
    denied: events.filter(e => e.decision === "DENY").length,
    allowed: events.filter(e => e.decision === "ALLOW").length,
    review: events.filter(e => e.decision === "HUMAN_REVIEW").length,
  };

  return (
    <div className="space-y-6">
      <header className="flex items-center justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wider text-accent mb-1">Security Events</p>
          <h2 className="text-2xl font-bold">Audit Trail</h2>
        </div>
        <Button variant="ghost" size="sm" onClick={refresh}>
          <RefreshCw className="w-4 h-4 mr-2" /> Refresh
        </Button>
      </header>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-4 flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-blue-500/10 flex items-center justify-center">
              <Clock className="w-4 h-4 text-blue-400" />
            </div>
            <div>
              <p className="text-xs text-muted">Total Events</p>
              <p className="text-xl font-bold">{stats.total}</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-emerald-500/10 flex items-center justify-center">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
            </div>
            <div>
              <p className="text-xs text-muted">Allowed</p>
              <p className="text-xl font-bold">{stats.allowed}</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-violet-500/10 flex items-center justify-center">
              <AlertTriangle className="w-4 h-4 text-violet-400" />
            </div>
            <div>
              <p className="text-xs text-muted">Needs Review</p>
              <p className="text-xl font-bold">{stats.review}</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-red-500/10 flex items-center justify-center">
              <ShieldAlert className="w-4 h-4 text-red-400" />
            </div>
            <div>
              <p className="text-xs text-muted">Denied</p>
              <p className="text-xl font-bold">{stats.denied}</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Filters + Table */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between w-full">
            <div className="flex items-center gap-2">
              <Filter className="w-4 h-4 text-muted" />
              <h3 className="text-base font-semibold">Events</h3>
              <span className="text-xs text-muted">({filtered.length})</span>
            </div>
            <div className="flex gap-2">
              <select
                value={filterDecision}
                onChange={e => setFilterDecision(e.target.value as Decision | "ALL")}
                className="h-8 rounded-lg border border-border bg-surface-alt text-xs text-ink px-2 focus:outline-none focus:ring-1 focus:ring-accent"
              >
                <option value="ALL">All Decisions</option>
                {decisions.map(d => <option key={d} value={d}>{d}</option>)}
              </select>
              <select
                value={filterChannel}
                onChange={e => setFilterChannel(e.target.value as Channel | "ALL")}
                className="h-8 rounded-lg border border-border bg-surface-alt text-xs text-ink px-2 focus:outline-none focus:ring-1 focus:ring-accent"
              >
                <option value="ALL">All Channels</option>
                {Object.entries(channelLabels).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
              </select>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {!apiOnline ? (
            <p className="text-sm text-muted italic py-8 text-center">Connect to the API to view audit events. Run the backend on port 8000.</p>
          ) : filtered.length === 0 ? (
            <p className="text-sm text-muted italic py-8 text-center">No events match the current filters.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border text-left">
                    <th className="pb-2 pr-4 text-xs text-muted font-medium">Time</th>
                    <th className="pb-2 pr-4 text-xs text-muted font-medium">Channel</th>
                    <th className="pb-2 pr-4 text-xs text-muted font-medium">Decision</th>
                    <th className="pb-2 pr-4 text-xs text-muted font-medium">Risk</th>
                    <th className="pb-2 text-xs text-muted font-medium">Summary</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((e, i) => (
                    <tr
                      key={i}
                      onClick={() => setSelected(e)}
                      className={cn(
                        "border-b border-border/50 cursor-pointer transition-colors",
                        selected === e ? "bg-surface-alt" : "hover:bg-surface-alt/50"
                      )}
                    >
                      <td className="py-2.5 pr-4 text-muted whitespace-nowrap">{new Date(e.timestamp).toLocaleTimeString()}</td>
                      <td className="py-2.5 pr-4">{channelLabels[e.channel]}</td>
                      <td className="py-2.5 pr-4"><Badge variant={e.decision}>{e.decision}</Badge></td>
                      <td className="py-2.5 pr-4 font-mono">{e.risk_score}</td>
                      <td className="py-2.5 text-muted truncate max-w-sm">{e.summary}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Detail Panel */}
      {selected && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between w-full">
              <h3 className="text-base font-semibold">Event Detail</h3>
              <Button variant="ghost" size="sm" onClick={() => setSelected(null)}>Close</Button>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-4 gap-4 text-sm">
              <div>
                <p className="text-xs text-muted">Timestamp</p>
                <p className="font-mono">{new Date(selected.timestamp).toLocaleString()}</p>
              </div>
              <div>
                <p className="text-xs text-muted">Channel</p>
                <p>{channelLabels[selected.channel]}</p>
              </div>
              <div>
                <p className="text-xs text-muted">Decision</p>
                <Badge variant={selected.decision}>{selected.decision}</Badge>
              </div>
              <div>
                <p className="text-xs text-muted">Risk Score</p>
                <p className="font-mono">{selected.risk_score}/100</p>
              </div>
            </div>
            <div>
              <p className="text-xs text-muted mb-1">Summary</p>
              <p className="text-sm">{selected.summary}</p>
            </div>
            {selected.findings.length > 0 && (
              <div>
                <p className="text-xs font-semibold text-muted uppercase tracking-wider mb-2">Findings ({selected.findings.length})</p>
                <div className="space-y-2">
                  {selected.findings.map((f, i) => (
                    <div key={i} className="rounded-lg border border-border bg-background p-3 text-sm">
                      <span className="font-semibold">{f.rule_id}</span>
                      <span className="text-muted"> · {f.name}</span>
                      <span className="text-muted"> · severity {f.severity}</span>
                      <p className="text-xs text-muted mt-1">{f.explanation}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {selected.masked_content && (
              <div>
                <p className="text-xs font-semibold text-muted uppercase tracking-wider mb-2">Masked Content</p>
                <pre className="text-xs bg-background border border-border rounded-lg p-3 overflow-auto max-h-40 text-muted whitespace-pre-wrap">{selected.masked_content}</pre>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
