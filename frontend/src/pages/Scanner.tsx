import { useCallback, useEffect, useRef, useState } from "react";
import { FileWarning, Sparkles } from "lucide-react";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { checkHealth, scan, scenarios, type Channel, type Decision, type ScanResult } from "@/lib/scanner";

const channelLabels: Record<Channel, string> = { prompt: "Prompt", output: "Model Output", file: "Uploaded Text", tool_call: "Tool Call" };

function decisionColor(d: Decision) {
  return { ALLOW: "text-emerald-400", LOG: "text-blue-400", HUMAN_REVIEW: "text-violet-400", DENY: "text-red-400" }[d];
}

function riskBarColor(d: Decision) {
  return { ALLOW: "bg-emerald-500", LOG: "bg-blue-500", HUMAN_REVIEW: "bg-violet-500", DENY: "bg-red-500" }[d];
}

export default function ScannerPage() {
  const [apiOnline, setApiOnline] = useState(false);
  const [channel, setChannel] = useState<Channel>("prompt");
  const [content, setContent] = useState(scenarios.normal.content);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [scanning, setScanning] = useState(false);
  const initialized = useRef(false);

  useEffect(() => {
    if (initialized.current) return;
    initialized.current = true;
    checkHealth().then(({ online }) => {
      setApiOnline(online);
      doScan("prompt", scenarios.normal.content, online);
    });
  }, []);

  const doScan = useCallback(async (ch: Channel, text: string, online?: boolean) => {
    if (!text.trim()) return;
    setScanning(true);
    const r = await scan(ch, text, online ?? apiOnline);
    setResult(r);
    setScanning(false);
  }, [apiOnline]);

  const handleScenario = (key: string) => {
    const s = scenarios[key];
    setChannel(s.channel);
    setContent(s.content);
    doScan(s.channel, s.content);
  };

  return (
    <div className="space-y-6">
      <header>
        <p className="text-xs font-semibold uppercase tracking-wider text-accent mb-1">Live Gateway</p>
        <h2 className="text-2xl font-bold">Security Scanner</h2>
      </header>

      {/* Metrics */}
      {result && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 sm:gap-4">
          <Card>
            <CardContent className="p-4">
              <p className="text-xs text-muted mb-1">Decision</p>
              <p className={cn("text-2xl font-bold", decisionColor(result.decision))}>{result.decision}</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4">
              <p className="text-xs text-muted mb-1">Risk Score</p>
              <p className="text-2xl font-bold">{result.risk_score}<span className="text-sm text-muted">/100</span></p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4">
              <p className="text-xs text-muted mb-1">Findings</p>
              <p className="text-2xl font-bold">{(result.findings || []).length}</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4">
              <p className="text-xs text-muted mb-1">Channel</p>
              <p className="text-2xl font-bold">{channelLabels[result.channel]}</p>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Scanner + Results */}
      <section className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between w-full">
              <h3 className="text-base font-semibold">Input</h3>
              <select
                value={channel}
                onChange={e => setChannel(e.target.value as Channel)}
                className="h-8 rounded-lg border border-border bg-surface-alt text-sm text-ink px-3 focus:outline-none focus:ring-1 focus:ring-accent"
              >
                {Object.entries(channelLabels).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
              </select>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <textarea
              value={content}
              onChange={e => setContent(e.target.value)}
              spellCheck={false}
              className="w-full h-52 rounded-lg border border-border bg-background text-sm text-ink p-3 resize-y focus:outline-none focus:ring-1 focus:ring-accent font-mono"
            />
            <div className="flex flex-wrap gap-2">
              <Button size="sm" onClick={() => handleScenario("normal")}>Normal</Button>
              <Button size="sm" onClick={() => handleScenario("injection")}>Injection</Button>
              <Button size="sm" onClick={() => handleScenario("secret")}>Secret Leak</Button>
              <Button size="sm" onClick={() => handleScenario("tool")}>Tool Risk</Button>
              <Button variant="primary" size="sm" className="ml-auto" onClick={() => doScan(channel, content)} disabled={scanning}>
                {scanning ? "Scanning..." : "Scan"}
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <h3 className="text-base font-semibold">Decision Packet</h3>
              {result?.ai_enhanced && (
                <span className="flex items-center gap-1 text-xs text-violet-400 bg-violet-500/10 border border-violet-500/30 rounded-full px-2 py-0.5">
                  <Sparkles className="w-3 h-3" /> AI Enhanced
                </span>
              )}
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            {result ? (
              <>
                <p className="text-sm text-muted">{result.summary}</p>
                <div className="h-2 rounded-full bg-surface-alt overflow-hidden">
                  <div className={cn("h-full transition-all duration-300", riskBarColor(result.decision))} style={{ width: `${result.risk_score}%` }} />
                </div>
                {(result.findings || []).length > 0 ? (
                  <div className="space-y-2">
                    <p className="text-xs font-semibold text-muted uppercase tracking-wider">Findings</p>
                    {(result.findings || []).map((f, i) => (
                      <div key={i} className="rounded-lg border border-border bg-background p-3">
                        <div className="flex items-center gap-2 mb-1">
                          <FileWarning className="w-3.5 h-3.5 text-red-400" />
                          <span className="text-sm font-semibold">{f.rule_id}</span>
                          <span className="text-sm text-muted">· {f.name}</span>
                        </div>
                        <p className="text-xs text-muted">{f.explanation}</p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted italic">No findings.</p>
                )}
                {result.masked_content && (
                  <div>
                    <p className="text-xs font-semibold text-muted uppercase tracking-wider mb-2">Masked Output</p>
                    <pre className="text-xs bg-background border border-border rounded-lg p-3 overflow-auto max-h-32 text-muted whitespace-pre-wrap">{result.masked_content}</pre>
                  </div>
                )}
              </>
            ) : (
              <p className="text-sm text-muted italic">Run a scan to see results.</p>
            )}
          </CardContent>
        </Card>
      </section>
    </div>
  );
}
