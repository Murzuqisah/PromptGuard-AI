/**
 * PromptGuard AI TypeScript SDK
 *
 * A typed client for the PromptGuard AI firewall API with retry logic
 * and fail-safe behavior.
 */

export interface GuardResult {
  permitted: boolean;
  decision: "ALLOW" | "LOG" | "HUMAN_REVIEW" | "DENY";
  risk_score: number;
  event_id: string;
  summary: string;
  findings_count: number;
  findings: Finding[];
  ai_enhanced: boolean;
  action: string;
  source: string;
  timestamp: string;
}

export interface ScanResult {
  event_id: string;
  decision: "ALLOW" | "LOG" | "HUMAN_REVIEW" | "DENY";
  risk_score: number;
  summary: string;
  findings: Finding[];
  masked_content: string;
  ai_enhanced: boolean;
  channel: string;
  timestamp: string;
  tenant_id: string;
}

export interface Finding {
  rule_id: string;
  name: string;
  category: string;
  severity: number;
  decision: string;
  evidence: string;
  explanation: string;
}

export interface BatchResult {
  overall_decision: "ALLOW" | "DENY";
  total: number;
  denied: number;
  results: { decision: string; risk_score: number; event_id: string; summary: string; findings_count: number }[];
}

export interface PromptGuardOptions {
  baseUrl: string;
  apiKey?: string;
  timeout?: number;
  maxRetries?: number;
  failSafeDecision?: "ALLOW" | "DENY";
}

export class PromptGuardError extends Error {
  constructor(public statusCode: number, public detail: string) {
    super(`PromptGuard API error ${statusCode}: ${detail}`);
    this.name = "PromptGuardError";
  }
}

export class PromptGuardClient {
  private baseUrl: string;
  private apiKey: string;
  private timeout: number;
  private maxRetries: number;
  private failSafeDecision: "ALLOW" | "DENY";

  constructor(options: PromptGuardOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.apiKey = options.apiKey || "";
    this.timeout = options.timeout || 10000;
    this.maxRetries = options.maxRetries || 3;
    this.failSafeDecision = options.failSafeDecision || "DENY";
  }

  async guard(action: string, content: string, channel = "prompt", source = "ts-sdk", metadata: Record<string, unknown> = {}): Promise<GuardResult> {
    return this.request<GuardResult>("POST", "/v1/guard", { action, content, channel, source, metadata });
  }

  async isPermitted(action: string, content: string, channel = "prompt"): Promise<boolean> {
    try {
      const result = await this.guard(action, content, channel);
      return result.permitted;
    } catch {
      return this.failSafeDecision === "ALLOW";
    }
  }

  async scan(content: string, channel = "prompt"): Promise<ScanResult> {
    return this.request<ScanResult>("POST", "/scan", { channel, content });
  }

  async scanTool(toolName: string, args: Record<string, unknown>): Promise<ScanResult> {
    return this.request<ScanResult>("POST", "/scan-tool", { tool_name: toolName, arguments: args });
  }

  async batchScan(items: { channel: string; content: string }[]): Promise<BatchResult> {
    return this.request<BatchResult>("POST", "/v1/batch", { items });
  }

  async health(): Promise<Record<string, unknown>> {
    return this.request("GET", "/health");
  }

  async stats(): Promise<Record<string, unknown>> {
    return this.request("GET", "/v1/stats");
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (this.apiKey) headers["Authorization"] = `Bearer ${this.apiKey}`;

    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeout);

      try {
        const res = await fetch(url, {
          method,
          headers,
          body: body ? JSON.stringify(body) : undefined,
          signal: controller.signal,
        });
        clearTimeout(timer);

        if (res.status === 429) {
          const retryAfter = parseInt(res.headers.get("Retry-After") || "60", 10);
          await this.sleep(Math.min(retryAfter * 1000, 120000));
          continue;
        }

        if (!res.ok) {
          const data = await res.json().catch(() => ({ detail: res.statusText }));
          throw new PromptGuardError(res.status, data.detail || res.statusText);
        }

        return (await res.json()) as T;
      } catch (err) {
        clearTimeout(timer);
        if (err instanceof PromptGuardError) throw err;
        if (attempt === this.maxRetries - 1) throw err;
        await this.sleep(2 ** attempt * 1000);
      }
    }
    throw new PromptGuardError(503, "Max retries exceeded");
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
