import { useState } from "react";
import { FileWarning, Eye, Terminal, Shield, AlertTriangle, Network, KeyRound, Code, Bug, Globe, Database, Lock } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { Decision } from "@/lib/scanner";

interface PolicyRule {
  id: string;
  name: string;
  category: string;
  description: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  action: Decision;
  patterns: string[];
  enabled: boolean;
  icon: typeof Shield;
  color: string;
}

const defaultPolicies: PolicyRule[] = [
  // ─── Prompt Injection ──────────────────────────────────────────────────────
  {
    id: "PG-INJ-001", name: "Instruction Override", category: "Prompt Injection",
    description: "Detects attempts to override system or developer instructions by asking the model to ignore previous context.",
    severity: "Critical", action: "DENY",
    patterns: ["ignore.*previous.*instruction", "disregard.*system.*prompt", "bypass.*rules"],
    enabled: true, icon: FileWarning, color: "text-red-400",
  },
  {
    id: "PG-INJ-002", name: "Credential Exfiltration", category: "Prompt Injection",
    description: "Blocks prompts that attempt to extract passwords, API keys, tokens, or other credentials from the model context.",
    severity: "Critical", action: "DENY",
    patterns: ["reveal.*password", "dump.*credentials", "leak.*api.key", "echo.*token"],
    enabled: true, icon: KeyRound, color: "text-red-400",
  },
  {
    id: "PG-INJ-003", name: "Role Manipulation", category: "Prompt Injection",
    description: "Detects attempts to change the model's assigned role or persona to bypass safety constraints.",
    severity: "Critical", action: "DENY",
    patterns: ["you are now.*", "act as.*unrestricted", "DAN", "jailbreak", "god mode"],
    enabled: true, icon: AlertTriangle, color: "text-red-400",
  },
  {
    id: "PG-INJ-004", name: "Prompt Leaking", category: "Prompt Injection",
    description: "Blocks attempts to extract the system prompt or hidden instructions from the model.",
    severity: "Critical", action: "DENY",
    patterns: ["repeat.*system prompt", "show.*initial prompt", "reveal.*hidden prompt"],
    enabled: true, icon: Eye, color: "text-red-400",
  },
  {
    id: "PG-INJ-005", name: "Encoding Evasion", category: "Prompt Injection",
    description: "Detects use of hex, unicode, HTML entities, or URL encoding to bypass text-based filters.",
    severity: "Critical", action: "DENY",
    patterns: ["\\x41\\x42\\x43", "&#x61;&#x62;", "%41%42%43"],
    enabled: true, icon: Code, color: "text-red-400",
  },
  {
    id: "PG-INJ-006", name: "Indirect Injection Marker", category: "Prompt Injection",
    description: "Detects model-specific control tokens that indicate prompt injection from external content.",
    severity: "Critical", action: "DENY",
    patterns: ["[INST]", "<|im_start|>", "<<SYS>>", "[SYSTEM]"],
    enabled: true, icon: Bug, color: "text-red-400",
  },
  {
    id: "PG-INJ-007", name: "Multi-language Evasion", category: "Prompt Injection",
    description: "Detects use of foreign languages to evade English-only detection filters.",
    severity: "High", action: "HUMAN_REVIEW",
    patterns: ["traduce.*ignore", "übersetze.*system", "翻译.*instruction"],
    enabled: true, icon: Globe, color: "text-amber-400",
  },

  // ─── Policy Violations ─────────────────────────────────────────────────────
  {
    id: "PG-POL-001", name: "Social Engineering", category: "Policy Violation",
    description: "Blocks requests for phishing, impersonation, MFA bypass, or credential harvesting assistance.",
    severity: "Critical", action: "DENY",
    patterns: ["phish", "impersonate", "bypass mfa", "credential harvesting"],
    enabled: true, icon: AlertTriangle, color: "text-red-400",
  },
  {
    id: "PG-POL-002", name: "Malware Generation", category: "Policy Violation",
    description: "Prevents the model from generating malicious software including ransomware, keyloggers, and exploits.",
    severity: "Critical", action: "DENY",
    patterns: ["write.*malware", "create.*ransomware", "generate.*keylogger", "build.*rootkit"],
    enabled: true, icon: Bug, color: "text-red-400",
  },
  {
    id: "PG-POL-003", name: "SQL Injection Assistance", category: "Policy Violation",
    description: "Blocks requests for SQL injection payloads or database exploitation techniques.",
    severity: "Critical", action: "DENY",
    patterns: ["sql injection", "union select", "' or '1'='1", "drop table"],
    enabled: true, icon: Database, color: "text-red-400",
  },
  {
    id: "PG-POL-004", name: "XSS Payload Crafting", category: "Policy Violation",
    description: "Detects cross-site scripting payloads in prompts or model output.",
    severity: "Critical", action: "DENY",
    patterns: ["<script>", "javascript:", "onerror=", "document.cookie"],
    enabled: true, icon: Code, color: "text-red-400",
  },
  {
    id: "PG-POL-005", name: "SSRF Attempt", category: "Policy Violation",
    description: "Blocks server-side request forgery attempts targeting internal services or cloud metadata.",
    severity: "Critical", action: "DENY",
    patterns: ["169.254.169.254", "fetch.*metadata", "curl.*localhost", "access.*internal"],
    enabled: true, icon: Globe, color: "text-red-400",
  },
  {
    id: "PG-POL-006", name: "Privilege Escalation", category: "Policy Violation",
    description: "Detects requests for privilege escalation techniques targeting root or admin access.",
    severity: "Critical", action: "DENY",
    patterns: ["sudo.*root", "chmod 777", "setuid", "escalat.*privilege"],
    enabled: true, icon: Lock, color: "text-red-400",
  },

  // ─── Secret Leakage ────────────────────────────────────────────────────────
  {
    id: "PG-SEC-001", name: "AWS Access Key", category: "Secret Leakage",
    description: "Identifies AWS access key IDs (AKIA...) in content and blocks exposure.",
    severity: "Critical", action: "DENY",
    patterns: ["AKIA[0-9A-Z]{16}"],
    enabled: true, icon: Eye, color: "text-red-400",
  },
  {
    id: "PG-SEC-002", name: "JWT Token", category: "Secret Leakage",
    description: "Detects JSON Web Tokens in output content and flags for review.",
    severity: "High", action: "HUMAN_REVIEW",
    patterns: ["eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+"],
    enabled: true, icon: Eye, color: "text-violet-400",
  },
  {
    id: "PG-SEC-003", name: "Generic API Key", category: "Secret Leakage",
    description: "Detects generic secret assignments like api_key=, token=, password= with long values.",
    severity: "High", action: "HUMAN_REVIEW",
    patterns: ["api_key=...", "secret=...", "token=..."],
    enabled: true, icon: KeyRound, color: "text-violet-400",
  },
  {
    id: "PG-SEC-004", name: "Private Key Block", category: "Secret Leakage",
    description: "Detects PEM-encoded private keys (RSA, EC, OPENSSH, DSA, PGP) in content.",
    severity: "Critical", action: "DENY",
    patterns: ["-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----"],
    enabled: true, icon: Lock, color: "text-red-400",
  },
  {
    id: "PG-SEC-005", name: "Bearer Token", category: "Secret Leakage",
    description: "Detects Bearer authentication tokens in content.",
    severity: "High", action: "HUMAN_REVIEW",
    patterns: ["Bearer eyJ...", "Bearer sk-..."],
    enabled: true, icon: Eye, color: "text-violet-400",
  },
  {
    id: "PG-SEC-006", name: "GitHub Token", category: "Secret Leakage",
    description: "Identifies GitHub personal access tokens (ghp_, gho_, ghu_, ghs_, ghr_).",
    severity: "Critical", action: "DENY",
    patterns: ["ghp_[A-Za-z0-9]{36}", "gho_[A-Za-z0-9]{36}"],
    enabled: true, icon: KeyRound, color: "text-red-400",
  },
  {
    id: "PG-SEC-007", name: "Slack Token", category: "Secret Leakage",
    description: "Detects Slack API tokens (xoxb-, xoxp-, xoxa-, xoxr-, xoxs-).",
    severity: "Critical", action: "DENY",
    patterns: ["xoxb-...", "xoxp-..."],
    enabled: true, icon: KeyRound, color: "text-red-400",
  },
  {
    id: "PG-SEC-008", name: "Stripe Key", category: "Secret Leakage",
    description: "Identifies Stripe API keys (sk_test_, sk_live_, rk_test_, rk_live_).",
    severity: "Critical", action: "DENY",
    patterns: ["sk_test_[A-Za-z0-9]{20}", "sk_live_[A-Za-z0-9]{20}"],
    enabled: true, icon: KeyRound, color: "text-red-400",
  },
  {
    id: "PG-SEC-009", name: "Database Connection String", category: "Secret Leakage",
    description: "Detects database connection URIs with embedded credentials.",
    severity: "High", action: "HUMAN_REVIEW",
    patterns: ["mongodb://user:pass@...", "postgres://...", "mysql://..."],
    enabled: true, icon: Database, color: "text-violet-400",
  },
  {
    id: "PG-SEC-010", name: "Webhook URL", category: "Secret Leakage",
    description: "Detects Slack/Discord webhook URLs that could be abused for exfiltration.",
    severity: "Medium", action: "LOG",
    patterns: ["hooks.slack.com/...", "hooks.discord.com/..."],
    enabled: true, icon: Network, color: "text-blue-400",
  },
  {
    id: "PG-SEC-011", name: "Google API Key", category: "Secret Leakage",
    description: "Identifies Google API keys (AIza...) in content.",
    severity: "Critical", action: "DENY",
    patterns: ["AIza[0-9A-Za-z_-]{35}"],
    enabled: true, icon: KeyRound, color: "text-red-400",
  },
  {
    id: "PG-SEC-012", name: "AWS Secret Key", category: "Secret Leakage",
    description: "Detects AWS secret access keys in content.",
    severity: "Critical", action: "DENY",
    patterns: ["aws_secret_access_key=...", "AWS_SECRET_ACCESS_KEY=..."],
    enabled: true, icon: Lock, color: "text-red-400",
  },

  // ─── Tool Governance ───────────────────────────────────────────────────────
  {
    id: "PG-TOOL-001", name: "Destructive Commands", category: "Tool Governance",
    description: "Blocks shell commands that could destroy filesystems, such as rm -rf, format, mkfs, or dd operations.",
    severity: "Critical", action: "DENY",
    patterns: ["rm -rf /", "mkfs.*", "dd if=.* of=/dev/.*", "format C:"],
    enabled: true, icon: Terminal, color: "text-red-400",
  },
  {
    id: "PG-TOOL-002", name: "Credential File Access", category: "Tool Governance",
    description: "Flags tool calls that read sensitive credential files like SSH keys, shadow, or .env files.",
    severity: "High", action: "HUMAN_REVIEW",
    patterns: [".ssh/id_rsa", "/etc/shadow", ".aws/credentials", ".env", ".netrc"],
    enabled: true, icon: Eye, color: "text-violet-400",
  },
  {
    id: "PG-TOOL-003", name: "Network Exfiltration", category: "Tool Governance",
    description: "Blocks tool calls that send data to external endpoints via curl, wget, or netcat.",
    severity: "Critical", action: "DENY",
    patterns: ["curl.*--data", "wget.*--post-data", "nc.*upload"],
    enabled: true, icon: Network, color: "text-red-400",
  },
  {
    id: "PG-TOOL-004", name: "Reverse Shell", category: "Tool Governance",
    description: "Detects attempts to establish reverse shells via bash, netcat, python, or socat.",
    severity: "Critical", action: "DENY",
    patterns: ["bash -i >&", "/dev/tcp/", "nc -e", "python.*socket.*connect"],
    enabled: true, icon: Terminal, color: "text-red-400",
  },
  {
    id: "PG-TOOL-005", name: "Package Install from URL", category: "Tool Governance",
    description: "Flags installation of packages from external URLs that could introduce supply chain attacks.",
    severity: "High", action: "HUMAN_REVIEW",
    patterns: ["pip install http://...", "npm install git+...", "cargo install github.com/..."],
    enabled: true, icon: Code, color: "text-violet-400",
  },
  {
    id: "PG-TOOL-006", name: "Docker Escape", category: "Tool Governance",
    description: "Blocks attempts to escape containers or access the host via privileged mode or docker socket.",
    severity: "Critical", action: "DENY",
    patterns: ["docker run --privileged", "nsenter", "/var/run/docker.sock"],
    enabled: true, icon: Terminal, color: "text-red-400",
  },
  {
    id: "PG-TOOL-007", name: "Memory/Disk Dump", category: "Tool Governance",
    description: "Blocks attempts to dump process memory or raw disk for credential extraction.",
    severity: "Critical", action: "DENY",
    patterns: ["gcore", "/proc/*/mem", "/dev/mem", "memdump"],
    enabled: true, icon: AlertTriangle, color: "text-red-400",
  },
  {
    id: "PG-TOOL-008", name: "Scheduled Task Injection", category: "Tool Governance",
    description: "Flags modifications to cron jobs or scheduled tasks that could establish persistence.",
    severity: "High", action: "HUMAN_REVIEW",
    patterns: ["crontab -e", "/etc/cron.*", "schtasks /create"],
    enabled: true, icon: Code, color: "text-violet-400",
  },
  {
    id: "PG-TOOL-009", name: "Env Variable Harvesting", category: "Tool Governance",
    description: "Detects attempts to harvest environment variables containing secrets.",
    severity: "High", action: "HUMAN_REVIEW",
    patterns: ["printenv | grep secret", "env | grep key", "export | grep token"],
    enabled: true, icon: Eye, color: "text-violet-400",
  },
  {
    id: "PG-TOOL-010", name: "Firewall/Security Disable", category: "Tool Governance",
    description: "Blocks attempts to disable firewalls, SELinux, or other system security controls.",
    severity: "Critical", action: "DENY",
    patterns: ["ufw disable", "iptables -F", "setenforce 0", "systemctl stop firewall"],
    enabled: true, icon: Shield, color: "text-red-400",
  },
];

const severityColor: Record<string, string> = {
  Critical: "text-red-400 bg-red-500/10 border-red-500/30",
  High: "text-amber-400 bg-amber-500/10 border-amber-500/30",
  Medium: "text-blue-400 bg-blue-500/10 border-blue-500/30",
  Low: "text-muted bg-surface-alt border-border",
};

const categories = [...new Set(defaultPolicies.map(p => p.category))];

export default function PolicyPage() {
  const [policies, setPolicies] = useState(defaultPolicies);
  const [activeCategory, setActiveCategory] = useState<string | "ALL">("ALL");

  const togglePolicy = (id: string) => {
    setPolicies(prev => prev.map(p => p.id === id ? { ...p, enabled: !p.enabled } : p));
  };

  const filtered = activeCategory === "ALL" ? policies : policies.filter(p => p.category === activeCategory);
  const enabledCount = policies.filter(p => p.enabled).length;

  return (
    <div className="space-y-6">
      <header>
        <p className="text-xs font-semibold uppercase tracking-wider text-accent mb-1">Governance</p>
        <h2 className="text-2xl font-bold">Security Policies</h2>
        <p className="text-sm text-muted mt-1">Manage detection rules across prompt injection, secret leakage, policy violations, and tool governance.</p>
      </header>

      {/* Summary */}
      <div className="grid grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-4 flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-accent/10 flex items-center justify-center">
              <Shield className="w-4 h-4 text-accent" />
            </div>
            <div>
              <p className="text-xs text-muted">Active Rules</p>
              <p className="text-xl font-bold">{enabledCount}<span className="text-sm text-muted">/{policies.length}</span></p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-red-500/10 flex items-center justify-center">
              <FileWarning className="w-4 h-4 text-red-400" />
            </div>
            <div>
              <p className="text-xs text-muted">DENY Rules</p>
              <p className="text-xl font-bold">{policies.filter(p => p.action === "DENY").length}</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-violet-500/10 flex items-center justify-center">
              <AlertTriangle className="w-4 h-4 text-violet-400" />
            </div>
            <div>
              <p className="text-xs text-muted">REVIEW Rules</p>
              <p className="text-xl font-bold">{policies.filter(p => p.action === "HUMAN_REVIEW").length}</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-blue-500/10 flex items-center justify-center">
              <Eye className="w-4 h-4 text-blue-400" />
            </div>
            <div>
              <p className="text-xs text-muted">Categories</p>
              <p className="text-xl font-bold">{categories.length}</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Category Filter */}
      <div className="flex flex-wrap gap-2">
        <button
          onClick={() => setActiveCategory("ALL")}
          className={cn(
            "px-3 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer",
            activeCategory === "ALL" ? "bg-accent/20 text-accent border border-accent/30" : "bg-surface-alt text-muted border border-border hover:text-ink"
          )}
        >
          All ({policies.length})
        </button>
        {categories.map(cat => (
          <button
            key={cat}
            onClick={() => setActiveCategory(cat)}
            className={cn(
              "px-3 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer",
              activeCategory === cat ? "bg-accent/20 text-accent border border-accent/30" : "bg-surface-alt text-muted border border-border hover:text-ink"
            )}
          >
            {cat} ({policies.filter(p => p.category === cat).length})
          </button>
        ))}
      </div>

      {/* Policy Rules */}
      <div className="space-y-3">
        {filtered.map(policy => {
          const Icon = policy.icon;
          return (
            <Card key={policy.id} className={cn("transition-all", !policy.enabled && "opacity-50")}>
              <CardContent className="p-5">
                <div className="flex items-start gap-4">
                  <div className={cn("w-10 h-10 rounded-lg flex items-center justify-center shrink-0", policy.action === "DENY" ? "bg-red-500/10" : policy.action === "HUMAN_REVIEW" ? "bg-violet-500/10" : "bg-blue-500/10")}>
                    <Icon className={cn("w-5 h-5", policy.color)} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      <span className="font-mono text-xs text-muted">{policy.id}</span>
                      <span className={cn("text-xs px-1.5 py-0.5 rounded border", severityColor[policy.severity])}>{policy.severity}</span>
                      <Badge variant={policy.action}>{policy.action}</Badge>
                    </div>
                    <h4 className="font-semibold mb-1">{policy.name}</h4>
                    <p className="text-sm text-muted mb-3">{policy.description}</p>
                    <div className="flex flex-wrap gap-1.5">
                      {policy.patterns.map((p, i) => (
                        <code key={i} className="text-xs bg-background border border-border rounded px-1.5 py-0.5 text-muted font-mono">{p}</code>
                      ))}
                    </div>
                  </div>
                  <button
                    onClick={() => togglePolicy(policy.id)}
                    className={cn(
                      "w-11 h-6 rounded-full relative transition-colors shrink-0 cursor-pointer",
                      policy.enabled ? "bg-accent" : "bg-border"
                    )}
                  >
                    <span className={cn(
                      "absolute top-0.5 w-5 h-5 rounded-full bg-white transition-transform",
                      policy.enabled ? "left-5.5" : "left-0.5"
                    )} />
                  </button>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}
