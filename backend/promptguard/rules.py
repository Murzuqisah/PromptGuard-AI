from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from re import Pattern, compile


class Decision(StrEnum):
    ALLOW = "ALLOW"
    LOG = "LOG"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    DENY = "DENY"


class Channel(StrEnum):
    PROMPT = "prompt"
    OUTPUT = "output"
    FILE = "file"


@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str
    category: str
    severity: int
    decision: Decision
    pattern: Pattern[str]
    explanation: str


# ─── Prompt Injection Rules ───────────────────────────────────────────────────

PROMPT_RULES = [
    Rule(
        "PG-INJ-001",
        "Instruction override",
        "prompt_injection",
        35,
        Decision.DENY,
        compile(r"\b(ignore|disregard|forget|override|bypass)\b.{0,60}\b(previous|prior|system|developer|above)\b.{0,40}\b(instructions?|prompts?|messages?|rules?|context)\b", 2),
        "The prompt asks the model to override higher-priority instructions.",
    ),
    Rule(
        "PG-INJ-002",
        "Credential exfiltration",
        "prompt_injection",
        45,
        Decision.DENY,
        compile(r"\b(reveal|print|show|dump|exfiltrate|leak|output|display|echo)\b.{0,60}\b(passwords?|credentials?|secrets?|api[-_ ]?keys?|tokens?|private keys?|env(ironment)?\s*var)", 2),
        "The prompt attempts to extract secrets or credentials.",
    ),
    Rule(
        "PG-INJ-003",
        "Role manipulation",
        "prompt_injection",
        30,
        Decision.DENY,
        compile(r"\b(you are now|act as|pretend to be|developer mode|god mode|jailbreak|DAN|unrestricted mode|no filter)\b", 2),
        "The prompt attempts to change model role or safety posture.",
    ),
    Rule(
        "PG-INJ-004",
        "Prompt leaking",
        "prompt_injection",
        30,
        Decision.DENY,
        compile(r"\b(repeat|print|show|reveal|output)\b.{0,40}\b(system prompt|system message|initial prompt|hidden prompt|instructions above)\b", 2),
        "The prompt attempts to extract the system prompt.",
    ),
    Rule(
        "PG-INJ-005",
        "Encoding evasion",
        "prompt_injection",
        35,
        Decision.DENY,
        compile(r"(\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|&#x?[0-9a-fA-F]+;|%[0-9a-fA-F]{2}){3,}", 0),
        "The prompt uses encoded sequences to evade detection.",
    ),
    Rule(
        "PG-INJ-006",
        "Indirect injection marker",
        "prompt_injection",
        40,
        Decision.DENY,
        compile(r"\[INST\]|\[/INST\]|<\|im_start\|>|<\|im_end\|>|<<SYS>>|<</SYS>>|\[SYSTEM\]", 0),
        "The prompt contains model-specific control tokens indicating injection.",
    ),
    Rule(
        "PG-INJ-007",
        "Multi-language evasion",
        "prompt_injection",
        25,
        Decision.HUMAN_REVIEW,
        compile(r"\b(traduce|übersetze|traduire|翻译|переведи).{0,40}\b(ignore|system|instruction)", 2),
        "The prompt uses a foreign language to evade English-only filters.",
    ),
    Rule(
        "PG-POL-001",
        "Social engineering",
        "policy_violation",
        30,
        Decision.DENY,
        compile(r"\b(phish|spoof|impersonate|bypass mfa|steal session|credential harvesting|pretexting)\b", 2),
        "The prompt appears to request social engineering assistance.",
    ),
    Rule(
        "PG-POL-002",
        "Malware generation",
        "policy_violation",
        50,
        Decision.DENY,
        compile(r"\b(write|create|generate|build).{0,40}\b(malware|ransomware|keylogger|trojan|rootkit|backdoor|exploit|virus|worm)\b", 2),
        "The prompt requests generation of malicious software.",
    ),
    Rule(
        "PG-POL-003",
        "SQL injection assistance",
        "policy_violation",
        35,
        Decision.DENY,
        compile(r"\b(sql injection|sqli|union select|' or '1'='1|drop table|; --)\b", 2),
        "The prompt requests SQL injection attack assistance.",
    ),
    Rule(
        "PG-POL-004",
        "XSS payload crafting",
        "policy_violation",
        35,
        Decision.DENY,
        compile(r"<script[^>]*>|javascript:|on(error|load|click)\s*=|document\.(cookie|location)", 2),
        "The prompt contains or requests cross-site scripting payloads.",
    ),
    Rule(
        "PG-POL-005",
        "SSRF attempt",
        "policy_violation",
        40,
        Decision.DENY,
        compile(r"\b(fetch|request|curl|wget|access)\b.{0,40}\b(169\.254\.169\.254|metadata|localhost|127\.0\.0\.1|0\.0\.0\.0|internal)", 2),
        "The prompt attempts server-side request forgery against internal services.",
    ),
    Rule(
        "PG-POL-006",
        "Privilege escalation",
        "policy_violation",
        40,
        Decision.DENY,
        compile(r"\b(sudo|chmod\s+[0-7]*777|chown\s+root|setuid|escalat|privilege)\b.{0,40}\b(root|admin|superuser|0)", 2),
        "The prompt requests privilege escalation techniques.",
    ),
]


# ─── Secret Detection Rules ──────────────────────────────────────────────────

SECRET_RULES = [
    Rule(
        "PG-SEC-001",
        "AWS access key",
        "secret_leakage",
        45,
        Decision.DENY,
        compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "An AWS access key pattern was detected.",
    ),
    Rule(
        "PG-SEC-002",
        "JWT token",
        "secret_leakage",
        35,
        Decision.HUMAN_REVIEW,
        compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"),
        "A JWT-like token was detected.",
    ),
    Rule(
        "PG-SEC-003",
        "Generic API key",
        "secret_leakage",
        30,
        Decision.HUMAN_REVIEW,
        compile(r"\b(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?", 2),
        "A generic secret assignment was detected.",
    ),
    Rule(
        "PG-SEC-004",
        "Private key block",
        "secret_leakage",
        50,
        Decision.DENY,
        compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
        "A private key block was detected.",
    ),
    Rule(
        "PG-SEC-005",
        "Bearer token",
        "secret_leakage",
        35,
        Decision.HUMAN_REVIEW,
        compile(r"\bBearer\s+[A-Za-z0-9_\-\.]{20,}\b"),
        "A Bearer authentication token was detected.",
    ),
    Rule(
        "PG-SEC-006",
        "GitHub token",
        "secret_leakage",
        45,
        Decision.DENY,
        compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b"),
        "A GitHub personal access token was detected.",
    ),
    Rule(
        "PG-SEC-007",
        "Slack token",
        "secret_leakage",
        40,
        Decision.DENY,
        compile(r"\bxox[baprs]-[0-9]{10,}-[A-Za-z0-9\-]+\b"),
        "A Slack API token was detected.",
    ),
    Rule(
        "PG-SEC-008",
        "Stripe key",
        "secret_leakage",
        45,
        Decision.DENY,
        compile(r"\b[sr]k_(test|live)_[A-Za-z0-9]{20,}\b"),
        "A Stripe API key was detected.",
    ),
    Rule(
        "PG-SEC-009",
        "Database connection string",
        "secret_leakage",
        40,
        Decision.HUMAN_REVIEW,
        compile(r"(mongodb|postgres|mysql|redis)://[^\s'\"]{10,}", 2),
        "A database connection string with credentials was detected.",
    ),
    Rule(
        "PG-SEC-010",
        "Webhook URL",
        "secret_leakage",
        25,
        Decision.LOG,
        compile(r"https?://hooks\.(slack|discord)\.com/[^\s'\"]{10,}", 2),
        "A webhook URL was detected that could be abused.",
    ),
    Rule(
        "PG-SEC-011",
        "Google API key",
        "secret_leakage",
        40,
        Decision.DENY,
        compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        "A Google API key was detected.",
    ),
    Rule(
        "PG-SEC-012",
        "AWS secret key",
        "secret_leakage",
        50,
        Decision.DENY,
        compile(r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*[A-Za-z0-9/+=]{40}"),
        "An AWS secret access key was detected.",
    ),
]


# ─── Tool Call Rules ─────────────────────────────────────────────────────────

TOOL_RULES = [
    Rule(
        "PG-TOOL-001",
        "Destructive filesystem command",
        "dangerous_tool_call",
        55,
        Decision.DENY,
        compile(r"\brm\s+-rf\s+(?:/|\$HOME|~|\*)|\\bmkfs\b|\bdd\s+if=|\bformat\s+[a-zA-Z]:", 2),
        "The tool call contains a destructive filesystem operation.",
    ),
    Rule(
        "PG-TOOL-002",
        "Credential file access",
        "dangerous_tool_call",
        35,
        Decision.HUMAN_REVIEW,
        compile(r"(\.ssh/id_rsa|/etc/shadow|/etc/passwd|\.aws/credentials|\.env|\.netrc|\.pgpass)", 2),
        "The tool call accesses sensitive local credential material.",
    ),
    Rule(
        "PG-TOOL-003",
        "Network exfiltration",
        "dangerous_tool_call",
        40,
        Decision.DENY,
        compile(r"\b(curl|wget|nc|netcat|ncat)\b.{0,120}\b(upload|paste|webhook|http|--data|--post|-d\s)", 2),
        "The tool call resembles network exfiltration.",
    ),
    Rule(
        "PG-TOOL-004",
        "Reverse shell",
        "dangerous_tool_call",
        55,
        Decision.DENY,
        compile(r"(bash\s+-i\s+>&|/dev/tcp/|nc\s+-[elp]|mkfifo|python.*socket.*connect|socat\s+exec)", 2),
        "The tool call attempts to establish a reverse shell.",
    ),
    Rule(
        "PG-TOOL-005",
        "Package install from URL",
        "dangerous_tool_call",
        30,
        Decision.HUMAN_REVIEW,
        compile(r"\b(pip|npm|gem|cargo)\s+install\b.{0,60}(http|git\+|github\.com)", 2),
        "The tool call installs packages from an external URL.",
    ),
    Rule(
        "PG-TOOL-006",
        "Docker escape",
        "dangerous_tool_call",
        50,
        Decision.DENY,
        compile(r"(docker\s+run\s+.*--privileged|nsenter|mount\s+.*proc|/var/run/docker\.sock)", 2),
        "The tool call attempts container escape or host access.",
    ),
    Rule(
        "PG-TOOL-007",
        "Disk or memory dump",
        "dangerous_tool_call",
        45,
        Decision.DENY,
        compile(r"\b(gcore|memdump|/proc/\d+/mem|/dev/mem|strings\s+/proc)", 2),
        "The tool call attempts to dump process memory or disk.",
    ),
    Rule(
        "PG-TOOL-008",
        "Cron/scheduled task injection",
        "dangerous_tool_call",
        35,
        Decision.HUMAN_REVIEW,
        compile(r"(crontab\s+-[elr]|/etc/cron|schtasks\s+/create|at\s+\d)", 2),
        "The tool call modifies scheduled tasks for persistence.",
    ),
    Rule(
        "PG-TOOL-009",
        "Environment variable harvesting",
        "dangerous_tool_call",
        30,
        Decision.HUMAN_REVIEW,
        compile(r"\b(printenv|env\b|set\b|export\b).{0,20}(grep|secret|key|token|password)", 2),
        "The tool call attempts to harvest environment variables.",
    ),
    Rule(
        "PG-TOOL-010",
        "Firewall/security disable",
        "dangerous_tool_call",
        50,
        Decision.DENY,
        compile(r"\b(ufw\s+disable|iptables\s+-F|setenforce\s+0|systemctl\s+stop\s+firewall)", 2),
        "The tool call attempts to disable system security controls.",
    ),
]
