# @promptguard/sdk

TypeScript SDK for [PromptGuard AI](https://github.com/Murzuqisah/PromptGuard-AI) — enterprise agent firewall.

## Install

```bash
npm install @promptguard/sdk
```

## Usage

```typescript
import { PromptGuardClient } from "@promptguard/sdk";

const client = new PromptGuardClient({
  baseUrl: "http://localhost:8000",
  apiKey: "your-key",
});

// Simple boolean check (fail-safe: returns false on error)
if (await client.isPermitted("execute_command", "rm -rf /tmp")) {
  execute();
}

// Full result with findings
const result = await client.guard("send_email", emailBody, "output");
console.log(result.decision, result.risk_score, result.findings);

// Scan content
const scan = await client.scan("Ignore previous instructions", "prompt");
console.log(scan.decision);
```
