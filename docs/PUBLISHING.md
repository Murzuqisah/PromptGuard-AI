# SDK Publishing Guide

Instructions for publishing PromptGuard AI SDK packages to PyPI and npm via GitHub Actions.

---

## Overview

| Package | Registry | Workflow | Trigger |
|---------|----------|----------|---------|
| `promptguard-ai` | PyPI | `publish-python.yml` | Tag `sdk/python/v*` |
| `@promptguard/sdk` | npm | `publish-npm.yml` | Tag `sdk/typescript/v*` |

Both workflows also support manual trigger via the GitHub Actions UI (`workflow_dispatch`).

---

## Python SDK → PyPI

### Setup (one-time)

#### 1. Create GitHub Environment

Go to: <https://github.com/Murzuqisah/PromptGuard-AI/settings/environments>

- Click **New environment**
- Name: `pypi`
- Click **Configure environment**
- No additional protection rules needed (or add reviewers for approval before publish)

#### 2. Register Trusted Publisher on PyPI

Go to: <https://pypi.org/manage/account/publishing/>

Under **Add a new pending publisher**, fill in:

| Field | Value |
|-------|-------|
| PyPI project name | `promptguard-ai` |
| Owner | `Murzuqisah` |
| Repository name | `PromptGuard-AI` |
| Workflow name | `publish-python.yml` |
| Environment name | `pypi` |

Click **Add**.

This uses OpenID Connect (OIDC) — no API token is needed. GitHub Actions authenticates directly with PyPI.

#### 3. Publish

```bash
# Tag and push
git tag sdk/python/v1.0.0
git push origin sdk/python/v1.0.0
```

The workflow will automatically build and publish to PyPI.

#### Verify

```bash
pip install promptguard-ai
python -c "from promptguard import PromptGuardClient; print('OK')"
```

Package URL: <https://pypi.org/project/promptguard-ai/>

---

## TypeScript SDK → npm

### Setup (one-time)

#### 1. Create npm Access Token

Go to: <https://www.npmjs.com/settings/YOUR_USERNAME/tokens>

- Click **Generate New Token**
- Type: **Automation** (for CI/CD, no 2FA prompt)
- Copy the token (starts with `npm_`)

#### 2. Add Token as GitHub Secret

```bash
gh secret set NPM_TOKEN
# Paste the npm token when prompted
```

Or go to: <https://github.com/Murzuqisah/PromptGuard-AI/settings/secrets/actions>

- Click **New repository secret**
- Name: `NPM_TOKEN`
- Value: your npm token

#### 3. Create GitHub Environment (optional)

Go to: <https://github.com/Murzuqisah/PromptGuard-AI/settings/environments>

- Create environment named `npm`
- Add protection rules if desired (e.g., require approval)

#### 4. Publish

```bash
# Tag and push
git tag sdk/typescript/v1.0.0
git push origin sdk/typescript/v1.0.0
```

The workflow will automatically build and publish to npm.

#### Verify

```bash
npm install @promptguard/sdk
node -e "const { PromptGuardClient } = require('@promptguard/sdk'); console.log('OK')"
```

Package URL: <https://www.npmjs.com/package/@promptguard/sdk>

---

## Version Bumping

When releasing a new version:

1. Update the version in the package file:
   - Python: `sdks/python/pyproject.toml` → `version = "1.1.0"`
   - TypeScript: `sdks/typescript/package.json` → `"version": "1.1.0"`

2. Commit the version bump:

   ```bash
   git add sdks/
   git commit -m "chore: bump SDK versions to 1.1.0"
   git push origin main
   ```

3. Tag and push:

   ```bash
   git tag sdk/python/v1.1.0
   git tag sdk/typescript/v1.1.0
   git push origin --tags
   ```

---

## Manual Trigger

Both workflows support `workflow_dispatch`. To trigger manually:

1. Go to <https://github.com/Murzuqisah/PromptGuard-AI/actions>
2. Select the workflow (Publish Python SDK or Publish TypeScript SDK)
3. Click **Run workflow**
4. Select the branch and click **Run workflow**

---

## Troubleshooting

### PyPI: "Publisher not found"

Ensure the trusted publisher is configured with the exact values:

- Owner must match the GitHub org/user (case-sensitive)
- Workflow filename must match exactly (`publish-python.yml`)
- Environment name must match (`pypi`)

### PyPI: "Project already exists"

The package name is taken. Change `name` in `pyproject.toml` and re-register the trusted publisher.

### npm: "403 Forbidden"

- Verify `NPM_TOKEN` secret is set correctly
- Ensure the token has publish permissions
- Check if the package name is available: `npm info @promptguard/sdk`

### npm: "Package name too similar"

npm may reject names similar to existing packages. Try a different scope or name.

---

## CI Workflow Files

- Python: `.github/workflows/publish-python.yml`
- TypeScript: `.github/workflows/publish-npm.yml`
