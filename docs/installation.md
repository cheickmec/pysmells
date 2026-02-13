# Installation Guide

smellcheck ships as a Python package (pip, GitHub Action, pre-commit) and as an [Agent Skills](https://agentskills.io) plugin for AI coding assistants. This guide covers every supported platform.

## Python package

### pip

```bash
pip install smellcheck

smellcheck src/
smellcheck myfile.py --format json
smellcheck src/ --min-severity warning --fail-on warning
```

### GitHub Action

```yaml
- uses: cheickmec/smellcheck@v1
  with:
    paths: 'src/'
    fail-on: 'error'       # exit 1 on error-level findings (default)
    min-severity: 'info'   # display all findings (default)
    format: 'github'       # GitHub annotations (default)
```

### pre-commit

```yaml
repos:
  - repo: https://github.com/cheickmec/smellcheck
    rev: v0.3.1
    hooks:
      - id: smellcheck
        args: ['--fail-on', 'warning']
```

### SARIF / Code Scanning

Upload smellcheck findings to GitHub Code Scanning so they appear as native alerts in the Security tab and as PR annotations:

```yaml
code-scanning:
  runs-on: ubuntu-latest
  permissions:
    security-events: write
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-python@v5
      with:
        python-version: '3.12'
    - run: pip install smellcheck
    - run: smellcheck src/ --format sarif --min-severity warning > results.sarif
      continue-on-error: true
    - uses: github/codeql-action/upload-sarif@v4
      with:
        sarif_file: results.sarif
      if: always()
```

---

## Agent Skills plugin

The Agent Skills plugin is a directory containing `SKILL.md`, 8 reference files, and a detection script with a bundled copy of smellcheck. **No pip install required** -- the skill works out of the box after installation.

### Claude Code

```bash
/plugin marketplace add cheickmec/smellcheck
/plugin install python-refactoring@smellcheck
```

Then use `/python-refactoring` or ask Claude to refactor your code.

### OpenAI Codex CLI

```bash
$skill-installer install cheickmec/smellcheck
```

### Gemini CLI

```bash
gemini skills install https://github.com/cheickmec/smellcheck.git \
  --path plugins/python-refactoring/skills/python-refactoring
```

Or copy to the workspace skills directory:

```bash
git clone --depth 1 https://github.com/cheickmec/smellcheck.git /tmp/smellcheck
mkdir -p .gemini/skills
cp -r /tmp/smellcheck/plugins/python-refactoring/skills/python-refactoring .gemini/skills/
rm -rf /tmp/smellcheck
```

### Universal installer

Works with Claude Code, Cursor, Copilot, Codex, Gemini CLI, and any tool supporting the Agent Skills standard:

```bash
npx ai-agent-skills install cheickmec/smellcheck
```

### Cursor

Copy the skill directory into your project's `.cursor/skills/` folder:

```bash
git clone --depth 1 https://github.com/cheickmec/smellcheck.git /tmp/smellcheck
mkdir -p .cursor/skills
cp -r /tmp/smellcheck/plugins/python-refactoring/skills/python-refactoring .cursor/skills/
rm -rf /tmp/smellcheck
```

Restart Cursor -- the agent auto-discovers skills in `.cursor/skills/`.

For global installation (all projects), copy to `~/.cursor/skills/` instead.

### VS Code / GitHub Copilot

```bash
git clone --depth 1 https://github.com/cheickmec/smellcheck.git /tmp/smellcheck
mkdir -p .github/skills
cp -r /tmp/smellcheck/plugins/python-refactoring/skills/python-refactoring .github/skills/
rm -rf /tmp/smellcheck
```

### Roo Code

```bash
git clone --depth 1 https://github.com/cheickmec/smellcheck.git /tmp/smellcheck
mkdir -p .roo/skills
cp -r /tmp/smellcheck/plugins/python-refactoring/skills/python-refactoring .roo/skills/
rm -rf /tmp/smellcheck
```

### Windsurf

```bash
git clone --depth 1 https://github.com/cheickmec/smellcheck.git /tmp/smellcheck
mkdir -p .windsurf/skills
cp -r /tmp/smellcheck/plugins/python-refactoring/skills/python-refactoring .windsurf/skills/
rm -rf /tmp/smellcheck
```

---

## Tools without Agent Skills support

For tools that only read flat markdown rule files, copy `SKILL.md` as a rule. The AI gets the smell catalog and can run the CLI, but won't have the reference files for refactoring guidance.

### Continue.dev

```bash
curl -fsSL https://raw.githubusercontent.com/cheickmec/smellcheck/main/plugins/python-refactoring/skills/python-refactoring/SKILL.md \
  -o .continue/rules/smellcheck.md
```

### Amazon Q

```bash
curl -fsSL https://raw.githubusercontent.com/cheickmec/smellcheck/main/plugins/python-refactoring/skills/python-refactoring/SKILL.md \
  -o .amazonq/rules/smellcheck.md
```

### Aider

No install needed -- load at runtime:

```bash
aider --read /path/to/SKILL.md
```

---

## Compatibility matrix

| Tool | Install method | Status |
|------|---------------|--------|
| pip | `pip install smellcheck` | Native |
| GitHub Actions | `uses: cheickmec/smellcheck@v1` | Native |
| pre-commit | `.pre-commit-config.yaml` | Native |
| Claude Code | `/plugin marketplace add` | Native |
| OpenAI Codex CLI | `$skill-installer install` | Native |
| Cursor | `.cursor/skills/` | Native |
| GitHub Copilot | `.github/skills/` | Native |
| Roo Code | `.roo/skills/` | Native |
| Gemini CLI | `gemini skills install` | Native |
| Windsurf | `.windsurf/skills/` | Manual |
| Continue.dev | `.continue/rules/` | Manual |
| Amazon Q | `.amazonq/rules/` | Manual |
| Aider | `--read SKILL.md` | Manual |
