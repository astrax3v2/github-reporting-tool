# GitHub VAPT Report Generator

Generate professional Vulnerability Assessment & Penetration Testing (VAPT) reports in `.docx` format from GitHub repository issues.

## Setup

```bash
npm install
```

## Usage

```bash
# Generate report from all issues
node index.js owner/repo --token ghp_yourtoken

# Filter by labels
node index.js owner/repo --token ghp_yourtoken --labels "vulnerability,bug"

# Specific issues only
node index.js owner/repo --token ghp_yourtoken --issues 5,12,18

# Custom output path
node index.js owner/repo --token ghp_yourtoken --output my-report.docx

# Using env var for token
export GITHUB_TOKEN=ghp_yourtoken
node index.js owner/repo
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --token` | GitHub personal access token | `GITHUB_TOKEN` env var |
| `-l, --labels` | Filter by labels (comma-separated) | all issues |
| `-s, --state` | Issue state: `open`, `closed`, `all` | `all` |
| `-o, --output` | Output `.docx` file path | `VAPT_Report_<repo>_<date>.docx` |
| `-i, --issues` | Specific issue numbers (comma-separated) | all issues |

## Issue Format

For best results, structure GitHub issues with these sections:

- **Affected URL** — the endpoint or URL affected
- **Analysis** — description of the vulnerability
- **Impact** — potential impact
- **Remediation** — recommended fixes
- **POC** — proof of concept / steps to reproduce

Severity is detected from issue labels (`critical`, `high`, `medium`, `low`) or from the body text.

## Report Output

The generated `.docx` report includes:

1. **Cover Page** — project details, date, classification
2. **Executive Summary** — overview of findings
3. **Severity Summary Table** — counts by severity level
4. **Findings Overview Table** — all vulnerabilities at a glance
5. **Detailed Findings** — per-vulnerability tables with full details and comments
6. **Disclaimer**
