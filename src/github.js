const { Octokit } = require("@octokit/rest");

function createClient(token) {
  return new Octokit({ auth: token });
}

async function fetchIssues(octokit, owner, repo, options = {}) {
  const params = {
    owner,
    repo,
    state: options.state || "all",
    per_page: options.perPage || 100,
  };
  if (options.labels) params.labels = options.labels;

  const issues = await octokit.paginate(octokit.rest.issues.listForRepo, params);
  return issues.filter((i) => !i.pull_request);
}

async function fetchIssueComments(octokit, owner, repo, issueNumber) {
  const { data } = await octokit.rest.issues.listComments({
    owner,
    repo,
    issue_number: issueNumber,
  });
  return data;
}

function parseVulnerability(issue, comments) {
  const body = issue.body || "";
  const vuln = {
    id: `VULN-${String(issue.number).padStart(3, "0")}`,
    title: issue.title,
    status: issue.state,
    labels: issue.labels.map((l) => l.name),
    severity: extractSeverity(issue),
    affectedUrl: extractSection(body, "Affected URL") || extractSection(body, "Affected Endpoint") || "N/A",
    analysis: extractSection(body, "Analysis") || extractSection(body, "Description") || "",
    impact: extractSection(body, "Impact") || "",
    remediation: extractSection(body, "Remediation") || extractSection(body, "Recommendation") || "",
    poc: extractSection(body, "POC") || extractSection(body, "Proof of Concept") || extractSection(body, "Steps to Reproduce") || "",
    rawBody: body,
    comments: comments.map((c) => ({
      author: c.user.login,
      body: c.body,
      date: c.created_at,
    })),
    createdAt: issue.created_at,
    updatedAt: issue.updated_at,
    author: issue.user.login,
  };
  return vuln;
}

function extractSeverity(issue) {
  const labels = issue.labels.map((l) => l.name.toLowerCase());
  for (const sev of ["critical", "high", "medium", "low", "informational", "info"]) {
    if (labels.some((l) => l.includes(sev))) return sev === "info" ? "Informational" : capitalize(sev);
  }
  const body = (issue.body || "").toLowerCase();
  for (const sev of ["critical", "high", "medium", "low"]) {
    if (body.includes(`severity: ${sev}`) || body.includes(`severity:${sev}`) || body.includes(`risk: ${sev}`)) {
      return capitalize(sev);
    }
  }
  return "Medium";
}

function extractSection(body, heading) {
  const patterns = [
    new RegExp(`##?\\s*${heading}[:\\s]*\\n([\\s\\S]*?)(?=\\n##|$)`, "i"),
    new RegExp(`\\*\\*${heading}\\*\\*[:\\s]*\\n([\\s\\S]*?)(?=\\n\\*\\*|\\n##|$)`, "i"),
    new RegExp(`${heading}[:\\s]*\\n([\\s\\S]*?)(?=\\n[A-Z][a-z]+[:\\s]*\\n|\\n##|$)`, "i"),
  ];
  for (const re of patterns) {
    const match = body.match(re);
    if (match) return match[1].trim();
  }
  return "";
}

function capitalize(s) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

module.exports = { createClient, fetchIssues, fetchIssueComments, parseVulnerability };
