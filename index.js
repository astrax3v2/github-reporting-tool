#!/usr/bin/env node

const { program } = require("commander");
const path = require("path");
const { createClient, fetchIssues, fetchIssueComments, parseVulnerability } = require("./src/github");
const { generateReport } = require("./src/report");

program
  .name("vapt-report")
  .description("Generate VAPT reports from GitHub repository issues")
  .argument("<repo>", "GitHub repository in owner/repo format")
  .option("-t, --token <token>", "GitHub personal access token (or set GITHUB_TOKEN env var)")
  .option("-l, --labels <labels>", "Filter issues by labels (comma-separated)", "")
  .option("-s, --state <state>", "Issue state: open, closed, all", "all")
  .option("-o, --output <path>", "Output file path", "")
  .option("-i, --issues <numbers>", "Specific issue numbers (comma-separated)", "")
  .action(async (repo, options) => {
    const [owner, repoName] = repo.split("/");
    if (!owner || !repoName) {
      console.error("Error: Repository must be in owner/repo format");
      process.exit(1);
    }

    const token = options.token || process.env.GITHUB_TOKEN;
    if (!token) {
      console.error("Error: GitHub token required. Use --token or set GITHUB_TOKEN env var");
      process.exit(1);
    }

    const outputPath = options.output || `VAPT_Report_${repoName}_${new Date().toISOString().slice(0, 10)}.docx`;

    try {
      const octokit = createClient(token);
      console.log(`Fetching issues from ${owner}/${repoName}...`);

      let issues;
      if (options.issues) {
        const numbers = options.issues.split(",").map(Number);
        issues = await Promise.all(
          numbers.map(async (n) => {
            const { data } = await octokit.rest.issues.get({ owner, repo: repoName, issue_number: n });
            return data;
          })
        );
      } else {
        issues = await fetchIssues(octokit, owner, repoName, {
          state: options.state,
          labels: options.labels || undefined,
        });
      }

      console.log(`Found ${issues.length} issues. Fetching comments...`);

      const vulns = await Promise.all(
        issues.map(async (issue) => {
          const comments = await fetchIssueComments(octokit, owner, repoName, issue.number);
          return parseVulnerability(issue, comments);
        })
      );

      console.log(`Parsed ${vulns.length} vulnerabilities. Generating report...`);

      const outFile = await generateReport(vulns, { owner, repo: repoName }, outputPath);
      console.log(`Report generated: ${path.resolve(outFile)}`);
    } catch (err) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

program.parse();
