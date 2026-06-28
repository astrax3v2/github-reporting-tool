const {
  Document,
  Packer,
  Paragraph,
  Table,
  TableRow,
  TableCell,
  TextRun,
  WidthType,
  AlignmentType,
  BorderStyle,
  ShadingType,
  HeadingLevel,
  PageBreak,
  Header,
  Footer,
  PageNumber,
  NumberFormat,
} = require("docx");
const fs = require("fs");

const SEVERITY_COLORS = {
  Critical: "8B0000",
  High: "FF0000",
  Medium: "FFA500",
  Low: "008000",
  Informational: "0000FF",
};

const BORDER = {
  top: { style: BorderStyle.SINGLE, size: 1, color: "999999" },
  bottom: { style: BorderStyle.SINGLE, size: 1, color: "999999" },
  left: { style: BorderStyle.SINGLE, size: 1, color: "999999" },
  right: { style: BorderStyle.SINGLE, size: 1, color: "999999" },
};

function headerCell(text, widthPct) {
  return new TableCell({
    width: { size: widthPct, type: WidthType.PERCENTAGE },
    shading: { type: ShadingType.SOLID, color: "1a237e" },
    borders: BORDER,
    children: [
      new Paragraph({
        alignment: AlignmentType.CENTER,
        children: [new TextRun({ text, bold: true, color: "FFFFFF", size: 20, font: "Calibri" })],
      }),
    ],
  });
}

function cell(text, widthPct, options = {}) {
  return new TableCell({
    width: { size: widthPct, type: WidthType.PERCENTAGE },
    borders: BORDER,
    shading: options.shading,
    children: [
      new Paragraph({
        children: [
          new TextRun({
            text: text || "N/A",
            size: 18,
            font: "Calibri",
            bold: options.bold,
            color: options.color,
          }),
        ],
      }),
    ],
  });
}

function multiLineCell(text, widthPct) {
  const lines = (text || "N/A").split("\n").filter(Boolean);
  return new TableCell({
    width: { size: widthPct, type: WidthType.PERCENTAGE },
    borders: BORDER,
    children: lines.map(
      (line) =>
        new Paragraph({
          children: [new TextRun({ text: line.replace(/^[\s\-\d.]+/, "").trim() || line, size: 18, font: "Calibri" })],
          bullet: line.match(/^[\s]*[-*\d]/) ? { level: 0 } : undefined,
        })
    ),
  });
}

function labelValueRow(label, value, valueOptions = {}) {
  return new TableRow({
    children: [
      cell(label, 25, { bold: true, shading: { type: ShadingType.SOLID, color: "E8EAF6" } }),
      typeof value === "string" ? cell(value, 75, valueOptions) : multiLineCell(value, 75),
    ],
  });
}

function buildSummaryTable(vulns) {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 };
  vulns.forEach((v) => {
    const sev = v.severity in counts ? v.severity : "Medium";
    counts[sev]++;
  });

  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: [
      new TableRow({ children: [headerCell("Severity", 30), headerCell("Count", 20), headerCell("Percentage", 25), headerCell("Status", 25)] }),
      ...Object.entries(counts).map(
        ([sev, count]) =>
          new TableRow({
            children: [
              cell(sev, 30, { bold: true, color: SEVERITY_COLORS[sev] }),
              cell(String(count), 20),
              cell(vulns.length ? `${((count / vulns.length) * 100).toFixed(1)}%` : "0%", 25),
              cell(count > 0 ? "Identified" : "-", 25),
            ],
          })
      ),
      new TableRow({
        children: [
          cell("Total", 30, { bold: true, shading: { type: ShadingType.SOLID, color: "E8EAF6" } }),
          cell(String(vulns.length), 20, { bold: true }),
          cell("100%", 25, { bold: true }),
          cell("", 25),
        ],
      }),
    ],
  });
}

function buildVulnDetailTable(vuln, index) {
  const sevColor = SEVERITY_COLORS[vuln.severity] || "000000";
  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: [
      new TableRow({
        children: [
          new TableCell({
            columnSpan: 2,
            width: { size: 100, type: WidthType.PERCENTAGE },
            shading: { type: ShadingType.SOLID, color: "1a237e" },
            borders: BORDER,
            children: [
              new Paragraph({
                alignment: AlignmentType.LEFT,
                children: [
                  new TextRun({
                    text: `${index + 1}. ${vuln.title}`,
                    bold: true,
                    color: "FFFFFF",
                    size: 22,
                    font: "Calibri",
                  }),
                ],
              }),
            ],
          }),
        ],
      }),
      labelValueRow("Vulnerability ID", vuln.id),
      labelValueRow("Severity", vuln.severity, { bold: true, color: sevColor }),
      labelValueRow("Status", vuln.status === "open" ? "Open" : "Closed"),
      labelValueRow("Affected URL / Endpoint", vuln.affectedUrl),
      labelValueRow("Analysis", vuln.analysis),
      labelValueRow("Impact", vuln.impact),
      labelValueRow("Remediation", vuln.remediation),
      labelValueRow("Proof of Concept (POC)", vuln.poc),
      ...(vuln.comments.length > 0
        ? [
            labelValueRow(
              "Response / Comments",
              vuln.comments.map((c) => `[${c.author} - ${new Date(c.date).toLocaleDateString()}]: ${c.body}`).join("\n")
            ),
          ]
        : []),
      labelValueRow("Reported By", vuln.author),
      labelValueRow("Date Reported", new Date(vuln.createdAt).toLocaleDateString()),
      labelValueRow("Last Updated", new Date(vuln.updatedAt).toLocaleDateString()),
    ],
  });
}

function buildFindingsOverviewTable(vulns) {
  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: [
      new TableRow({
        children: [
          headerCell("#", 5),
          headerCell("Vulnerability", 30),
          headerCell("Severity", 15),
          headerCell("Status", 10),
          headerCell("Affected URL", 25),
          headerCell("Reported", 15),
        ],
      }),
      ...vulns.map(
        (v, i) =>
          new TableRow({
            children: [
              cell(String(i + 1), 5),
              cell(v.title, 30),
              cell(v.severity, 15, { bold: true, color: SEVERITY_COLORS[v.severity] }),
              cell(v.status === "open" ? "Open" : "Closed", 10),
              cell(v.affectedUrl, 25),
              cell(new Date(v.createdAt).toLocaleDateString(), 15),
            ],
          })
      ),
    ],
  });
}

async function generateReport(vulns, meta, outputPath) {
  const sortOrder = { Critical: 0, High: 1, Medium: 2, Low: 3, Informational: 4 };
  vulns.sort((a, b) => (sortOrder[a.severity] ?? 5) - (sortOrder[b.severity] ?? 5));

  const today = new Date().toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });

  const sections = [
    {
      properties: {
        page: {
          margin: { top: 1000, right: 1000, bottom: 1000, left: 1000 },
          size: { orientation: "portrait" },
        },
      },
      headers: {
        default: new Header({
          children: [
            new Paragraph({
              alignment: AlignmentType.RIGHT,
              children: [new TextRun({ text: "CONFIDENTIAL - Vulnerability Assessment & Penetration Testing Report", italics: true, size: 16, color: "999999", font: "Calibri" })],
            }),
          ],
        }),
      },
      footers: {
        default: new Footer({
          children: [
            new Paragraph({
              alignment: AlignmentType.CENTER,
              children: [
                new TextRun({ text: "Page ", size: 16, font: "Calibri" }),
                new TextRun({ children: [PageNumber.CURRENT], size: 16, font: "Calibri" }),
                new TextRun({ text: " of ", size: 16, font: "Calibri" }),
                new TextRun({ children: [PageNumber.TOTAL_PAGES], size: 16, font: "Calibri" }),
              ],
            }),
          ],
        }),
      },
      children: [
        new Paragraph({ spacing: { before: 3000 } }),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          children: [new TextRun({ text: "VULNERABILITY ASSESSMENT", size: 52, bold: true, color: "1a237e", font: "Calibri" })],
        }),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          children: [new TextRun({ text: "&", size: 36, color: "666666", font: "Calibri" })],
        }),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          children: [new TextRun({ text: "PENETRATION TESTING REPORT", size: 52, bold: true, color: "1a237e", font: "Calibri" })],
        }),
        new Paragraph({ spacing: { before: 600 } }),
        new Table({
          width: { size: 60, type: WidthType.PERCENTAGE },
          rows: [
            new TableRow({ children: [cell("Project", 40, { bold: true }), cell(meta.repo, 60)] }),
            new TableRow({ children: [cell("Repository", 40, { bold: true }), cell(`${meta.owner}/${meta.repo}`, 60)] }),
            new TableRow({ children: [cell("Report Date", 40, { bold: true }), cell(today, 60)] }),
            new TableRow({ children: [cell("Total Findings", 40, { bold: true }), cell(String(vulns.length), 60)] }),
            new TableRow({ children: [cell("Report Version", 40, { bold: true }), cell("1.0", 60)] }),
            new TableRow({ children: [cell("Classification", 40, { bold: true }), cell("CONFIDENTIAL", 60, { bold: true, color: "FF0000" })] }),
          ],
        }),

        // Executive Summary
        new Paragraph({ children: [new PageBreak()] }),
        new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun({ text: "1. Executive Summary", bold: true, size: 28, color: "1a237e", font: "Calibri" })] }),
        new Paragraph({
          spacing: { after: 200 },
          children: [
            new TextRun({
              text: `This report presents the findings of a Vulnerability Assessment and Penetration Testing (VAPT) engagement conducted on the ${meta.repo} application. A total of ${vulns.length} vulnerabilities were identified and documented through GitHub issue tracking. The findings are categorized by severity and include detailed analysis, impact assessment, remediation recommendations, and proof of concept where applicable.`,
              size: 20,
              font: "Calibri",
            }),
          ],
        }),

        // Severity Summary
        new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 400 }, children: [new TextRun({ text: "2. Severity Summary", bold: true, size: 28, color: "1a237e", font: "Calibri" })] }),
        buildSummaryTable(vulns),

        // Findings Overview
        new Paragraph({ children: [new PageBreak()] }),
        new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun({ text: "3. Findings Overview", bold: true, size: 28, color: "1a237e", font: "Calibri" })] }),
        buildFindingsOverviewTable(vulns),

        // Detailed Findings
        new Paragraph({ children: [new PageBreak()] }),
        new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun({ text: "4. Detailed Findings", bold: true, size: 28, color: "1a237e", font: "Calibri" })] }),
        ...vulns.flatMap((v, i) => [
          new Paragraph({ spacing: { before: 400 } }),
          buildVulnDetailTable(v, i),
        ]),

        // Disclaimer
        new Paragraph({ children: [new PageBreak()] }),
        new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun({ text: "5. Disclaimer", bold: true, size: 28, color: "1a237e", font: "Calibri" })] }),
        new Paragraph({
          children: [
            new TextRun({
              text: "This report is generated from GitHub issue data and reflects the vulnerabilities documented at the time of generation. The assessment is based on the information available in the repository issues and may not represent a complete security assessment. This report is confidential and intended solely for the authorized recipients.",
              size: 20,
              font: "Calibri",
            }),
          ],
        }),
      ],
    },
  ];

  const doc = new Document({
    creator: "GitHub VAPT Report Generator",
    title: `VAPT Report - ${meta.repo}`,
    description: "Vulnerability Assessment and Penetration Testing Report",
    sections,
  });

  const buffer = await Packer.toBuffer(doc);
  fs.writeFileSync(outputPath, buffer);
  return outputPath;
}

module.exports = { generateReport };
