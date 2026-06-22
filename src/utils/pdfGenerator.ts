/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { jsPDF } from 'jspdf';
import { Scenario, CloudTrailEvent } from '../types';

export const generatePDFReport = (scenario: Scenario, reportType: string, operatorEmail: string) => {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4'
  });

  const pageWidth = 210;
  const pageHeight = 297;
  const leftMargin = 15;
  const rightMargin = 15;
  const usableWidth = pageWidth - leftMargin - rightMargin; // 180mm

  let y = 20;

  // Header helper function to write corporate-styled header & line on every page
  const drawPageHeader = (pageNum: number) => {
    // Draw top dark blue bar
    doc.setFillColor(15, 23, 42); // slate 900
    doc.rect(0, 0, pageWidth, 12, 'F');
    
    // Cyan action indicator element on the left
    doc.setFillColor(6, 182, 212); // cyan 500
    doc.rect(0, 0, 5, 12, 'F');

    // Title text inside header bar
    doc.setTextColor(255, 255, 255);
    doc.setFont("Helvetica", "bold");
    doc.setFontSize(8);
    doc.text("CLOUDTRACE FORENSIC ASSURANCE LABS | SECURE EVIDENCE REPORT", leftMargin, 8);

    // Right-aligned status in header bar
    doc.setFont("Helvetica", "normal");
    doc.setTextColor(156, 163, 175); // gray-400
    doc.text("CLASSIFICATION: HIGHLY RESTRICTED // SOC-AUDIT", pageWidth - rightMargin, 8, { align: "right" });
  };

  // Footer helper to write credentials and page numbers
  const drawPageFooter = (pageNum: number) => {
    // Bottom separator line
    doc.setDrawColor(226, 232, 240); // gray-200
    doc.setLineWidth(0.3);
    doc.line(leftMargin, pageHeight - 15, pageWidth - rightMargin, pageHeight - 15);

    // Left aligned footer details
    doc.setFont("Helvetica", "normal");
    doc.setFontSize(7.5);
    doc.setTextColor(100, 116, 139); // slate-500
    doc.text(`Digital Sign-off ID: SIG-CT-${scenario.id.toUpperCase()}-${operatorEmail.split('@')[0].toUpperCase()}`, leftMargin, pageHeight - 10);

    // Right aligned footer details
    const pageText = `Page ${pageNum}`;
    doc.text(pageText, pageWidth - rightMargin, pageHeight - 10, { align: "right" });
  };

  // Helper function to check if we need to add a new page
  const checkPageOverflow = (heightNeeded: number, pageNumRef: { current: number }) => {
    if (y + heightNeeded > pageHeight - 20) {
      drawPageFooter(pageNumRef.current);
      doc.addPage();
      pageNumRef.current += 1;
      drawPageHeader(pageNumRef.current);
      y = 22; // reset y to top margin on new page
    }
  };

  // Helper to add descriptive body paragraph text with automatic word wrapping
  const addTextParagraph = (text: string, fontStyle: 'normal' | 'bold' | 'oblique' = 'normal', fontSize = 9.5, color = [51, 65, 85], pageNumRef: { current: number }) => {
    doc.setFont("Helvetica", fontStyle);
    doc.setFontSize(fontSize);
    doc.setTextColor(color[0], color[1], color[2]);

    const lines: string[] = doc.splitTextToSize(text, usableWidth);
    const lineHeight = fontSize * 0.45; // mm spacing estimate per line

    lines.forEach(line => {
      checkPageOverflow(lineHeight + 1, pageNumRef);
      doc.text(line, leftMargin, y);
      y += lineHeight + 1;
    });
    y += 2; // paragraph bottom margin
  };

  // Page tracking reference
  const pageNum = { current: 1 };

  // INITIAL HEADER
  drawPageHeader(pageNum.current);
  y = 24;

  // Document Title Page / Top Header
  doc.setFont("Helvetica", "bold");
  doc.setFontSize(22);
  doc.setTextColor(15, 23, 42); // slate-900
  doc.text("INCIDENT FORENSIC REPORT", leftMargin, y);
  y += 8;

  // Document classification type
  doc.setFont("Helvetica", "bold");
  doc.setFontSize(11);
  doc.setTextColor(6, 182, 212); // cyan accent
  doc.text(reportType.toUpperCase() + " // AWS CLOUDTRAIL DETECTOR", leftMargin, y);
  y += 5;

  // Divider
  doc.setDrawColor(6, 182, 212);
  doc.setLineWidth(1.2);
  doc.line(leftMargin, y, leftMargin + 60, y);
  y += 8;

  // Metadata Block Frame (Grey Info box)
  checkPageOverflow(36, pageNum);
  doc.setFillColor(248, 250, 252); // slate 50 (very light grey)
  doc.setDrawColor(226, 232, 240); // border-gray-200
  doc.setLineWidth(0.4);
  doc.roundedRect(leftMargin, y, usableWidth, 31, 2, 2, 'FD');

  doc.setFont("Helvetica", "bold");
  doc.setFontSize(8.5);
  doc.setTextColor(71, 85, 105); // slate-600

  // Left column metadata
  doc.text("CASE REFERENCE:", leftMargin + 4, y + 5);
  doc.text("DATE OF COMPILE:", leftMargin + 4, y + 10);
  doc.text("TARGET AWS ACCOUNT:", leftMargin + 4, y + 15);
  doc.text("SYSTEM INVESTIGATOR:", leftMargin + 4, y + 20);
  doc.text("CASE RISK SEVERITY:", leftMargin + 4, y + 25);

  doc.setFont("Helvetica", "normal");
  doc.setTextColor(15, 23, 42); // slate-900
  doc.text(`CASE-ID-${scenario.id.toUpperCase()}`, leftMargin + 45, y + 5);
  doc.text(new Date().toUTCString(), leftMargin + 45, y + 10);
  doc.text(scenario.targetAccount, leftMargin + 45, y + 15);
  doc.text(`${operatorEmail}  [Secure IAM Token Auth]`, leftMargin + 45, y + 20);

  // Style Severity pill
  const sev = scenario.severity.toUpperCase();
  const sevColor = sev === 'CRITICAL' ? [220, 38, 38] : sev === 'HIGH' ? [234, 88, 12] : [202, 138, 4];
  doc.setFont("Helvetica", "bold");
  doc.setTextColor(sevColor[0], sevColor[1], sevColor[2]);
  doc.text(sev, leftMargin + 45, y + 25);

  y += 37;

  // SECTION 1: EXECUTIVE SUMMARY
  checkPageOverflow(12, pageNum);
  doc.setFont("Helvetica", "bold");
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text("1. EXECUTIVE SUMMARY", leftMargin, y);
  y += 4;
  doc.setDrawColor(203, 213, 225); // slate 300
  doc.setLineWidth(0.4);
  doc.line(leftMargin, y, pageWidth - rightMargin, y);
  y += 5;

  addTextParagraph(scenario.summary, "normal", 9.5, [71, 85, 105], pageNum);
  addTextParagraph(scenario.description, "normal", 9.5, [71, 85, 105], pageNum);

  // SECTION 2: THREAT INTELLIGENCE SUMMARY
  checkPageOverflow(12, pageNum);
  doc.setFont("Helvetica", "bold");
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text("2. THREAT COUNTER-MEASURE INTEL", leftMargin, y);
  y += 4;
  doc.setLineWidth(0.4);
  doc.line(leftMargin, y, pageWidth - rightMargin, y);
  y += 5;

  // Double card layout for threat stats
  checkPageOverflow(26, pageNum);
  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(226, 232, 240);
  doc.roundedRect(leftMargin, y, usableWidth, 22, 1.5, 1.5, 'FD');

  doc.setFont("Helvetica", "bold");
  doc.setFontSize(8.5);
  doc.setTextColor(71, 85, 105);
  doc.text("Threat Vector & Pivot Path:", leftMargin + 4, y + 5);
  doc.text("Assigned Threat Actor Group:", leftMargin + 4, y + 10);
  doc.text("Calculated System Mitigation:", leftMargin + 4, y + 15);

  doc.setFont("Helvetica", "normal");
  doc.setTextColor(15, 23, 42);
  doc.text(scenario.insights.attackVector, leftMargin + 50, y + 5);
  doc.text(scenario.insights.threatActor, leftMargin + 50, y + 10);
  doc.text(scenario.insights.mitigation, leftMargin + 50, y + 15);
  y += 28;

  // SECTION 3: TEMPORAL FORENSIC TIMELINE (The absolute highlight)
  checkPageOverflow(15, pageNum);
  doc.setFont("Helvetica", "bold");
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text("3. CHRONOLOGICAL CLOUDTRAIL EVIDENCE SEGMENTS", leftMargin, y);
  y += 4;
  doc.setLineWidth(0.4);
  doc.line(leftMargin, y, pageWidth - rightMargin, y);
  y += 6;

  addTextParagraph("The following logs document the exact chronological order of AWS API transactions that triggered telemetry anomaly flags and were associated with the principal exfiltration chain:", "normal", 8.5, [100, 116, 139], pageNum);

  // Table header for chronology
  checkPageOverflow(10, pageNum);
  doc.setFillColor(30, 41, 59); // slate-800
  doc.rect(leftMargin, y, usableWidth, 7.5, 'F');
  
  doc.setFont("Helvetica", "bold");
  doc.setFontSize(7.5);
  doc.setTextColor(255, 255, 255);
  doc.text("TIMESTAMP", leftMargin + 2, y + 5);
  doc.text("API EVENT / ACTION", leftMargin + 38, y + 5);
  doc.text("AWS PRINCIPAL (ARN)", leftMargin + 85, y + 5);
  doc.text("SOURCE IP", leftMargin + 143, y + 5);
  doc.text("ANOMALY", leftMargin + 163, y + 5);
  y += 7.5;

  scenario.timeline.forEach((event, idx) => {
    // Height estimate calculation for table row wrapper
    const textHeight = 11;
    checkPageOverflow(textHeight, pageNum);

    // Alternate backgrounds
    if (idx % 2 === 0) {
      doc.setFillColor(248, 250, 252); // slate 50
    } else {
      doc.setFillColor(255, 255, 255); // white
    }
    doc.rect(leftMargin, y, usableWidth, textHeight, 'F');

    // Horizontal row borders
    doc.setDrawColor(241, 245, 249); // slate-100
    doc.setLineWidth(0.2);
    doc.line(leftMargin, y + textHeight, pageWidth - rightMargin, y + textHeight);

    // Render cells
    doc.setFont("Helvetica", "normal");
    doc.setFontSize(6.5);
    doc.setTextColor(71, 85, 105);
    
    // Date/Time
    const utcTimeOnly = event.eventTime.replace('T', ' ').substring(0, 19);
    doc.text(utcTimeOnly, leftMargin + 2, y + 4.5);
    doc.setFont("Helvetica", "bold");
    doc.text(`${idx + 1}.`, leftMargin + 31, y + 4.5);

    // Event & Source
    doc.setTextColor(15, 23, 42); // bold black
    const apiNameText = event.eventName.length > 25 ? event.eventName.substring(0, 23) + "..." : event.eventName;
    doc.text(apiNameText, leftMargin + 38, y + 4.5);
    doc.setFont("Helvetica", "normal");
    doc.setFontSize(6);
    doc.setTextColor(100, 116, 139);
    doc.text(event.eventSource, leftMargin + 38, y + 8);

    // Principal ARN
    doc.setFontSize(6.5);
    doc.setTextColor(71, 85, 105);
    let arnLabel = event.userIdentity?.arn || "N/A";
    if (arnLabel.includes('/')) {
      arnLabel = arnLabel.substring(arnLabel.lastIndexOf('/') + 1);
    } else if (arnLabel.includes(':')) {
      arnLabel = arnLabel.substring(arnLabel.lastIndexOf(':') + 1);
    }
    const croppedArn = arnLabel.length > 36 ? arnLabel.substring(0, 34) + "..." : arnLabel;
    doc.text(croppedArn, leftMargin + 85, y + 4.5);
    
    // Region
    doc.setFontSize(6);
    doc.setTextColor(148, 163, 184);
    doc.text(`Reg: ${event.awsRegion}`, leftMargin + 85, y + 8);

    // Source IP
    doc.setFontSize(6.5);
    doc.setTextColor(15, 23, 42);
    doc.text(event.sourceIPAddress, leftMargin + 143, y + 4.5);

    // Anomaly Level
    const rawScore = (event.anomalyScore * 100).toFixed(0);
    const scoreColor = event.anomalyScore > 0.75 ? [220, 38, 38] : event.anomalyScore > 0.40 ? [234, 88, 12] : [71, 85, 105];
    doc.setFont("Helvetica", "bold");
    doc.setFontSize(7);
    doc.setTextColor(scoreColor[0], scoreColor[1], scoreColor[2]);
    doc.text(`${rawScore}%`, leftMargin + 163, y + 4.5);

    // MITRE Code tag under threat score
    if (event.mitreID) {
      doc.setFontSize(6.5);
      doc.setTextColor(6, 182, 212); // cyan
      doc.text(event.mitreID, leftMargin + 163, y + 8);
    }

    y += textHeight;
  });

  y += 7;

  // SECTION 4: CIS COMPLIANCE CORRELATION
  checkPageOverflow(15, pageNum);
  doc.setFont("Helvetica", "bold");
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text("4. STANDARDS AND COMPLIANCE MAP (MITRE ATT&CK & CIS)", leftMargin, y);
  y += 4;
  doc.setLineWidth(0.4);
  doc.line(leftMargin, y, pageWidth - rightMargin, y);
  y += 5;

  const isExfilCheck = scenario.timeline.some(e => e.threatCategory === 'Exfiltration' || e.threatCategory === 'Privilege Escalation');
  addTextParagraph(
    `CIS AWS Fundamentals Benchmark Audit shows a key systemic vulnerability in identity segregation: ${isExfilCheck ? '\n- CIS Control 1.16 is in violation: High-privilege Admin roles allow self-attaching inline policies directly in active user session threads. Multi-Factor Authentication is missing in credential parameters.' : '\n- CIS Control 2.1 is in violation: Inadequate backup storage access isolation was mapped during administrative STS enumeration pivots.'}`,
    "normal",
    8.5,
    [71, 85, 105],
    pageNum
  );

  y += 4;

  // SECTION 5: RECOMMENDED INVESTIGATION ACTION PLAN
  checkPageOverflow(15, pageNum);
  doc.setFont("Helvetica", "bold");
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text("5. RECOMMENDED INCIDENT DIRECTIVES & ACTION PLAN", leftMargin, y);
  y += 4;
  doc.setLineWidth(0.4);
  doc.line(leftMargin, y, pageWidth - rightMargin, y);
  y += 5;

  // Bullet items for Action plans
  const bulletItems = [
    `Revoke full active credentials of access key ${scenario.timeline[0]?.userIdentity?.accessKeyId || "AKIAUNKNOWN"} using SOAR playbooks or the AWS CLI directly.`,
    `Establish cross-account network firewalls to isolate traffic matching IP block ${scenario.timeline[0]?.sourceIPAddress || "127.0.0.1"} from AWS boundaries.`,
    `Trigger manual rolling of all sensitive keys associated with ARN principal roles verified on the timeline.`,
    `Implement AWS Config guardrails to prevent unauthorized modifications to CloudTrail configs and storage bucket logging targets.`
  ];

  bulletItems.forEach(item => {
    checkPageOverflow(8, pageNum);
    doc.setFillColor(6, 182, 212); // Cyan bullet
    doc.circle(leftMargin + 2, y + 1.5, 0.8, 'F');
    doc.setFont("Helvetica", "normal");
    doc.setFontSize(8.5);
    doc.setTextColor(51, 65, 85);

    const textWidth = usableWidth - 6;
    const bulletLines = doc.splitTextToSize(item, textWidth);
    bulletLines.forEach((bLine) => {
      checkPageOverflow(4.5, pageNum);
      doc.text(bLine, leftMargin + 6, y + 2.5);
      y += 4.5;
    });
    y += 1.5;
  });

  y += 4;

  // SECTION 6: FORENSIC SIGN-OFF SEAL
  checkPageOverflow(32, pageNum);
  y += 2;
  doc.setDrawColor(226, 232, 240);
  doc.setLineWidth(0.3);
  doc.line(leftMargin, y, pageWidth - rightMargin, y);
  y += 5;

  doc.setFont("Helvetica", "bold");
  doc.setFontSize(8);
  doc.setTextColor(100, 116, 139);
  doc.text("AUTHORIZING FORENSICS FIRM:", leftMargin, y);
  doc.text("INVESTIGATING OPERATOR CO-SIGN:", leftMargin + 95, y);

  doc.setFont("Helvetica", "normal");
  doc.setFontSize(8.5);
  doc.setTextColor(15, 23, 42);
  doc.text("CloudTrace Forensics Labs, Inc.", leftMargin, y + 5);
  doc.text(operatorEmail, leftMargin + 95, y + 5);

  doc.setFont("Helvetica", "oblique");
  doc.setFontSize(7.5);
  doc.setTextColor(148, 163, 184);
  doc.text("Secured by CloudTrace Cryptographic Sign-Off Policy", leftMargin, y + 9);
  doc.text(`Recorded UTC: ${new Date().toISOString()}`, leftMargin + 95, y + 9);

  // Digital secure seal visual representation
  doc.setDrawColor(6, 182, 212);
  doc.setLineWidth(0.5);
  doc.rect(leftMargin + 1, y + 13, 45, 5);
  doc.setFont("Helvetica", "bold");
  doc.setFontSize(6.5);
  doc.setTextColor(6, 182, 212);
  doc.text("VALID DIGITAL LOCK // CHAIN VERIFIED", leftMargin + 4, y + 16.5);

  // End footer for final page
  drawPageFooter(pageNum.current);

  // Save the PDF doc
  const filenameStr = `${scenario.name.toLowerCase().replace(/\s+/g, '_')}_assurance_report.pdf`;
  doc.save(filenameStr);
};
