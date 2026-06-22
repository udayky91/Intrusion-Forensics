/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import express from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { GoogleGenAI } from '@google/genai';
import dotenv from 'dotenv';
import { CloudTrailEvent, MisconfigFinding, ThreatIntelRecord, EvidenceArtifact } from './src/types';
import { MOCK_SCENARIOS, CIS_BENCHMARKS, INTEL_DATABASE, MOCK_EVIDENCE } from './src/mockData';

dotenv.config();

const app = express();
const PORT = 3000;

app.use(express.json());

// In-memory working database for active forensics session so changes persist
let activeScenarios = JSON.parse(JSON.stringify(MOCK_SCENARIOS));
let activeEvidence = JSON.parse(JSON.stringify(MOCK_EVIDENCE));
let activePlaybooksLog: { timestamp: string; action: string; status: string; appliedTo: string }[] = [];

// Lazy Gemini API client initializer following the strictly mandated guidelines
let aiClient: GoogleGenAI | null = null;
function getGeminiClient(): GoogleGenAI {
  if (!aiClient) {
    const key = process.env.GEMINI_API_KEY;
    if (!key || key === "MY_GEMINI_API_KEY" || key === "") {
      throw new Error("GEMINI_API_KEY is not configured in your Environment Secrets or .env file.");
    }
    aiClient = new GoogleGenAI({
      apiKey: key,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        }
      }
    });
  }
  return aiClient;
}

// REST Endpoints
// Healthcheck 
app.get('/api/health', (req, res) => {
  res.json({ status: "healthy", timestamp: new Date().toISOString() });
});

// Scenario fetch list
app.get('/api/scenarios', (req, res) => {
  res.json(activeScenarios);
});

// Scenario details
app.get('/api/scenarios/:id', (req, res) => {
  const scenario = activeScenarios.find((s: any) => s.id === req.params.id);
  if (!scenario) {
    res.status(404).json({ error: "Scenario not found" });
    return;
  }
  res.json(scenario);
});

// Threat intelligence IP checks
app.get('/api/intel/:ip', (req, res) => {
  const ip = req.params.ip;
  const intel = INTEL_DATABASE[ip];
  if (!intel) {
    res.json({
      ip,
      reputationScore: 12,
      abuseScore: 0,
      country: "Unknown",
      isp: "Unknown Net Provider",
      knownIoc: false,
      maliciousCategory: "Not explicitly documented in local threat intel databases."
    });
    return;
  }
  res.json(intel);
});

// CIS AWS misconfiguration findings list
app.get('/api/misconfig', (req, res) => {
  res.json(CIS_BENCHMARKS);
});

// SOAR playbook trigger simulation
app.post('/api/soar/playbook', (req, res) => {
  const { action, target, scenarioId } = req.body;
  if (!action || !target) {
    res.status(400).json({ error: "Missing action or target parameter." });
    return;
  }

  const logEntry = {
    timestamp: new Date().toISOString(),
    action,
    status: "SUCCESSFULLY_EXECUTED",
    appliedTo: target
  };
  activePlaybooksLog.unshift(logEntry);

  // If specific action was 'revoke_key', we update the risk level or mark event note
  if (scenarioId) {
    const sIdx = activeScenarios.findIndex((s: any) => s.id === scenarioId);
    if (sIdx !== -1) {
      activeScenarios[sIdx].notes = (activeScenarios[sIdx].notes || "") + `\n[SOAR Action - ${new Date().toLocaleTimeString()}]: Executed '${action}' on target '${target}'.`;
    }
  }

  res.json({
    message: `Security Orchestration Playbook completed successfully.`,
    playbookDetails: logEntry,
    activeLogs: activePlaybooksLog
  });
});

app.get('/api/soar/logs', (req, res) => {
  res.json(activePlaybooksLog);
});

// Evidence locker APIs
app.get('/api/evidence', (req, res) => {
  res.json(activeEvidence);
});

app.post('/api/evidence', (req, res) => {
  const { fileName, fileSize, fileHash, actionContext, userName } = req.body;
  if (!fileName || !fileHash) {
    res.status(400).json({ error: "Required fields 'fileName' and 'fileHash' are missing." });
    return;
  }

  const newArtifact: EvidenceArtifact = {
    id: `art-${activeEvidence.length + 1}`,
    fileName,
    fileSize: fileSize || "1.2 MB",
    fileHash,
    chainOfCustody: [
      {
        recordedAt: new Date().toISOString(),
        recordedBy: userName || "SOC Analyst",
        action: "Evidence Import & Hashing",
        notes: actionContext || "Manual raw JSON CloudTrail log fragment submission."
      }
    ],
    comments: []
  };

  activeEvidence.unshift(newArtifact);
  res.status(201).json(newArtifact);
});

app.post('/api/evidence/:id/comment', (req, res) => {
  const artId = req.params.id;
  const { text, author } = req.body;
  if (!text) {
    res.status(400).json({ error: "Comment text is required." });
    return;
  }

  const art = activeEvidence.find((a: any) => a.id === artId);
  if (!art) {
    res.status(404).json({ error: "Evidence artifact not found." });
    return;
  }

  const comment = {
    id: `com-${Date.now()}`,
    author: author || "SOC Investigator",
    timestamp: new Date().toISOString(),
    text
  };

  art.comments.push(comment);
  res.status(201).json(comment);
});

app.post('/api/evidence/:id/custody', (req, res) => {
  const artId = req.params.id;
  const { recordedBy, action, notes } = req.body;
  if (!action || !recordedBy) {
    res.status(400).json({ error: "Custody 'action' and 'recordedBy' are required." });
    return;
  }

  const art = activeEvidence.find((a: any) => a.id === artId);
  if (!art) {
    res.status(404).json({ error: "Evidence artifact not found." });
    return;
  }

  const custodyRecord = {
    recordedAt: new Date().toISOString(),
    recordedBy,
    action,
    notes: notes || ""
  };

  art.chainOfCustody.push(custodyRecord);
  res.status(201).json(custodyRecord);
});

// Custom Log Ingestion & Parsing Engine Endpoint
app.post('/api/ingest-logs', (req, res) => {
  const { rawText, fileName } = req.body;
  if (!rawText) {
    res.status(400).json({ error: "Raw CloudTrail log text is required." });
    return;
  }

  try {
    let parsed: any;
    try {
      parsed = JSON.parse(rawText);
    } catch {
      res.status(400).json({ error: "Failed to parse input as valid JSON format. Verify spacing/brackets." });
      return;
    }

    // Wrap to get Records
    const records = parsed.Records || parsed.records || (Array.isArray(parsed) ? parsed : [parsed]);
    const normalizedEvents: CloudTrailEvent[] = records.map((rec: any, idx: number) => {
      // Analyze parameters to label threat category
      const evName = rec.eventName || "UnknownAPICall";
      const evSrc = rec.eventSource || "unknown.amazonaws.com";
      const userIdent = rec.userIdentity || { type: "Unknown", principalId: "Unverified" };
      
      let threatCategory: any = "Normal";
      let mitreID = "";
      let mitreTechnique = "";
      let anomalyScore = 0.05;
      let riskLevel: any = "Normal";

      // Simple heuristic threat detection algorithms (Module 3/4)
      if (evName === "AttachUserPolicy" || evName === "PutUserPolicy" || evName === "AttachRolePolicy") {
         threatCategory = "Privilege Escalation";
         mitreID = "T1098";
         mitreTechnique = "IAM Policy Injection";
         anomalyScore = 0.88;
         riskLevel = "High";
      } else if (evSrc.startsWith("sts") && evName === "AssumeRole") {
         threatCategory = "Initial Access";
         mitreID = "T1552";
         mitreTechnique = "Session Assumed Usage";
         anomalyScore = 0.40;
         riskLevel = "Low";
      } else if (evName.startsWith("StopLogging") || evName.startsWith("DeleteTrail") || evName.startsWith("UpdateTrail")) {
         threatCategory = "Defense Evasion";
         mitreID = "T1562.008";
         mitreTechnique = "Impair Defenses: Disable Cloud Logs";
         anomalyScore = 0.99;
         riskLevel = "Critical";
      } else if (evSrc.startsWith("s3") && (evName === "GetObject" || evName === "GetObjectVersion")) {
         anomalyScore = 0.25;
         riskLevel = "Low";
         // High threat if reading database backup files
         const s3Key = rec.requestParameters?.key || "";
         if (s3Key.includes("backup") || s3Key.includes("pii") || s3Key.includes("dump") || s3Key.includes("sql")) {
           threatCategory = "Exfiltration";
           mitreID = "T1567";
           mitreTechnique = "Exfiltration Over Web Service / Backup Harvest";
           anomalyScore = 0.94;
           riskLevel = "Critical";
         }
      } else if (evName === "GetSecretValue" || evName === "GetDecryptedSecret") {
         threatCategory = "Credential Access";
         mitreID = "T1528";
         mitreTechnique = "Credentials from Password Manager";
         anomalyScore = 0.75;
         riskLevel = "High";
      } else if (evName.startsWith("List") || evName.startsWith("Get") || evName.startsWith("Describe")) {
         threatCategory = "Discovery";
         mitreID = "T1580";
         mitreTechnique = "Cloud Infrastructure Discovery";
         anomalyScore = 0.15;
         riskLevel = "Normal";
         if (rec.errorCode) {
           anomalyScore = 0.70; // AccessDenied on read is suspicious login / discovery loop
           riskLevel = "Medium";
         }
      }

      return {
        eventID: rec.eventID || `ingest-ev-${idx}-${Date.now()}`,
        eventName: evName,
        eventSource: evSrc,
        eventTime: rec.eventTime || new Date().toISOString(),
        awsRegion: rec.awsRegion || "us-east-1",
        sourceIPAddress: rec.sourceIPAddress || "127.0.0.1",
        userAgent: rec.userAgent || "AWS-Internal/1.0",
        userIdentity: {
          type: userIdent.type || "IAMUser",
          principalId: userIdent.principalId || "AssignedUser",
          arn: userIdent.arn || `arn:aws:iam::967205250947:user/${userIdent.userName || 'unknown'}`,
          accountId: userIdent.accountId || "967205250947",
          accessKeyId: userIdent.accessKeyId || "AKIAUNKNOWN",
          userName: userIdent.userName || "Operator"
        },
        requestParameters: rec.requestParameters || {},
        responseElements: rec.responseElements || {},
        errorCode: rec.errorCode,
        errorMessage: rec.errorMessage,
        threatCategory,
        mitreID,
        mitreTechnique,
        anomalyScore,
        relevanceConfidence: 0.90,
        explainabilityFeatures: { "Anomaly Detection Heuristic Match": anomalyScore, "Structural API Integrity Check": 0.8 },
        riskLevel,
        flagged: riskLevel === "High" || riskLevel === "Critical"
      };
    });

    const newScenarioId = `sc-${Date.now()}`;
    const newScenario = {
      id: newScenarioId,
      name: fileName || `Acquired Log - ${new Date().toLocaleDateString()}`,
      description: `Analysis segment loaded into browser forensics pipeline containing ${normalizedEvents.length} distinct API events.`,
      summary: "Imported evidence session analyzed through AegisForensics heuristics engine.",
      targetAccount: normalizedEvents[0]?.userIdentity.accountId || "967205250947",
      severity: normalizedEvents.some((e) => e.riskLevel === "Critical") ? "Critical" : normalizedEvents.some((e) => e.riskLevel === "High") ? "High" : "Medium",
      insights: {
        threatActor: "Dynamic Ingested Investigation Session",
        attackVector: "Ingested JSON file parsing extraction stream.",
        impact: "Requires prompt timeline graph investigation.",
        mitigation: "Generate automated report and implement remediation strategies."
      },
      timeline: normalizedEvents
    };

    activeScenarios.unshift(newScenario);

    // Also auto-add to active evidence artifacts
    const artifactId = `art-${activeEvidence.length + 1}`;
    activeEvidence.unshift({
      id: artifactId,
      fileName: fileName || "unnamed-ingest.json",
      fileSize: `${(rawText.length / 1024).toFixed(1)} KB`,
      fileHash: `${Math.random().toString(16).substring(2)}${Math.random().toString(16).substring(2)}`,
      chainOfCustody: [
        {
          recordedAt: new Date().toISOString(),
          recordedBy: "AegisForensics Log Engine",
          action: "Ingestion and Normalization Pipeline",
          notes: `Parsed ${normalizedEvents.length} log records successfully into investigative case ${newScenarioId}.`
        }
      ],
      comments: []
    });

    res.json({
      message: "Successfully parsed, analyzed, and injected log timeline.",
      scenarioId: newScenarioId,
      eventCount: normalizedEvents.length,
      extractedElements: normalizedEvents
    });
  } catch (err: any) {
    res.status(500).json({ error: `Internal normalization pipeline error: ${err.message}` });
  }
});

// Gemini Assistant endpoint - Real AI capabilities on the server side
app.post('/api/gemini/assistant', async (req, res) => {
  const { question, timelineEvents, context } = req.body;
  if (!question) {
    res.status(400).json({ error: "A question is required." });
    return;
  }

  try {
    const ai = getGeminiClient();
    
    // Construct system instructions and comprehensive prompt
    const timelineSnippet = timelineEvents ? JSON.stringify(timelineEvents.slice(0, 15)) : "No active events context.";
    const currentLocTime = new Date().toISOString();

    const systemInstruction = 
      "You are a Senior Cloud security specialist, SOC Threat Hunter, and Incident Response forensic expert. " +
      "Your role is to guide security engineers analyzing suspicious AWS CloudTrail log chains. " +
      "Be crisp, technically accurate, objective, and authoritative. Avoid marketing talk. Cite specific eventIDs or regions. " +
      "Provide a realistic remediation path and explain the attacker's technical steps. " +
      "Highlight which MITRE ATT&CK elements are involved. " +
      "Always generate a mock Splunk SPL command, Athena SQL check, or Sentinel KQL query to look for this exact threat vector.";

    const userPrompt = 
      `The local current timestamp is: ${currentLocTime}. \n` +
      `Timeline context under investigation (truncated): \n` +
      `${timelineSnippet} \n\n` +
      `Additional background details: ${context || "None"}. \n\n` +
      `User query/Incident inquiry: ${question}`;

    const response = await ai.models.generateContent({
      model: "gemini-3.5-flash",
      contents: userPrompt,
      config: {
        systemInstruction
      }
    });

    res.json({
      answer: response.text || "AI Assistant did not return a response content. Verify logs.",
      timestamp: new Date().toISOString()
    });
  } catch (err: any) {
    console.error("Gemini Assistant Failure:", err);
    res.status(500).json({ 
      error: `Gemini AI Engine could not be reached. ${err.message}`,
      fallbackAnswer: "AI Assistant failed to parse using the offline module. Refine connection permissions."
    });
  }
});

// Generative AI Attack Storytelling endpoint - Generates rich markdown chronological narratives
app.post('/api/gemini/story', async (req, res) => {
  const { scenarioName, timelineEvents } = req.body;
  if (!timelineEvents || !Array.isArray(timelineEvents)) {
    res.status(400).json({ error: "A valid list of timelineEvents is required for generating an attack narrative." });
    return;
  }

  try {
    const ai = getGeminiClient();
    const systemInstruction = 
      "You are an Elite Forensic Threat Intelligence Analyst. " +
      "Translate highly technical AWS API CloudTrail events (such as IAM, S3, RDS, Lambda triggers) into a compelling, clear human-readable narrative story. " +
      "Avoid general summaries. Detail how the attacker pivoted step-by-step from event 1 to event N, highlighting " +
      "vulnerable practices, API misuse, persistence tactics, and the ultimate impact. " +
      "Use clean markdown formatting including custom title headers, chronology lists, key Indicators of Compromise, and precise remediation guides.";

    const userPrompt = 
      `Generate the "Cloud Attack Narrative Story" for the incident scenario: "${scenarioName || 'Untangled Cloud Access Breach'}". \n` +
      `Here is the verified AWS CloudTrail event trail under study: \n` +
      `${JSON.stringify(timelineEvents)}`;

    const response = await ai.models.generateContent({
      model: "gemini-3.5-flash",
      contents: userPrompt,
      config: { systemInstruction }
    });

    res.json({
      story: response.text || "Failure generating narrative. Review format."
    });
  } catch (err: any) {
    console.error("Gemini Storyteller Failure:", err);
    res.status(500).json({ 
      error: `Gemini AI Storytelling could not be triggered. ${err.message}`,
      fallbackStory: "### Attack Chronology Narrative (Offline Mode - Local Analytics Heuristics)\n\n" +
                     "* **Phase 1: Initial Compromise** - Attacker targets Access Key elements, launching API enumeration checks.\n" +
                     "* **Phase 2: Administrative Defacement** - Attempted Direct Admin grants identified via Policy modifications.\n" +
                     "* **Phase 3: Environmental Blinding** - `StopLogging` action is triggered to prevent monitoring coverage.\n" +
                     "* **Phase 4: High-Volume Egress** - Storage elements target and download triggers. Core sensitive SQL outputs transferred."
    });
  }
});

// Live report exporter
app.post('/api/export-report', (req, res) => {
  const { scenarioId, reportType } = req.body;
  const scenario = activeScenarios.find((s: any) => s.id === scenarioId);
  if (!scenario) {
    res.status(404).json({ error: "Incident Scenario not found." });
    return;
  }

  // Create an elegant, clean HTML / Document format that can be viewed and copied
  const dateStr = new Date().toLocaleString();
  const reportBody = `
========================================================================
             AEGISFORENSICS CLOUD INTRUSION INVESTIGATION REPORT
========================================================================
Generated: ${dateStr}
Case Reference: CASE-ID-${scenarioId.toUpperCase()}
Incidence Segment: ${scenario.name}
Mitre Tactics Mapped: INITIAL ENTRY, PERSISTENCE, PRIVILEGE ESCALATION, DATA EXFIL
Status: FORENSIC ACQUISITION LOCKED
------------------------------------------------------------------------

1. EXECUTIVE SUMMARY
${scenario.summary}

2. METHODOLOGICAL EVIDENCE ACQUISITION
Forensic Analyst acquired logs corresponding to AWS Subnet Account Id: ${scenario.targetAccount}.
Security severity is classified as: [ ${scenario.severity.toUpperCase()} ].

3. TEMPORAL CHRONOLOGY DEVIATIONS
${scenario.timeline.map((e: CloudTrailEvent, i: number) => `
 [Event #${i + 1}]  -  Time: ${e.eventTime}
   * API: ${e.eventName}  |  Source: ${e.eventSource}
   * Requesting Entity: ${e.userIdentity?.arn}
   * Source Machine IP: ${e.sourceIPAddress}  |  User Agent: ${e.userAgent}
   * Hazard Level Score: ${e.anomalyScore * 100}%  |  Threat Tactic ID: ${e.mitreID} (${e.threatCategory})
   * Timeline Auditor Notes: ${e.notes || 'None recorded'}
`).join('\n')}

4. RECONSTRUCTED ATTACK TREE AND ATTACK COHERENCY
The attacker pivoted inside the account starting from STS session validation routines, targeting secondary credential modification permissions, then disabled logging mechanisms, and finally offloaded customer table database segments.

5. REGULATORY AUDITING AND CIS STANDARDS GAP ANALYSIS
This attack was assisted by critical architectural defaults conforming to CIS AWS Foundations benchmarks:
 - CIS 1.2: General lack of strict multi-factor enforcement for testing entities.
 - CIS 1.16: Excessive policy allocations allowing direct Administrator session self-binding.

6. REMEDIATION PLAYBOOK SUMMARY
AegisForensics SOAR has formulated the following playbooks:
 [Playbook 1]: Direct revocation of key credentials ${scenario.timeline[0]?.userIdentity?.accessKeyId || "N/A"}
 [Playbook 2]: Temporary isolation of IP blocks ${scenario.timeline[0]?.sourceIPAddress} across target WAF boundary filters.

========================================================================
                [ SECURE DIGITALLY ENCRPYTED FORENSIC ARTIFACT ]
========================================================================
`;

  res.json({
    scenarioName: scenario.name,
    reportType: reportType || "Technical Forensic Analysis",
    exportedAt: dateStr,
    fileName: `${scenario.name.toLowerCase().replace(/\s+/g, '_')}_forensic_report.txt`,
    content: reportBody
  });
});

// Fallback/Vite serving inside startServer
async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa"
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`[AegisForensics Backend Server] booting online on http://localhost:${PORT}`);
  });
}

startServer();
