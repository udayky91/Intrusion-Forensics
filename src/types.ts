/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export interface UserIdentity {
  type: string;
  principalId: string;
  arn: string;
  accountId: string;
  accessKeyId?: string;
  userName?: string;
  sessionContext?: {
    mfaAuthenticated: string;
    creationDate: string;
  };
}

export interface CloudTrailEvent {
  eventID: string;
  eventName: string;
  eventSource: string;
  eventTime: string;
  awsRegion: string;
  sourceIPAddress: string;
  userAgent: string;
  userIdentity: UserIdentity;
  requestParameters?: Record<string, any>;
  responseElements?: Record<string, any>;
  errorCode?: string;
  errorMessage?: string;
  
  // Normalized / Forensics fields
  threatCategory?: 'Initial Access' | 'Persistence' | 'Privilege Escalation' | 'Defense Evasion' | 'Credential Access' | 'Discovery' | 'Exfiltration' | 'Impact' | 'Normal';
  mitreTechnique?: string;
  mitreID?: string;
  anomalyScore: number; // 0.0 to 1.0
  relevanceConfidence: number; // 0.0 to 1.0
  explainabilityFeatures?: { [key: string]: number }; // SHAP/feature importance
  riskLevel: 'Normal' | 'Low' | 'Medium' | 'High' | 'Critical';
  flagged: boolean;
  notes?: string;
}

export interface Scenario {
  id: string;
  name: string;
  description: string;
  summary: string;
  targetAccount: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  timeline: CloudTrailEvent[];
  insights: {
    threatActor: string;
    attackVector: string;
    impact: string;
    mitigation: string;
  };
}

export interface ResearchPaperSection {
  title: string;
  subtitle: string;
  paragraphs: string[];
}

export interface MisconfigFinding {
  id: string;
  controlId: string;
  section: string;
  title: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  status: 'FAIL' | 'PASS';
  impact: string;
  remediation: string;
}

export interface EvidenceArtifact {
  id: string;
  fileName: string;
  fileSize: string;
  fileHash: string;
  chainOfCustody: {
    recordedAt: string;
    recordedBy: string;
    action: string;
    notes: string;
  }[];
  comments: {
    id: string;
    author: string;
    timestamp: string;
    text: string;
  }[];
}

export interface ThreatIntelRecord {
  ip: string;
  reputationScore: number; // 0 to 100
  abuseScore: number; // percentage
  country: string;
  isp: string;
  knownIoc: boolean;
  maliciousCategory: string;
}
