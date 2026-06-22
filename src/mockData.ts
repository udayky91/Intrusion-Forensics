/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { Scenario, MisconfigFinding, ThreatIntelRecord, EvidenceArtifact, ResearchPaperSection } from './types';

export const INTEL_DATABASE: Record<string, ThreatIntelRecord> = {
  "193.106.191.22": {
    ip: "193.106.191.22",
    reputationScore: 94,
    abuseScore: 88,
    country: "Netherlands (Tor Exit)",
    isp: "M247 Europe",
    knownIoc: true,
    maliciousCategory: "Anonymizer / Active Bruteforce / Ransomware C2"
  },
  "185.220.101.44": {
    ip: "185.220.101.44",
    reputationScore: 82,
    abuseScore: 75,
    country: "Germany (Tor Node)",
    isp: "Zwiebelfreunde",
    knownIoc: true,
    maliciousCategory: "Tor Proxy / Crawler"
  },
  "45.227.254.10": {
    ip: "45.227.254.10",
    reputationScore: 99,
    abuseScore: 97,
    country: "Seychelles (Malicious Scanner)",
    isp: "VaporHost LLC",
    knownIoc: true,
    maliciousCategory: "Bruteforce / IAM Exploit Scanning"
  },
  "12.181.44.19": {
    ip: "12.181.44.19",
    reputationScore: 8,
    abuseScore: 2,
    country: "United States (Corporate IP)",
    isp: "AT&T Business",
    knownIoc: false,
    maliciousCategory: "None (Legitimate User Office IP)"
  }
};

export const CIS_BENCHMARKS: MisconfigFinding[] = [
  {
    id: "MC-01",
    controlId: "1.2",
    section: "Identity and Access Management",
    title: "Ensure multi-factor authentication (MFA) is enabled for all IAM users",
    severity: "Critical",
    status: "FAIL",
    impact: "Unprotected credentials are highly vulnerable to credential stuffing, phishing, and API session hijacking.",
    remediation: "Configure IAM MFA requirements for console login. Enforce MFA conditionally via SCPs."
  },
  {
    id: "MC-02",
    controlId: "1.16",
    section: "Identity and Access Management",
    title: "Ensure IAM policies do not allow broad administrative privileges (*:*)",
    severity: "High",
    status: "FAIL",
    impact: "Compromised credential keys with wildcards grant attackers total root-level control over the subscription.",
    remediation: "Transition admin assignments to AWS Identity Center with permission boundaries."
  },
  {
    id: "MC-03",
    controlId: "2.1",
    section: "Storage",
    title: "Ensure S3 Buckets are configured with Public Access Block enabled",
    severity: "Critical",
    status: "FAIL",
    impact: "Permissive S3 policies expose internal backups, PII, and sensitive source code to scanning bots.",
    remediation: "Apply Block Public Access (BPA) at both AWS Account-level and individual Bucket-level."
  },
  {
    id: "MC-04",
    controlId: "2.4",
    section: "Logging",
    title: "Ensure CloudTrail logging is enabled across all regions",
    severity: "High",
    status: "PASS",
    impact: "Failing to log regional APIs leaves dark-corners for attackers to deploy silent backdoor infrastructure.",
    remediation: "Ensure multi-region CloudTrail logging is integrated with KMS encryption and Log File Validation."
  },
  {
    id: "MC-05",
    controlId: "4.1",
    section: "Networking",
    title: "Ensure security groups do not allow unrestricted ingress to administrative ports (22, 3389)",
    severity: "High",
    status: "FAIL",
    impact: "Exposing SSH/RDP services globally invites brute force and active exploitation of zero-day kernel flaws.",
    remediation: "Restrict administrative ingress security rules to specific white-listed enterprise VPN gateways."
  }
];

export const MOCK_SCENARIOS: Scenario[] = [
  {
    id: "sc-01",
    name: "Operation CloudRaid",
    description: "Multi-stage IAM credential compromise, console hijacking, privilege escalation, logging tampering, and S3 backup data exfiltration.",
    summary: "An attack that targets dev credential leakage. The threat actor obtains active AWS Access Keys, performs broad discovery, grants administrator privileges to a surrogate secondary session, disables threat detection trails, and successfully offloads corporate data backups.",
    targetAccount: "967205250947",
    severity: "Critical",
    insights: {
      threatActor: "APT29 (Cozy Bear Affiliate) / Cloud-oriented Threat Group",
      attackVector: "Hardcoded AWS Access Keys leaked via a public testing repository.",
      impact: "Compromise of 1.4TB of customer PII and database backup files, accompanied by an audit trail freeze.",
      mitigation: "Revoke compromised credentials, enable S3 Object Lock, enforce strict conditional VPC policies, and mandate hardware-based MFA token bindings."
    },
    timeline: [
      {
        eventID: "ev-101",
        eventName: "GetCallerIdentity",
        eventSource: "sts.amazonaws.com",
        eventTime: "2026-06-22T00:15:00Z",
        awsRegion: "us-east-1",
        sourceIPAddress: "193.106.191.22",
        userAgent: "aws-cli/2.11.11 Python/3.11.3 Linux/5.15.0-72-generic",
        userIdentity: {
          type: "IAMUser",
          principalId: "AIDA96720525DEBUGDEV",
          arn: "arn:aws:iam::967205250947:user/dev-testing-key",
          accountId: "967205250947",
          accessKeyId: "AKIA967205250947CR"
        },
        threatCategory: "Discovery",
        mitreTechnique: "Cloud Infrastructure Discovery",
        mitreID: "T1580",
        anomalyScore: 0.82,
        relevanceConfidence: 0.95,
        explainabilityFeatures: { "Unusual IP Location": 0.85, "Off-Hours Execution": 0.60, "First-time API Usage": 0.50 },
        riskLevel: "High",
        flagged: true,
        notes: "Initial credential validation scanner sweep detected from unsanctioned Dutch ISP proxy."
      },
      {
        eventID: "ev-102",
        eventName: "ListBuckets",
        eventSource: "s3.amazonaws.com",
        eventTime: "2026-06-22T00:18:22Z",
        awsRegion: "us-east-1",
        sourceIPAddress: "193.106.191.22",
        userAgent: "aws-cli/2.11.11 Python/3.11.3",
        userIdentity: {
          type: "IAMUser",
          principalId: "AIDA96720525DEBUGDEV",
          arn: "arn:aws:iam::967205250947:user/dev-testing-key",
          accountId: "967205250947",
          accessKeyId: "AKIA967205250947CR"
        },
        threatCategory: "Discovery",
        mitreTechnique: "Cloud Storage Discovery",
        mitreID: "T1619",
        anomalyScore: 0.45,
        relevanceConfidence: 0.75,
        explainabilityFeatures: { "Unusual S3 Discovery": 0.55, "Unknown Agent": 0.25 },
        riskLevel: "Medium",
        flagged: false,
        notes: "Enumerating storage components to locate high-value target assets."
      },
      {
        eventID: "ev-103",
        eventName: "AttachUserPolicy",
        eventSource: "iam.amazonaws.com",
        eventTime: "2026-06-22T00:22:45Z",
        awsRegion: "us-east-1",
        sourceIPAddress: "193.106.191.22",
        userAgent: "aws-cli/2.11.11",
        userIdentity: {
          type: "IAMUser",
          principalId: "AIDA96720525DEBUGDEV",
          arn: "arn:aws:iam::967205250947:user/dev-testing-key",
          accountId: "967205250947",
          accessKeyId: "AKIA967205250947CR"
        },
        requestParameters: {
          userName: "dev-testing-key",
          policyArn: "arn:aws:iam::aws:policy/AdministratorAccess"
        },
        threatCategory: "Privilege Escalation",
        mitreTechnique: "Internal Defacement / Policy Injection",
        mitreID: "T1098",
        anomalyScore: 0.98,
        relevanceConfidence: 0.99,
        explainabilityFeatures: { "Admin Rights Granting": 0.99, "Self-Escalation Pattern": 0.95, "Anomalous IP": 0.88 },
        riskLevel: "Critical",
        flagged: true,
        notes: "CRITICAL: Suspicious session successfully bound AWS standard AdministratorAccess policy directly to itself."
      },
      {
        eventID: "ev-104",
        eventName: "StopLogging",
        eventSource: "cloudtrail.amazonaws.com",
        eventTime: "2026-06-22T00:28:10Z",
        awsRegion: "us-east-1",
        sourceIPAddress: "193.106.191.22",
        userAgent: "aws-cli/2.11.11",
        userIdentity: {
          type: "IAMUser",
          principalId: "AIDA96720525DEBUGDEV",
          arn: "arn:aws:iam::967205250947:user/dev-testing-key",
          accountId: "967205250947",
          accessKeyId: "AKIA967205250947CR"
        },
        requestParameters: {
          name: "arn:aws:cloudtrail:us-east-1:967205250947:trail/Production-Main-AuditTrail"
        },
        threatCategory: "Defense Evasion",
        mitreTechnique: "Impair Defenses: Disable Cloud Logs",
        mitreID: "T1562.008",
        anomalyScore: 0.99,
        relevanceConfidence: 1.0,
        explainabilityFeatures: { "Disabling CloudTrail Logging": 1.0, "Defense Evasion Behavior": 0.95 },
        riskLevel: "Critical",
        flagged: true,
        notes: "CRITICAL ALERT: Attacker attempted to shutdown standard enterprise audit logs to evade detection."
      },
      {
        eventID: "ev-105",
        eventName: "GetObject",
        eventSource: "s3.amazonaws.com",
        eventTime: "2026-06-22T00:35:12Z",
        awsRegion: "us-east-1",
        sourceIPAddress: "193.106.191.22",
        userAgent: "python-requests/2.31.0",
        userIdentity: {
          type: "IAMUser",
          principalId: "AIDA96720525DEBUGDEV",
          arn: "arn:aws:iam::967205250947:user/dev-testing-key",
          accountId: "967205250947",
          accessKeyId: "AKIA967205250947CR"
        },
        requestParameters: {
          bucketName: "aegis-production-db-backups",
          key: "mysql-backups/customer_pii_dump_2026_06.sql"
        },
        threatCategory: "Exfiltration",
        mitreTechnique: "Exfiltration Over Web Service / Cloud Medium",
        mitreID: "T1567",
        anomalyScore: 0.95,
        relevanceConfidence: 0.98,
        explainabilityFeatures: { "Data Volume Spike": 0.96, "Sensitive Bucket Access": 0.92, "Anomalous Tool": 0.8 },
        riskLevel: "Critical",
        flagged: true,
        notes: "Exfiltrating database dump from highly critical financial backup repository via automated scraper script."
      }
    ]
  },
  {
    id: "sc-02",
    name: "Operation ServerlessHijack",
    description: "Serverless function compromise, AWS secrets theft, backdoored serverless APIs, and remote database reconfiguration.",
    summary: "This operation details an advanced multi-staged assault on AWS Serverless infrastructure. The attacker assumes a role compromised on an exposed local EC2 container, queries sensitive production database passwords from AWS Secrets Manager, uploads a persistent unauthenticated remote command executor (backdoor) inside a production AWS Lambda function, and triggers database mutation controls.",
    targetAccount: "967205250947",
    severity: "High",
    insights: {
      threatActor: "UNC3944 (Scattered Spider) / Serverless specialists",
      attackVector: "SSRF vulnerability in web frontend allowing EC2 Instance Metadata Service v1 credentials harvest.",
      impact: "Unauthorized persistent serverless backdoors, database credential harvesting, and database modification.",
      mitigation: "Transition EC2 metadata structures to IMDSv2 strictly, apply minimal IAM roles for AWS Lambda execution, and activate comprehensive database activity guards."
    },
    timeline: [
      {
        eventID: "ev-201",
        eventName: "AssumeRole",
        eventSource: "sts.amazonaws.com",
        eventTime: "2026-06-22T01:10:00Z",
        awsRegion: "eu-west-1",
        sourceIPAddress: "185.220.101.44",
        userAgent: "boto3/1.28.1 Python/3.10.8",
        userIdentity: {
          type: "AssumedRole",
          principalId: "AROA96720525FRONTENDSESS",
          arn: "arn:aws:sts::967205250947:assumed-role/EC2WebAppExecutionRole/i-0fc652199bda88ae",
          accountId: "967205250947"
        },
        threatCategory: "Initial Access",
        mitreTechnique: "Cloud Instance Metadata Access hijacking",
        mitreID: "T1552",
        anomalyScore: 0.74,
        relevanceConfidence: 0.85,
        explainabilityFeatures: { "Unusual IP Access": 0.85, "Cross-Region Credential Use": 0.40 },
        riskLevel: "High",
        flagged: true,
        notes: "Legitimate EC2 execution tokens were activated from a public Tor Exit Gateway node in eu-west-1."
      },
      {
        eventID: "ev-202",
        eventName: "GetSecretValue",
        eventSource: "secretsmanager.amazonaws.com",
        eventTime: "2026-06-22T01:14:32Z",
        awsRegion: "eu-west-1",
        sourceIPAddress: "185.220.101.44",
        userAgent: "boto3/1.28.1 Python/3.10.8",
        userIdentity: {
          type: "AssumedRole",
          principalId: "AROA96720525FRONTENDSESS",
          arn: "arn:aws:sts::967205250947:assumed-role/EC2WebAppExecutionRole/i-0fc652199bda88ae",
          accountId: "967205250947"
        },
        requestParameters: {
          secretId: "arn:aws:secretsmanager:eu-west-1:967205250947:secret:ProductionDatabaseRDSSecret-fS8"
        },
        threatCategory: "Credential Access",
        mitreTechnique: "Steal Web Credentials / Credentials from Vault",
        mitreID: "T1528",
        anomalyScore: 0.89,
        relevanceConfidence: 0.91,
        explainabilityFeatures: { "Secrets Harvesting": 0.91, "First SecAccess on Node": 0.60 },
        riskLevel: "High",
        flagged: true,
        notes: "Attacker successfully harvested primary enterprise database passwords using the compromised EC2 Session token."
      },
      {
        eventID: "ev-203",
        eventName: "CreateFunction20150331",
        eventSource: "lambda.amazonaws.com",
        eventTime: "2026-06-22T01:21:05Z",
        awsRegion: "eu-west-1",
        sourceIPAddress: "185.220.101.44",
        userAgent: "boto3/1.28.1",
        userIdentity: {
          type: "AssumedRole",
          principalId: "AROA96720525FRONTENDSESS",
          arn: "arn:aws:sts::967205250947:assumed-role/EC2WebAppExecutionRole/i-0fc652199bda88ae",
          accountId: "967205250947"
        },
        requestParameters: {
          functionName: "Production-BackupCleaner-Backdoor",
          runtime: "python3.10",
          handler: "backdoor.lambda_handler"
        },
        threatCategory: "Persistence",
        mitreTechnique: "Serverless Execution backdooring",
        mitreID: "T1059.006",
        anomalyScore: 0.94,
        relevanceConfidence: 0.95,
        explainabilityFeatures: { "Unauthorized Code Upload": 0.95, "New Function Injection": 0.8 },
        riskLevel: "Critical",
        flagged: true,
        notes: "CRITICAL: Created a serverless function with high execution parameters named Backdoor to implement continuous shell capabilities."
      },
      {
        eventID: "ev-204",
        eventName: "ModifyDBInstance",
        eventSource: "rds.amazonaws.com",
        eventTime: "2026-06-22T01:30:15Z",
        awsRegion: "eu-west-1",
        sourceIPAddress: "185.220.101.44",
        userAgent: "boto3/1.28.1",
        userIdentity: {
          type: "AssumedRole",
          principalId: "AROA96720525FRONTENDSESS",
          arn: "arn:aws:sts::967205250947:assumed-role/EC2WebAppExecutionRole/i-0fc652199bda88ae",
          accountId: "967205250947"
        },
        requestParameters: {
          dBInstanceIdentifier: "aegisprod-rds-postgres",
          publiclyAccessible: true
        },
        threatCategory: "Impact",
        mitreTechnique: "Expose Cloud Assets publicly",
        mitreID: "T1562.001",
        anomalyScore: 0.97,
        relevanceConfidence: 0.98,
        explainabilityFeatures: { "Network Security Downgrade": 0.99, "Enabling Public Access": 0.98 },
        riskLevel: "Critical",
        flagged: true,
        notes: "CRITICAL SECURITY INCIDENT: Adjusted RDS DB structure to allow loose, open public accessibility (*:5432)."
      }
    ]
  }
];

export const MOCK_EVIDENCE: EvidenceArtifact[] = [
  {
    id: "art-1",
    fileName: "CloudTrail-Logs_967205250947_20260622.json.gz",
    fileSize: "8.4 MB",
    fileHash: "9f85c13e54619d08658cdb12af9a9a5f4f899de8cd0ec3cfec3d4df43b7dfbe3",
    chainOfCustody: [
      {
        recordedAt: "2026-06-22T02:00:00Z",
        recordedBy: "udayky91@gmail.com",
        action: "Evidence Acquisition",
        notes: "Acquired main CloudTrail logs automatically using AWS S3 API forensics daemon. Secure log integrity validated."
      },
      {
        recordedAt: "2026-06-22T02:15:00Z",
        recordedBy: "udayky91@gmail.com",
        action: "Integrity Verification",
        notes: "MD5/SHA256 checksum mismatch verification matches AWS secure log receipt file. Zero tamper events recorded."
      }
    ],
    comments: [
      {
        id: "com-1",
        author: "udayky91@gmail.com",
        timestamp: "2026-06-22T02:30:00Z",
        text: "The log segment completely validates critical exfiltration of SQL files from bucket 'aegis-production-db-backups'."
      }
    ]
  },
  {
    id: "art-2",
    fileName: "Compromised-Access-Key-AKIA96.txt",
    fileSize: "120 B",
    fileHash: "5e20606db9ec090cfdd546377777ca22ff6db9c6d3dfd7b7fa237ffdf8f3e098",
    chainOfCustody: [
      {
        recordedAt: "2026-06-22T03:00:00Z",
        recordedBy: "SOC Lead",
        action: "Key Isolation",
        notes: "Saved compromised developer access credentials from developer's automated testing deployment script repository for formal litigation."
      }
    ],
    comments: []
  }
];

export const RESEARCH_SECTIONS: ResearchPaperSection[] = [
  {
    title: "IEEE paper contribution section",
    subtitle: "AI-Driven Real-time Cloud Forensic Graph Reasoning",
    paragraphs: [
      "Traditional cloud forensics suffers from fragmented timeline isolation, leaving security engineers with thousands of nested JSON entries to trace in a manual spreadsheet. This research presents AegisForensics, an AI-powered automated CloudTrail intrusion response and temporal graph correlation architecture. By mapping AWS API calls directly onto Graph Structures representing session linkages, IAM boundaries, and network identities, we successfully isolate multi-stage advanced persistent threat (APT) paths automatically.",
      "Our main contribution is three-fold: (1) An explainable, feature-driven anomaly engine mapping raw user agency to statistical anomalous deviation scores. (2) A contextual attack reconstruction graph correlating identity escalation directly to storage exfiltration (e.g., S3 exfiltrations or public bucket openings). (3) A generative AI forensic narrative synthesis leveraging Gemini, providing an explainable, plain-English 'attack story' to bridge high-complexity JSON configurations to actionable executive mitigation actions within seconds."
    ]
  },
  {
    title: "Research Novelty",
    subtitle: "What makes this publication-worthy?",
    paragraphs: [
      "1. Graph-Neural and Session Alignment: Instead of focusing merely on standalone API alert triggers, our model reconstructs AWS session trees based on access key boundaries and IAM Principal lifecycles. This ensures that even if an attacker rotates their IP, the session correlation engine maintains custody of the target entity.",
      "2. Explainable AI with Local SHAP-driven Feature Explanations: To empower SOC analysts, every single calculated threat level is supported by interactive feature importance arrays (e.g., assessing why an execution was flagged, visualizing MFA states, unusual agent types, or regional anomalies).",
      "3. Generative AI Attack Storytelling: Integrating modern Gemini models allows us to instantly generate technically robust incident chronologies, root-cause summaries, and live SQL threat hunting search commands (e.g., Splunk / Athena / Sentinel KQL query generation) dynamically tailored to the precise timeline ingested."
    ]
  }
];
