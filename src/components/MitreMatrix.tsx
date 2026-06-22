/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { CloudTrailEvent } from '../types';

interface MitreMatrixProps {
  timeline: CloudTrailEvent[];
}

export default function MitreMatrix({ timeline }: MitreMatrixProps) {
  // Broad list of cloud techniques to show inside matrix
  const MITRE_CLUSTERS = [
    {
      tactic: "Initial Access",
      techniques: [
        { id: "T1566", name: "Phishing: Spearphishing", desc: "Access via link" },
        { id: "T1552", name: "Unsecured Credentials", desc: "Hardcoded API keys" },
        { id: "T1133", name: "External Services", desc: "Exposed API gateway" }
      ]
    },
    {
      tactic: "Persistence",
      techniques: [
        { id: "T1098", name: "Account Manipulation", desc: "Creating backup keys" },
        { id: "T1059.006", name: "Serverless Persistent", desc: "Rogue lambda deploy" },
        { id: "T1136", name: "Create Account", desc: "Backdoor IAM role" }
      ]
    },
    {
      tactic: "Privilege Escalation",
      techniques: [
        { id: "T1098.003", name: "Policy Injection", desc: "Admin permissions" },
        { id: "T1548", name: "Bypass Authorization", desc: "Assume execution role" },
        { id: "T1134", name: "Token Impersonation", desc: "STS session theft" }
      ]
    },
    {
      tactic: "Defense Evasion",
      techniques: [
        { id: "T1562.008", name: "Impair Defenses: Logs", desc: "Shut down CloudTrail" },
        { id: "T1578", name: "Modify Cloud Compute", desc: "Terminate security group" },
        { id: "T1562.001", name: "Disable Security Tools", desc: "Stop GuardDuty" }
      ]
    },
    {
      tactic: "Credential Access",
      techniques: [
        { id: "T1528", name: "Steal Credentials", desc: "Secrets Manager crawl" },
        { id: "T1555", name: "Credentials from Store", desc: "EC2 Metadata API" },
        { id: "T1110", name: "Brute Force", desc: "Password spraying" }
      ]
    },
    {
      tactic: "Discovery",
      techniques: [
        { id: "T1580", name: "Cloud Infrastructure", desc: "ListBuckets / APIs" },
        { id: "T1619", name: "Cloud Storage Discovery", desc: "S3 objects traversal" },
        { id: "T1082", name: "System Information", desc: "Describe DB clusters" }
      ]
    },
    {
      tactic: "Exfiltration",
      techniques: [
        { id: "T1537", name: "Transfer Cloud Assets", desc: "S3 high volume egress" },
        { id: "T1567", name: "Over Web Service", desc: "Exfil to foreign bucket" },
        { id: "T1048", name: "Alternative Protocol", desc: "Direct database dump" }
      ]
    },
    {
      tactic: "Impact",
      techniques: [
        { id: "T1529", name: "System Shutdown", desc: "Terminating instances" },
        { id: "T1485", name: "Data Destruction", desc: "Deletions / S3 purging" },
        { id: "T1496", name: "Resource Hijacking", desc: "Crypto mining spikes" }
      ]
    }
  ];

  // Helper to check if a technique is active in the current timeline
  const activeTechniqueIDs = timeline.map(e => e.mitreID).filter(Boolean);

  return (
    <div id="mitre-matrix-view" className="bg-[#141414] border border-[#262626] rounded-xl p-6">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h2 className="text-xl font-sans font-semibold text-white">MITRE ATT&CK® Enterprise & Cloud Navigator</h2>
          <p className="text-xs text-gray-400">Heatmap of tactics mapped dynamically from CloudTrail forensic timelines</p>
        </div>
        <div className="flex gap-4 text-xs">
          <div className="flex items-center gap-1.5 text-red-400">
            <span className="w-2.5 h-2.5 rounded bg-red-500/20 border border-red-500/35"></span>
            <span>Active Threat Vector</span>
          </div>
          <div className="flex items-center gap-1.5 text-gray-500">
            <span className="w-2.5 h-2.5 rounded bg-[#0A0A0A] border border-[#262626]"></span>
            <span>Inactive Technique</span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 xl:grid-cols-8 gap-4 overflow-x-auto">
        {MITRE_CLUSTERS.map((cluster) => {
          // Count active in this tactic
          const isActiveTactic = cluster.techniques.some(tech => activeTechniqueIDs.includes(tech.id));

          return (
            <div key={cluster.tactic} className="flex flex-col min-w-[140px] bg-black/40 border border-[#262626] rounded-lg">
              <div className={`p-3 text-center border-b font-sans font-semibold text-xs tracking-wider uppercase ${
                isActiveTactic 
                  ? 'bg-red-500/10 text-red-400 border-red-900/45' 
                  : 'bg-[#141414] text-gray-400 border-[#262626]'
              }`}>
                {cluster.tactic}
              </div>
              <div className="p-2 flex flex-col gap-2.5 flex-grow">
                {cluster.techniques.map((tech) => {
                  const isActive = activeTechniqueIDs.includes(tech.id);
                  const triggeringEvents = timeline.filter(e => e.mitreID === tech.id);

                  return (
                    <div
                      key={tech.id}
                      className={`p-2.5 rounded-md border text-left transition-all ${
                        isActive
                          ? 'bg-red-500/10 border-red-500/30 shadow-[0_0_12px_rgba(239,68,68,0.1)] text-red-150'
                          : 'bg-[#0F0F0F] border-[#262626] hover:border-[#404040]'
                      }`}
                    >
                      <div className="flex justify-between items-baseline mb-1">
                        <span className={`text-[10px] font-mono font-medium ${isActive ? 'text-red-400' : 'text-gray-500'}`}>
                          {tech.id}
                        </span>
                        {isActive && (
                          <span className="bg-red-500/20 text-red-300 text-[9px] px-1 rounded font-bold">
                            {triggeringEvents.length}x
                          </span>
                        )}
                      </div>
                      <h4 className={`text-xs font-sans font-medium line-clamp-1 ${isActive ? 'text-[#FFFFFF]' : 'text-gray-400'}`}>
                        {tech.name}
                      </h4>
                      <p className="text-[10px] text-gray-500 mt-1 font-mono tracking-tight leading-relaxed">
                        {tech.desc}
                      </p>

                      {isActive && (
                        <div className="mt-2 pt-2 border-t border-red-500/20 flex flex-col gap-1">
                          {triggeringEvents.map((ev) => (
                            <span key={ev.eventID} className="text-[9px] font-mono text-red-300 bg-red-950/30 px-1 py-0.5 rounded truncate">
                              API: {ev.eventName}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
