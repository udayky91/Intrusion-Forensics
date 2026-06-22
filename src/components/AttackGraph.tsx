/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { CloudTrailEvent } from '../types';
import { Shield, Hammer, Key, FileText, Database, ShieldAlert, ArrowRight } from 'lucide-react';

interface AttackGraphProps {
  timeline: CloudTrailEvent[];
  scenarioName: string;
}

interface Node {
  id: string;
  label: string;
  type: 'IP' | 'USER_KEY' | 'IAM_ROLE' | 'SECURITY_SERVICE' | 'STORAGE_TARGET' | 'ATTACK_STAGE' | 'BACKDOOR' | 'DATABASE';
  description: string;
  cx: number;
  cy: number;
  threatLevel: 'Low' | 'Medium' | 'High' | 'Critical';
}

interface Edge {
  source: string;
  target: string;
  label: string;
  isActive: boolean;
  isThreat: boolean;
}

export default function AttackGraph({ timeline, scenarioName }: AttackGraphProps) {
  const [selectedNode, setSelectedNode] = useState<Node | null>(null);

  // Generate dynamic nodes & edges depending on the selected scenario
  const isCloudRaid = scenarioName.includes("CloudRaid") || timeline.some(e => e.eventName.includes("StopLogging"));

  const nodes: Node[] = isCloudRaid 
    ? [
        { id: "node-ip", label: "193.106.191.22", type: "IP", description: "Malicious Dutch Tor Exit IP detected performing brute queries.", cx: 100, cy: 150, threatLevel: "Critical" },
        { id: "node-key", label: "dev-testing-key", type: "USER_KEY", description: "AKIA96...CR Compromised AWS Account Developer Access Credentials.", cx: 280, cy: 150, threatLevel: "Critical" },
        { id: "node-priv", label: "AttachUserPolicy (AdminRights)", type: "ATTACK_STAGE", description: "Triggered Privilege Escalation. Direct Administrator access attached.", cx: 460, cy: 80, threatLevel: "Critical" },
        { id: "node-eva", label: "StopLogging (Trail-TAMPER)", type: "BACKDOOR", description: "Disabled main Production-Main-AuditTrail logging entity.", cx: 460, cy: 220, threatLevel: "High" },
        { id: "node-store", label: "aegis-production-db-backups", type: "STORAGE_TARGET", description: "Target S3 bucket holding main SQL customer backups.", cx: 640, cy: 150, threatLevel: "Critical" }
      ]
    : [
        { id: "node-ip-b", label: "185.220.101.44", type: "IP", description: "Suspect German Tor exit entry node initiating AssumeRole flows.", cx: 100, cy: 150, threatLevel: "High" },
        { id: "node-sess", label: "EC2WebAppExecutionRole", type: "IAM_ROLE", description: "STS Session Assumed from exposed IMDSv1 web container.", cx: 280, cy: 150, threatLevel: "High" },
        { id: "node-cred", label: "SecretsManager: RDSSecret", type: "USER_KEY", description: "Extracted cleartext primary production production DB passwords.", cx: 460, cy: 80, threatLevel: "Critical" },
        { id: "node-lambda", label: "Lambda: BackupCleaner", type: "BACKDOOR", description: "Injected Python serverless backdoor command triggers.", cx: 460, cy: 220, threatLevel: "Critical" },
        { id: "node-db", label: "aegisprod-rds-postgres", type: "DATABASE", description: "Reconfigured database exposing postgres publicly (port 5432).", cx: 640, cy: 150, threatLevel: "Critical" }
      ];

  const edges: Edge[] = isCloudRaid
    ? [
        { source: "node-ip", target: "node-key", label: "API Authenticate via STS GetCallerIdentity", isActive: true, isThreat: true },
        { source: "node-key", target: "node-priv", label: "Self-attach Administrator policy", isActive: true, isThreat: true },
        { source: "node-key", target: "node-eva", label: "Trigger CloudTrail audit trail deactivation", isActive: true, isThreat: true },
        { source: "node-priv", target: "node-store", label: "Access secure backup data via high volume download", isActive: true, isThreat: true },
        { source: "node-eva", target: "node-store", label: "Coverage blind spot during GetObject triggers", isActive: true, isThreat: true }
      ]
    : [
        { source: "node-ip-b", target: "node-sess", label: "Unauthorized AWS AssumeRole trigger via Tor IP", isActive: true, isThreat: true },
        { source: "node-sess", target: "node-cred", label: "Harvest AWS Secrets Database configuration strings", isActive: true, isThreat: true },
        { source: "node-sess", target: "node-lambda", label: "Deploy backdoored Python micro-function", isActive: true, isThreat: true },
        { source: "node-sess", target: "node-db", label: "ModifyDBInstance to allow broad remote endpoints", isActive: true, isThreat: true },
        { source: "node-lambda", target: "node-db", label: "Initiate SQL table scanning commands", isActive: true, isThreat: true }
      ];

  // Colors mapping for node types
  const getNodeColor = (type: string) => {
    switch (type) {
      case 'IP': return '#f43f5e'; // rose-500
      case 'USER_KEY': return '#f59e0b'; // amber-500
      case 'IAM_ROLE': return '#ec4899'; // pink-500
      case 'STORAGE_TARGET': return '#06b6d4'; // cyan-500
      case 'DATABASE': return '#3b82f6'; // blue-500
      case 'ATTACK_STAGE': return '#a855f7'; // purple-500
      case 'BACKDOOR': return '#ef4444'; // red-500
      default: return '#94a3b8';
    }
  };

  const getNodeIcon = (type: string) => {
    switch (type) {
      case 'IP': return <ShieldAlert className="w-5 h-5 text-rose-400" />;
      case 'USER_KEY': return <Key className="w-5 h-5 text-amber-400" />;
      case 'IAM_ROLE': return <Shield className="w-5 h-5 text-pink-400" />;
      case 'STORAGE_TARGET': return <FileText className="w-5 h-5 text-cyan-400" />;
      case 'DATABASE': return <Database className="w-5 h-5 text-blue-400" />;
      case 'ATTACK_STAGE': return <Hammer className="w-5 h-5 text-purple-400" />;
      case 'BACKDOOR': return <ShieldAlert className="w-5 h-5 text-red-500" />;
      default: return <Shield className="w-5 h-5 text-slate-400" />;
    }
  };

  return (
    <div id="attack-graph-view" className="bg-[#141414] border border-[#262626] rounded-xl p-6">
      <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-4 mb-6">
        <div>
          <h2 className="text-xl font-sans font-semibold text-white flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-550 bg-cyan-500 shadow-[0_0_10px_rgba(6,182,212,0.5)] animate-pulse"></span>
            Interactive Graph-Based Attack Reconstruction
          </h2>
          <p className="text-xs text-gray-400">Context-Aware digital twin reconstruction mapping compromised entities, security boundaries, and data flow</p>
        </div>
        <div className="flex flex-wrap gap-2 text-[11px] bg-black/40 p-2 border border-[#262626] rounded-lg">
          <span className="flex items-center gap-1.5 px-2 py-0.5 text-red-400 border border-[#262626] bg-red-500/10 rounded">
            <span className="w-1.5 h-1.5 rounded-full bg-red-500"></span> Threat IP
          </span>
          <span className="flex items-center gap-1.5 px-2 py-0.5 text-orange-400 border border-[#262626] bg-orange-500/10 rounded">
            <span className="w-1.5 h-1.5 rounded-full bg-orange-500"></span> User Key
          </span>
          <span className="flex items-center gap-1.5 px-2 py-0.5 text-pink-400 border border-[#262626] bg-pink-500/10 rounded">
            <span className="w-1.5 h-1.5 rounded-full bg-pink-500"></span> Policy Roles
          </span>
          <span className="flex items-center gap-1.5 px-2 py-0.5 text-cyan-400 border border-[#262626] bg-cyan-550/10 bg-cyan-500/10 rounded">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-500"></span> Target Storage
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* SVG Drawing Canvas of Graph Topology (Module 8) */}
        <div className="xl:col-span-2 bg-[#0A0A0A] border border-[#262626] rounded-lg overflow-hidden relative min-h-[400px] flex items-center justify-center">
          <div className="absolute top-4 left-4 text-xs font-mono text-gray-500 uppercase tracking-widest bg-[#0F0F0F] border border-[#262626] px-2.5 py-1 rounded">
            Graph Topology Model: Neo4j Node Relations
          </div>

          <svg className="w-full h-full min-h-[400px]" viewBox="0 0 740 320">
            <defs>
              <marker id="arrow" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#f43f5e" />
              </marker>
              <marker id="arrow-inactive" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#262626" />
              </marker>
            </defs>

            {/* Draw Links/Edges */}
            {edges.map((edge, idx) => {
              const srcNode = nodes.find(n => n.id === edge.source);
              const tgtNode = nodes.find(n => n.id === edge.target);
              if (!srcNode || !tgtNode) return null;

              return (
                <g key={`edge-${idx}`}>
                  {/* Neon Threat Track Laser Line */}
                  <line
                    x1={srcNode.cx} y1={srcNode.cy}
                    x2={tgtNode.cx} y2={tgtNode.cy}
                    stroke={edge.isThreat ? '#f43f5e' : '#262626'}
                    strokeWidth={edge.isThreat ? 2 : 1}
                    strokeDasharray={edge.isThreat ? '6,4' : 'none'}
                    markerEnd={edge.isThreat ? 'url(#arrow)' : 'url(#arrow-inactive)'}
                    className={edge.isThreat ? 'animate-[dash_20s_linear_infinite]' : ''}
                  />
                  {/* Subtle edge middle label hover element */}
                  <ellipse
                    cx={(srcNode.cx + tgtNode.cx) / 2}
                    cy={(srcNode.cy + tgtNode.cy) / 2}
                    rx="10" ry="10"
                    fill="#0A0A0A" stroke="#262626"
                    className="cursor-help"
                  />
                  <text
                    x={(srcNode.cx + tgtNode.cx) / 2}
                    y={(srcNode.cy + tgtNode.cy) / 2 + 3}
                    textAnchor="middle"
                    fill="#a3a3a3"
                    fontSize="9px"
                    fontFamily="monospace"
                  >
                    i
                  </text>
                </g>
              );
            })}

            {/* Draw Nodes */}
            {nodes.map((node) => {
              const worksAsSelected = selectedNode?.id === node.id;
              const nodeColor = getNodeColor(node.type);

              return (
                <g
                  key={node.id}
                  className="cursor-pointer group transition-all"
                  onClick={() => setSelectedNode(node)}
                >
                  {/* Outer Pulsing Glow */}
                  <circle
                    cx={node.cx} cy={node.cy}
                    r={worksAsSelected ? 24 : 18}
                    fill="transparent"
                    stroke={nodeColor}
                    strokeWidth={2}
                    strokeOpacity={worksAsSelected ? 0.9 : 0.2}
                    className="group-hover:stroke-opacity-80 transition-all"
                  />
                  {/* Solid background Node circle */}
                  <circle
                    cx={node.cx} cy={node.cy}
                    r={worksAsSelected ? 18 : 14}
                    fill="#0F0F0F"
                    stroke={nodeColor}
                    strokeWidth={2}
                  />
                  {/* Inside Indicator */}
                  <text
                    x={node.cx} y={node.cy + 4}
                    textAnchor="middle"
                    fontSize="10"
                    fill="#FFFFFF"
                    fontFamily="sans-serif"
                    fontWeight="bold"
                  >
                    {node.type.substring(0, 2)}
                  </text>

                  {/* Label tag below node */}
                  <text
                    x={node.cx} y={node.cy + 32}
                    textAnchor="middle"
                    fontSize="10px"
                    fill={worksAsSelected ? '#FFFFFF' : '#a3a3a3'}
                    fontFamily="monospace"
                    fontWeight={worksAsSelected ? 'bold' : 'normal'}
                  >
                    {node.label}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>

        {/* Selected Entity Context panel */}
        <div className="bg-[#0F0F0F] border border-[#262626] rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex justify-between items-center pb-3 border-b border-[#262626]">
              <h3 className="text-sm font-sans font-semibold text-white">Reconstructed Node Metadata</h3>
              <span className="text-[10px] bg-cyan-500/10 text-cyan-400 px-2 py-0.5 border border-[#262626] rounded">
                Active Forensics
              </span>
            </div>

            {selectedNode ? (
              <div className="mt-4 flex flex-col gap-4">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-black/40 border border-[#262626] rounded-lg">
                    {getNodeIcon(selectedNode.type)}
                  </div>
                  <div>
                    <h4 className="text-sm font-semibold text-white">{selectedNode.label}</h4>
                    <span className="text-[10px] font-mono text-gray-400 capitalize bg-black/40 border border-[#262626]/60 px-1.5 py-0.5 rounded">
                      Type: {selectedNode.type}
                    </span>
                  </div>
                </div>

                <div className="bg-[#0A0A0A] border border-[#262626] p-3 rounded-md text-xs leading-relaxed text-gray-300">
                  <span className="font-semibold text-gray-400 block mb-1">Entity Investigation Bio:</span>
                  {selectedNode.description}
                </div>

                <div className="flex justify-between items-center text-xs">
                  <span className="text-gray-500">Anomalous Risk Severity:</span>
                  <span className={`px-2 py-0.5 rounded-full font-sans font-bold text-[10px] ${
                    selectedNode.threatLevel === 'Critical' ? 'bg-red-500/10 text-red-400 border border-red-900/30' :
                    selectedNode.threatLevel === 'High' ? 'bg-orange-500/10 text-orange-400 border border-orange-950/30' :
                    'bg-[#0A0A0A] text-gray-300 border border-[#262626]'
                  }`}>
                    {selectedNode.threatLevel}
                  </span>
                </div>
              </div>
            ) : (
              <div className="text-center py-12 text-gray-500 text-xs">
                <Shield className="w-10 h-10 text-gray-650 mx-auto mb-3 animate-pulse text-cyan-500" />
                Select any network topological node on the workspace to extract security credentials, relationships, and context indicators.
              </div>
            )}
          </div>

          <div className="mt-6 pt-3 border-t border-[#262626]">
            <div className="bg-black/40 border border-[#262626] p-2.5 rounded text-[10px] text-gray-500 font-mono flex items-start gap-1.5">
              <span>*</span>
              <span>Visual mapping implements predictive security heuristics: correlating lateral pivoting over identical credential IDs and session ARNs.</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
