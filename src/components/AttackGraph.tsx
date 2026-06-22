/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useRef, useEffect } from 'react';
import * as d3 from 'd3';
import { CloudTrailEvent } from '../types';
import { Shield, Hammer, Key, FileText, Database, ShieldAlert, ArrowRight, Flame, Layers } from 'lucide-react';

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
  const [hotSpotEnabled, setHotSpotEnabled] = useState(true);
  const [hotSpotThreshold, setHotSpotThreshold] = useState(30);

  // Dynamic Node filtering states & collections
  const [disabledTypes, setDisabledTypes] = useState<string[]>([]);

  // Hover Tooltip States & Cursor Tracker
  const [hoveredNode, setHoveredNode] = useState<Node | null>(null);
  const [mousePos, setMousePos] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const containerRef = useRef<HTMLDivElement>(null);

  const updateMousePos = (e: React.MouseEvent) => {
    if (containerRef.current) {
      const rect = containerRef.current.getBoundingClientRect();
      setMousePos({
        x: e.clientX - rect.left,
        y: e.clientY - rect.top,
      });
    }
  };

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

  // Get all unique node types in the current scenario
  const availableNodeTypes = Array.from(new Set(nodes.map(n => n.type)));

  // Filtered nodes and edges dynamically
  const filteredNodes = nodes.filter(n => !disabledTypes.includes(n.type));
  const filteredEdges = edges.filter(e => {
    const hasSource = filteredNodes.some(n => n.id === e.source);
    const hasTarget = filteredNodes.some(n => n.id === e.target);
    return hasSource && hasTarget;
  });

  // Clear selected / hovered nodes if they are filtered out
  useEffect(() => {
    if (selectedNode && !filteredNodes.some(n => n.id === selectedNode.id)) {
      setSelectedNode(null);
    }
    if (hoveredNode && !filteredNodes.some(n => n.id === hoveredNode.id)) {
      setHoveredNode(null);
    }
  }, [disabledTypes, scenarioName]);

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

  // Human-friendly translations for AWS services and threat concepts
  const getNodeTypeLabelAndDesc = (type: string) => {
    switch (type) {
      case 'IP':
        return { name: 'EC2 Host / Tor IP', desc: 'Virtual ingress endpoint' };
      case 'USER_KEY':
        return { name: 'Compromised API Keys', desc: 'Secure AWS access credentials' };
      case 'IAM_ROLE':
        return { name: 'IAM Delegation Roles', desc: 'Identity & Access tokens' };
      case 'STORAGE_TARGET':
        return { name: 'S3 Target Buckets', desc: 'Storage target S3 data' };
      case 'DATABASE':
        return { name: 'RDS Databases', desc: 'Relational data assets' };
      case 'ATTACK_STAGE':
        return { name: 'Privilege Escalation', desc: 'In-flight policy overpasses' };
      case 'BACKDOOR':
        return { name: 'Backdoor Functions', desc: 'Persistent stealth hooks' };
      default:
        return { name: type, desc: 'Cluster boundaries' };
    }
  };

  // Get threat level numerical representation to calculate criticality index
  const getThreatWeight = (level: string) => {
    switch (level) {
      case 'Critical': return 4;
      case 'High': return 3;
      case 'Medium': return 2;
      case 'Low': return 1;
      default: return 1;
    }
  };

  // Count active paths connected to a given node (source or target)
  const getConnectedCount = (nodeId: string) => {
    return filteredEdges.filter(e => e.source === nodeId || e.target === nodeId).length;
  };

  // Calculate Aggregated Criticality Heat Score out of 100
  // Threat Level weight (1-4) represents up to 60 pts (weighted 15 pts per unit)
  // Number of connected attack paths (edges) represents up to 40 pts (weighted 10 pts per edge, max 4 edges)
  const getHotSpotScore = (node: Node) => {
    const rawWeight = getThreatWeight(node.threatLevel);
    const rawPaths = getConnectedCount(node.id);
    const score = (rawWeight * 15) + (rawPaths * 10);
    return Math.min(100, Math.max(10, score));
  };

  // Pre-calculate hot spot indices so D3 scales can calibrate smoothly
  const computedScores = filteredNodes.map(n => getHotSpotScore(n));
  const minScore = d3.min(computedScores) || 10;
  const maxScore = d3.max(computedScores) || 100;

  // D3 Scales mapping physical score metrics -> visual glow indicators
  const glowRadiusScale = d3.scaleLinear()
    .domain([minScore, maxScore])
    .range([18, 45]);

  const glowOpacityScale = d3.scaleLinear()
    .domain([minScore, maxScore])
    .range([0.2, 0.85]);

  // Interpolated visual heat colors using D3: cyan (low background target) -> hot orange (medium focal) -> warning feedback red (critical hotspot)
  const glowColorScale = d3.scaleLinear<string, string>()
    .domain([minScore, (minScore + maxScore) / 2, maxScore])
    .range(['#22d3ee', '#f97316', '#ef4444']);

  // Extract associated events from raw CloudTrail timeline mapping to selected/hovered nodes
  const getAssociatedEvents = (node: Node) => {
    return timeline.filter(e => {
      const serialized = JSON.stringify(e).toLowerCase();
      const lLabel = node.label.toLowerCase();
      
      if (node.type === 'IP') {
        return e.sourceIPAddress === node.label || serialized.includes(lLabel);
      }
      if (node.type === 'USER_KEY') {
        return (
          e.userIdentity?.accessKeyId?.toLowerCase() === lLabel ||
          e.userIdentity?.userName?.toLowerCase() === lLabel ||
          e.userIdentity?.arn?.toLowerCase().includes(lLabel) ||
          serialized.includes(lLabel)
        );
      }
      if (node.type === 'ATTACK_STAGE' || node.type === 'BACKDOOR') {
        const parts = node.label.split(' ');
        const mainKeyword = parts[0].toLowerCase();
        return e.eventName?.toLowerCase().includes(mainKeyword) || serialized.includes(mainKeyword);
      }
      if (node.type === 'STORAGE_TARGET' || node.type === 'DATABASE' || node.type === 'IAM_ROLE') {
        return serialized.includes(lLabel) || e.eventName?.toLowerCase().includes(lLabel) || e.eventSource?.toLowerCase().includes(lLabel);
      }
      return serialized.includes(lLabel);
    });
  };

  return (
    <div id="attack-graph-view" className="bg-[#141414] border border-[#262626] rounded-xl p-6">
      <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-4 mb-6">
        <div>
          <h2 className="text-xl font-sans font-semibold text-white flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-500 shadow-[0_0_10px_rgba(6,182,212,0.5)] animate-pulse"></span>
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

      {/* Dynamic D3 Hotspot Controller Interactive Console */}
      <div className="bg-[#0F0F0F] border border-[#262626] rounded-xl p-4 mb-6 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-orange-500/10 border border-orange-500/20 rounded-lg text-orange-400">
            <Flame className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <span className="text-xs font-mono text-orange-400 uppercase font-bold tracking-wider block">D3.js Intelligent Criticality Engine</span>
            <p className="text-xs text-gray-300">Live holographic heatmap layer calculating node vulnerability relative to target severity and path connections.</p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-4 w-full md:w-auto">
          {/* Active Toggle Checkbox */}
          <label className="flex items-center gap-2 cursor-pointer select-none text-xs text-gray-300 font-sans border border-[#262626] bg-black/40 hover:bg-black/60 px-3 py-1.5 rounded-lg transition-all">
            <input 
              type="checkbox" 
              checked={hotSpotEnabled} 
              onChange={(e) => setHotSpotEnabled(e.target.checked)}
              className="accent-orange-500 w-3.5 h-3.5 cursor-pointer rounded bg-black border-[#262626]"
            />
            <span className="font-semibold uppercase tracking-wide">Plot Heatmap Layer</span>
          </label>

          {/* Range Slider for Interactive Threshold */}
          {hotSpotEnabled && (
            <div className="flex items-center gap-3 bg-black/40 border border-[#262626] px-3 py-1.5 rounded-lg text-xs w-full sm:w-auto">
              <span className="text-gray-400 font-mono text-[11px] whitespace-nowrap uppercase">Min Score Filter:</span>
              <input 
                type="range" 
                min="10" 
                max="100" 
                value={hotSpotThreshold} 
                onChange={(e) => setHotSpotThreshold(Number(e.target.value))}
                className="w-24 accent-orange-500 h-1.5 bg-[#262626] rounded-lg cursor-pointer"
              />
              <span className="font-mono text-orange-400 font-bold min-w-[28px] text-right">{hotSpotThreshold}</span>
            </div>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Side-by-side container for Sidebar + Graph Canvas */}
        <div id="attack-graph-container" ref={containerRef} className="xl:col-span-2 bg-[#0A0A0A] border border-[#262626] rounded-lg overflow-hidden min-h-[400px] flex flex-col md:flex-row relative">
          
          {/* Integrated Filtering Sidebar */}
          <div className="w-full md:w-60 bg-[#0C0C0C] border-b md:border-b-0 md:border-r border-[#262626] p-4 flex flex-col shrink-0 select-none z-10">
            <div className="flex items-center gap-2 mb-3 pb-2 border-b border-[#262626]/80 text-[#E5E5E5]">
              <Layers className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-semibold uppercase tracking-wider font-sans">Node Type Filters</span>
            </div>
            
            <p className="text-[11px] text-gray-400 leading-relaxed mb-4 font-sans">
              Toggle specific node visibility (e.g., EC2, IAM, S3 storage) to isolate threat vectors and simplify the graph representation.
            </p>
            
            <div className="space-y-2 max-h-[280px] overflow-y-auto pr-1">
              {availableNodeTypes.map(type => {
                const isChecked = !disabledTypes.includes(type);
                const info = getNodeTypeLabelAndDesc(type);
                const color = getNodeColor(type);
                
                return (
                  <label 
                    key={type} 
                    className={`flex items-start gap-2.5 p-2 rounded-lg border transition-all cursor-pointer ${
                      isChecked 
                        ? 'bg-black/50 border-[#262626] hover:bg-black/80' 
                        : 'bg-black/25 border-dashed border-[#1a1a1a] opacity-50 hover:bg-black/40'
                    }`}
                  >
                    <input 
                      type="checkbox"
                      checked={isChecked}
                      onChange={() => {
                        if (isChecked) {
                          setDisabledTypes([...disabledTypes, type]);
                        } else {
                          setDisabledTypes(disabledTypes.filter(t => t !== type));
                        }
                      }}
                      className="mt-1 accent-cyan-500 w-3.5 h-3.5 rounded border-gray-700 font-sans cursor-pointer"
                    />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5">
                        <span 
                          className="w-2 h-2 rounded-full shrink-0 animate-pulse" 
                          style={{ backgroundColor: color }}
                        />
                        <span className="text-[11px] font-semibold text-gray-200 truncate leading-none">
                          {info.name}
                        </span>
                      </div>
                      <span className="text-[9px] text-gray-500 font-mono block mt-1">
                        {info.desc}
                      </span>
                    </div>
                  </label>
                );
              })}
            </div>

            {disabledTypes.length > 0 && (
              <button
                onClick={() => setDisabledTypes([])}
                className="mt-4 w-full py-1.5 border border-[#262626] bg-[#141414] hover:bg-[#1C1C1C] text-[10px] text-cyan-400 font-mono rounded transition-all uppercase font-bold"
              >
                Reset Filters
              </button>
            )}
          </div>

          {/* Graph view Area */}
          <div className="flex-1 relative flex items-center justify-center p-2 min-h-[350px]">
            {/* Legend block */}
            <div className="absolute top-4 left-4 text-xs font-mono text-gray-500 uppercase tracking-widest bg-[#0F0F0F]/90 border border-[#262626] px-2.5 py-1 rounded z-10 backdrop-blur-sm shadow-md">
              Graph Topology Model: Neo4j Node Relations
            </div>

            {filteredNodes.length > 0 ? (
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
                {filteredEdges.map((edge, idx) => {
                  const srcNode = filteredNodes.find(n => n.id === edge.source);
                  const tgtNode = filteredNodes.find(n => n.id === edge.target);
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
                {filteredNodes.map((node) => {
                  const worksAsSelected = selectedNode?.id === node.id;
                  const nodeColor = getNodeColor(node.type);

                  // Calculated high value metrics using our D3 ruleset
                  const hotSpotScore = getHotSpotScore(node);
                  const hasGlow = hotSpotEnabled && (hotSpotScore >= hotSpotThreshold);
                  const glowColor = glowColorScale(hotSpotScore);
                  const glowRadius = glowRadiusScale(hotSpotScore);
                  const glowOpacity = glowOpacityScale(hotSpotScore);

                  return (
                    <g
                      key={node.id}
                      className="cursor-pointer group transition-all"
                      onClick={() => setSelectedNode(node)}
                      onMouseEnter={(e) => {
                        setHoveredNode(node);
                        updateMousePos(e);
                      }}
                      onMouseMove={updateMousePos}
                      onMouseLeave={() => setHoveredNode(null)}
                    >
                      {/* Interactive Hot Spot D3.js Glow Layer (Glows brighter based on path count & severity) */}
                      {hasGlow && (
                        <g>
                          {/* Secondary soft pulsating outline halo */}
                          <circle
                            cx={node.cx} cy={node.cy}
                            r={glowRadius + 6}
                            fill="none"
                            stroke={glowColor}
                            strokeWidth={6}
                            strokeOpacity={glowOpacity * 0.3}
                            className="animate-pulse"
                          />
                          {/* Primary core background heatmap halo */}
                          <circle
                            cx={node.cx} cy={node.cy}
                            r={glowRadius}
                            fill={glowColor}
                            fillOpacity={glowOpacity * 0.15}
                            stroke={glowColor}
                            strokeWidth={2}
                            strokeOpacity={glowOpacity * 0.75}
                          />
                        </g>
                      )}

                      {/* Standard Outer Selection Ring (styled conditionally based on glow status) */}
                      <circle
                        cx={node.cx} cy={node.cy}
                        r={worksAsSelected ? 24 : (hasGlow ? glowRadius - 3 : 18)}
                        fill="transparent"
                        stroke={hasGlow ? glowColor : nodeColor}
                        strokeWidth={hasGlow ? 3 : 2}
                        strokeOpacity={worksAsSelected ? 1 : 0.25}
                        className="group-hover:stroke-opacity-100 transition-all font-sans"
                      />
                      {/* Solid background Node circle */}
                      <circle
                        cx={node.cx} cy={node.cy}
                        r={worksAsSelected ? 18 : 14}
                        fill="#0F0F0F"
                        stroke={hasGlow ? glowColor : nodeColor}
                        strokeWidth={worksAsSelected ? 3 : 2}
                      />
                      {/* Inside Indicator */}
                      <text
                        x={node.cx} y={node.cy + 4}
                        textAnchor="middle"
                        fontSize="10"
                        fill={hasGlow ? glowColor : '#FFFFFF'}
                        fontFamily="sans-serif"
                        fontWeight="bold"
                      >
                        {node.type.substring(0, 2)}
                      </text>

                      {/* High-Readability Permanent Service & Event Label Badge Block */}
                      {(() => {
                        const labelText = node.label;
                        const badgeWidth = Math.max(130, Math.min(180, labelText.length * 6.5 + 20));
                        const badgeHeight = 36;
                        const badgeY = node.cy + 24;
                        const typeLabel = node.type.replace('_', ' ');

                        return (
                          <g className="select-none pointer-events-none">
                            {/* Shadow/Glow under-rect */}
                            <rect
                              x={node.cx - badgeWidth / 2}
                              y={badgeY}
                              width={badgeWidth}
                              height={badgeHeight}
                              rx={6}
                              ry={6}
                              fill="#090909"
                              fillOpacity={0.95}
                              stroke={worksAsSelected ? '#FFFFFF' : (hasGlow ? glowColor : '#262626')}
                              strokeWidth={worksAsSelected ? 2 : (hasGlow ? 1.5 : 1)}
                              className="transition-all duration-300"
                            />
                            {/* Left solid indicator accent line */}
                            <rect
                              x={node.cx - badgeWidth / 2}
                              y={badgeY + 4}
                              width={3}
                              height={badgeHeight - 8}
                              rx={1.5}
                              fill={hasGlow ? glowColor : nodeColor}
                            />
                            {/* Service Type Label */}
                            <text
                              x={node.cx + 2}
                              y={badgeY + 14}
                              textAnchor="middle"
                              fontSize="8px"
                              fontFamily="monospace"
                              fontWeight="bold"
                              letterSpacing="0.5px"
                              fill={hasGlow ? glowColor : nodeColor}
                              fillOpacity={0.9}
                              className="uppercase font-mono"
                            >
                              {typeLabel}
                            </text>
                            {/* Event Identity/Name */}
                            <text
                              x={node.cx + 2}
                              y={badgeY + 26}
                              textAnchor="middle"
                              fontSize="9.5px"
                              fontFamily="sans-serif"
                              fontWeight="semibold"
                              fill={worksAsSelected ? '#FFFFFF' : '#cccccc'}
                            >
                              {labelText.length > 25 ? labelText.substring(0, 23) + '...' : labelText}
                            </text>
                          </g>
                        );
                      })()}
                    </g>
                  );
                })}
              </svg>
            ) : (
              <div className="text-center p-8 text-gray-500 text-xs flex flex-col items-center justify-center gap-3 font-sans select-none min-h-[300px]">
                <Layers className="w-10 h-10 text-gray-600 animate-pulse" />
                <span className="font-semibold text-gray-300">All Layers Filtered Out</span>
                <span className="text-[11px] text-gray-400 max-w-[280px]">
                  Select at least one active service or entity layer in the sidebar to plot.
                </span>
              </div>
            )}

            {/* Interactive Holographic Floating Tooltip Layer */}
            {hoveredNode && (() => {
              const hotSpotScore = getHotSpotScore(hoveredNode);
              const glowColor = glowColorScale(hotSpotScore);
              const matchedEvents = getAssociatedEvents(hoveredNode);
              const peakEvent = matchedEvents[0]; 

              return (
                <div 
                  className="absolute pointer-events-none bg-[#0a0a0ae6] border border-[#262626] rounded-xl p-3.5 shadow-2xl z-50 text-white w-72 backdrop-blur-md transition-all duration-75 ease-out"
                  style={{
                    left: `${mousePos.x}px`,
                    top: `${mousePos.y}px`,
                    transform: `translate(${mousePos.x > 450 ? '-105%' : '15px'}, ${mousePos.y > 170 ? '-105%' : '15px'})`,
                  }}
                >
                  {/* Node type tag & label */}
                  <div className="flex items-center gap-2 mb-2 pb-2 border-b border-[#262626]/85">
                    <div className="p-1 px-1.5 rounded text-[10px] font-mono font-black uppercase text-black" style={{ backgroundColor: glowColor }}>
                      {hoveredNode.type}
                    </div>
                    <span className="font-sans font-bold text-xs truncate max-w-[170px]" style={{ color: glowColor }}>
                      {hoveredNode.label}
                    </span>
                  </div>

                  {/* Subtitle / Description */}
                  <div className="text-[11px] text-gray-300 leading-normal mb-3 font-sans">
                    {hoveredNode.description}
                  </div>

                  {/* Risk and Criticality Metrics HUD */}
                  <div className="space-y-2 bg-[#0F0F0F] border border-[#262626]/60 p-2.5 rounded-lg text-[10px] mb-3">
                    <div className="flex justify-between items-center">
                      <span className="text-gray-400">Threat Level:</span>
                      <span className="font-bold uppercase" style={{ color: glowColor }}>
                        {hoveredNode.threatLevel}
                      </span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-gray-400">Interconnections:</span>
                      <span className="font-bold text-gray-255">
                        {getConnectedCount(hoveredNode.id)} attack path{getConnectedCount(hoveredNode.id) === 1 ? '' : 's'}
                      </span>
                    </div>
                    <div>
                      <div className="flex justify-between items-center mb-1">
                        <span className="text-gray-400">Heat Index:</span>
                        <span className="font-bold font-mono" style={{ color: glowColor }}>
                          {hotSpotScore}/100
                        </span>
                      </div>
                      <div className="w-full bg-[#1b1b1b] rounded-full h-1.5 overflow-hidden">
                        <div 
                          className="h-full rounded-full transition-all duration-300" 
                          style={{ 
                            width: `${hotSpotScore}%`,
                            backgroundColor: glowColor
                          }}
                        />
                      </div>
                    </div>
                  </div>

                  {/* Forensics Event Correlation Metadata */}
                  <div>
                    <span className="text-[9px] font-mono uppercase text-gray-400 tracking-wider block mb-1 font-bold">
                      Correlated CloudTrail Logs ({matchedEvents.length})
                    </span>
                    {peakEvent ? (
                      <div className="bg-[#141414]/90 p-2 rounded border border-[#262626] font-mono text-[9px] space-y-1">
                        <div className="flex justify-between text-gray-300 font-bold truncate">
                          <span>Event:</span>
                          <span className="text-cyan-400 truncate max-w-[140px]">{peakEvent.eventName}</span>
                        </div>
                        <div className="flex justify-between text-gray-400">
                          <span>Source:</span>
                          <span className="text-gray-200 truncate max-w-[130px]">{peakEvent.eventSource}</span>
                        </div>
                        <div className="flex justify-between text-gray-400">
                          <span>Timestamp:</span>
                          <span className="text-gray-200">{peakEvent.eventTime.substring(11, 19)} UTC</span>
                        </div>
                        <div className="flex justify-between text-gray-400 text-[8px] pt-1">
                          <span>Anomaly Score:</span>
                          <span className={peakEvent.anomalyScore > 0.6 ? "text-red-400 font-bold" : "text-amber-400"}>
                            {(peakEvent.anomalyScore * 100).toFixed(0)}% Match
                          </span>
                        </div>
                      </div>
                    ) : (
                      <div className="text-center py-1.5 bg-[#141414] rounded border border-[#262626] text-[9px] text-gray-500 font-mono">
                        No active logs match signature
                      </div>
                    )}
                  </div>
                </div>
              );
            })()}
          </div>
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

                {/* Risk and Criticality info */}
                <div className="flex justify-between items-center text-xs">
                  <span className="text-gray-500 font-sans">Anomalous Risk Severity:</span>
                  <span className={`px-2 py-0.5 rounded-full font-sans font-bold text-[10px] ${
                    selectedNode.threatLevel === 'Critical' ? 'bg-red-500/10 text-red-400 border border-red-900/30' :
                    selectedNode.threatLevel === 'High' ? 'bg-orange-500/10 text-orange-400 border border-orange-950/30' :
                    'bg-[#0A0A0A] text-gray-300 border border-[#262626]'
                  }`}>
                    {selectedNode.threatLevel}
                  </span>
                </div>

                {/* Live D3 Hot Spot Scoring Meter with Heat Index */}
                <div className="bg-black/30 border border-[#262626]/60 p-3.5 rounded-lg text-xs leading-relaxed mt-1">
                  <div className="flex items-center gap-2 mb-2 font-semibold text-gray-300">
                    <Flame className="w-4 h-4 text-orange-400" />
                    <span>D3 Hot-Spot Assessment</span>
                  </div>
                  <div className="grid grid-cols-2 gap-2 mt-2 text-[11px] font-mono">
                    <div className="bg-[#141414] p-2 border border-[#262626] rounded">
                      <span className="text-gray-550 block text-[9px] uppercase">Criticality Weight</span>
                      <span className="text-gray-200 block font-bold mt-1">
                        {getThreatWeight(selectedNode.threatLevel)} / 4
                      </span>
                    </div>
                    <div className="bg-[#141414] p-2 border border-[#262626] rounded">
                      <span className="text-gray-550 block text-[9px] uppercase font-sans">Connected Paths</span>
                      <span className="text-gray-200 block font-bold mt-1">
                        {getConnectedCount(selectedNode.id)} paths
                      </span>
                    </div>
                  </div>
                  <div className="mt-3">
                    <div className="flex justify-between text-[11px] mb-1">
                      <span className="text-gray-400">Aggregated Heat Score:</span>
                      <span className="font-bold font-mono text-cyan-400">
                        {getHotSpotScore(selectedNode)} / 100
                      </span>
                    </div>
                    {/* Visual gradient heat meter using interpolated D3 color scale */}
                    <div className="w-full bg-[#141414] rounded-full h-2 overflow-hidden border border-[#262626]">
                      <div 
                        className="h-full rounded-full transition-all duration-500" 
                        style={{ 
                          width: `${getHotSpotScore(selectedNode)}%`,
                          backgroundColor: glowColorScale(getHotSpotScore(selectedNode))
                        }}
                      />
                    </div>
                  </div>
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
            <div className="bg-black/40 border border-[#262626] p-2.5 rounded text-[10px] text-gray-500 font-mono flex items-start gap-1.5 leading-relaxed">
              <span>*</span>
              <span>Visual mapping implements predictive security heuristics: correlating lateral pivoting over identical credential IDs and session ARNs.</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
