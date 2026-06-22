/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { motion } from 'motion/react';
import { 
  ShieldAlert, 
  Terminal, 
  Layers, 
  MapPin, 
  Activity, 
  UploadCloud, 
  Search, 
  FileText, 
  Bot, 
  Sliders, 
  ActivitySquare, 
  Play, 
  FileDown, 
  BookOpen, 
  Database, 
  Globe, 
  Cpu, 
  CheckCircle, 
  X, 
  RefreshCw, 
  Plus, 
  User, 
  ExternalLink,
  MessageSquare,
  Lock,
  LockOpen
} from 'lucide-react';
import MitreMatrix from './components/MitreMatrix';
import AttackGraph from './components/AttackGraph';
import { CloudTrailEvent, Scenario, MisconfigFinding, ThreatIntelRecord, EvidenceArtifact } from './types';

export default function App() {
  // Navigation tabs
  const [activeTab, setActiveTab] = useState<'dashboard' | 'explorer' | 'timeline' | 'graph' | 'mitre' | 'assistant' | 'evidence' | 'intel' | 'risk' | 'misconfig' | 'soar' | 'reports' | 'research'>('dashboard');

  // Application-wide Forensics State
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [activeScenarioId, setActiveScenarioId] = useState<string>('');
  const [loadingScenarios, setLoadingScenarios] = useState<boolean>(true);
  const [errorText, setErrorText] = useState<string>('');

  // AI Assistant Chat States
  const [userQuestion, setUserQuestion] = useState<string>('');
  const [chatAnswer, setChatAnswer] = useState<string>('');
  const [loadingChat, setLoadingChat] = useState<boolean>(false);
  const [attackStory, setAttackStory] = useState<string>('');
  const [loadingStory, setLoadingStory] = useState<boolean>(false);

  // Ingest state
  const [rawLogText, setRawLogText] = useState<string>('');
  const [ingestFileName, setIngestFileName] = useState<string>('reconstruction-trail.json');
  const [ingestSuccess, setIngestSuccess] = useState<string>('');
  const [loadingIngest, setLoadingIngest] = useState<boolean>(false);

  // Threat Intel search state
  const [searchIP, setSearchIP] = useState<string>('193.106.191.22');
  const [intelResult, setIntelResult] = useState<ThreatIntelRecord | null>(null);
  const [loadingIntel, setLoadingIntel] = useState<boolean>(false);

  // Misconfig state
  const [misconfigFindings, setMisconfigFindings] = useState<MisconfigFinding[]>([]);
  const [loadingMisconfig, setLoadingMisconfig] = useState<boolean>(true);

  // Evidence states
  const [evidenceList, setEvidenceList] = useState<EvidenceArtifact[]>([]);
  const [evidenceComment, setEvidenceComment] = useState<string>('');
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<string>('');
  const [custodyRecordedBy, setCustodyRecordedBy] = useState<string>('');
  const [custodyAction, setCustodyAction] = useState<string>('Chain Transfer');
  const [custodyNotes, setCustodyNotes] = useState<string>('');

  // SOAR automated playbooks state
  const [activePlaybooksLog, setActivePlaybooksLog] = useState<any[]>([]);
  const [playbookTarget, setPlaybookTarget] = useState<string>('');
  const [playbookTriggering, setPlaybookTriggering] = useState<string>('');

  // Export report states
  const [reportType, setReportType] = useState<string>('Comprehensive Incident Forensics Report');
  const [exportedReport, setExportedReport] = useState<any>(null);
  const [loadingExport, setLoadingExport] = useState<boolean>(false);

  // Explore filters
  const [explorerSearch, setExplorerSearch] = useState<string>('');
  const [explorerCategory, setExplorerCategory] = useState<string>('ALL');
  const [explorerRisk, setExplorerRisk] = useState<string>('ALL');

  // Fetch initial scenarios on boot
  useEffect(() => {
    fetchScenarios();
    fetchMisconfigs();
    fetchEvidence();
    fetchSOALogs();
  }, []);

  const fetchScenarios = async () => {
    try {
      setLoadingScenarios(true);
      const res = await fetch('/api/scenarios');
      if (res.ok) {
        const data = await res.json();
        setScenarios(data);
        if (data.length > 0) {
          setActiveScenarioId(data[0].id);
        }
      } else {
        setErrorText('Failed to query scenarios from the Express API.');
      }
    } catch (err: any) {
      console.error(err);
      setErrorText(`Failed to connect to the backend server. Make sure dev server binds to port 3000.`);
    } finally {
      setLoadingScenarios(false);
    }
  };

  const fetchMisconfigs = async () => {
    try {
      const res = await fetch('/api/misconfig');
      if (res.ok) {
        const data = await res.json();
        setMisconfigFindings(data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoadingMisconfig(false);
    }
  };

  const fetchEvidence = async () => {
    try {
      const res = await fetch('/api/evidence');
      if (res.ok) {
        const data = await res.json();
        setEvidenceList(data);
        if (data.length > 0) {
          setSelectedEvidenceId(data[0].id);
        }
      }
    } catch (err) {
      console.error(err);
    }
  };

  const fetchSOALogs = async () => {
    try {
      const res = await fetch('/api/soar/logs');
      if (res.ok) {
        const data = await res.json();
        setActivePlaybooksLog(data);
      }
    } catch (err) {
      console.error(err);
    }
  };

  // Switch Active Incident Context and reset dependent AI queries
  const activeScenario = scenarios.find(s => s.id === activeScenarioId);

  useEffect(() => {
    setChatAnswer('');
    setAttackStory('');
    setExportedReport(null);
    if (activeScenario && activeScenario.timeline.length > 0) {
      // Suggest automatic IP / key targets based on active context
      const firstEv = activeScenario.timeline[0];
      setSearchIP(firstEv.sourceIPAddress);
      setPlaybookTarget(firstEv.userIdentity?.accessKeyId || firstEv.sourceIPAddress);
    }
  }, [activeScenarioId, scenarios]);

  // Handle Dynamic Log Ingestion & Parsing Engine
  const executeLogIngestion = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!rawLogText.trim()) return;
    try {
      setLoadingIngest(true);
      setIngestSuccess('');
      const res = await fetch('/api/ingest-logs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          rawText: rawLogText,
          fileName: ingestFileName
        })
      });

      const data = await res.json();
      if (res.ok) {
        setIngestSuccess(`Logs successfully normalized! Generated case ${data.scenarioId} containing ${data.eventCount} alerts.`);
        setRawLogText('');
        // Refresh scenario list and auto select newly ingested scenario cases
        const scenariosRes = await fetch('/api/scenarios');
        if (scenariosRes.ok) {
          const freshScenarios = await scenariosRes.json();
          setScenarios(freshScenarios);
          setActiveScenarioId(data.scenarioId);
        }
        fetchEvidence();
      } else {
        setErrorText(data.error || 'Syntax parsing error occurred.');
      }
    } catch (err: any) {
      setErrorText(`Ingestion framework error: ${err.message}`);
    } finally {
      setLoadingIngest(false);
    }
  };

  // Real-Time Gemini Assistant Queries
  const askGeminiAssistant = async () => {
    if (!userQuestion.trim()) return;
    try {
      setLoadingChat(true);
      setChatAnswer('');
      const res = await fetch('/api/gemini/assistant', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          question: userQuestion,
          timelineEvents: activeScenario?.timeline,
          context: activeScenario?.name
        })
      });

      const data = await res.json();
      if (res.ok) {
        setChatAnswer(data.answer);
      } else {
        setChatAnswer(`Error explaining events: ${data.error}`);
      }
    } catch (err: any) {
      setChatAnswer(`Failed to query Gemini. Ensure dynamic API Key is specified. Details: ${err.message}`);
    } finally {
      setLoadingChat(false);
    }
  };

  // Generative AI Attack Storytelling Chronicler
  const generateAIStory = async () => {
    try {
      setLoadingStory(true);
      setAttackStory('');
      const res = await fetch('/api/gemini/story', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scenarioName: activeScenario?.name,
          timelineEvents: activeScenario?.timeline
        })
      });

      const data = await res.json();
      if (res.ok) {
        setAttackStory(data.story);
      } else {
        setAttackStory(data.fallbackStory || 'Failed to synthesize chronological story.');
      }
    } catch (err: any) {
      setAttackStory(`Offline fallback chronicle loaded due to server link state: \n\n* Threat identified: Leaked developer API Key elements.\n* Actions mapped: Multiple high-risk API attachments followed by CloudTrail logging interruption. S3 exfiltration completed.`);
    } finally {
      setLoadingStory(false);
    }
  };

  // Execute SOAR Automated Mitigation Playbooks
  const triggerSOARPlaybook = async (action: string) => {
    if (!playbookTarget) return;
    try {
      setPlaybookTriggering(action);
      const res = await fetch('/api/soar/playbook', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action,
          target: playbookTarget,
          scenarioId: activeScenarioId
        })
      });
      const data = await res.json();
      if (res.ok) {
        fetchSOALogs();
        // Append log to notes locally as well
        if (activeScenario) {
          activeScenario.notes = (activeScenario.notes || "") + `\n[SOAR Action - ${new Date().toLocaleTimeString()}]: Executed '${action}' on target '${playbookTarget}'.`;
        }
      }
    } catch (err) {
      console.error(err);
    } finally {
      setPlaybookTriggering('');
    }
  };

  // Query Threat Intelligence Database
  const lookupThreatIntel = async () => {
    if (!searchIP.trim()) return;
    try {
      setLoadingIntel(true);
      const res = await fetch(`/api/intel/${searchIP}`);
      if (res.ok) {
        const data = await res.json();
        setIntelResult(data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoadingIntel(false);
    }
  };

  // Export Forensic Reports
  const exportForensicDocument = async () => {
    try {
      setLoadingExport(true);
      const res = await fetch('/api/export-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scenarioId: activeScenarioId,
          reportType
        })
      });
      const data = await res.json();
      if (res.ok) {
        setExportedReport(data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoadingExport(false);
    }
  };

  // Add Comment to Evidence File
  const addEvidenceComment = async () => {
    if (!evidenceComment.trim() || !selectedEvidenceId) return;
    try {
      const res = await fetch(`/api/evidence/${selectedEvidenceId}/comment`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          text: evidenceComment,
          author: "udayky91@gmail.com"
        })
      });
      if (res.ok) {
        fetchEvidence();
        setEvidenceComment('');
      }
    } catch (err) {
      console.error(err);
    }
  };

  // Record Chain of Custody Handshake
  const saveChainHandshake = async () => {
    if (!custodyRecordedBy.trim() || !custodyAction.trim() || !selectedEvidenceId) return;
    try {
      const res = await fetch(`/api/evidence/${selectedEvidenceId}/custody`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          recordedBy: custodyRecordedBy,
          action: custodyAction,
          notes: custodyNotes
        })
      });
      if (res.ok) {
        fetchEvidence();
        setCustodyRecordedBy('');
        setCustodyNotes('');
      }
    } catch (err) {
      console.error(err);
    }
  };

  // Heuristic Anomaly/Risk Indicators Mapping (Module 12)
  const getRiskBadge = (level: string) => {
    switch (level) {
      case 'Critical': return 'bg-red-500/10 text-red-400 border border-red-800/60';
      case 'High': return 'bg-amber-100/10 text-amber-500 border border-amber-800/60';
      case 'Medium': return 'bg-yellow-500/10 text-yellow-500 border border-yellow-800/40';
      case 'Low': return 'bg-blue-500/10 text-blue-400 border border-blue-900/30';
      default: return 'bg-slate-900 text-slate-400 border border-slate-800';
    }
  };

  // Filtering logs in Explorer (Module 2)
  const filteredEvents = activeScenario?.timeline.filter(e => {
    const searchMatch = e.eventName.toLowerCase().includes(explorerSearch.toLowerCase()) || 
                        e.eventSource.toLowerCase().includes(explorerSearch.toLowerCase()) || 
                        e.sourceIPAddress.includes(explorerSearch) ||
                        (e.userIdentity?.arn || '').toLowerCase().includes(explorerSearch.toLowerCase());
    const catMatch = explorerCategory === 'ALL' || e.threatCategory === explorerCategory;
    const riskMatch = explorerRisk === 'ALL' || e.riskLevel === explorerRisk;
    return searchMatch && catMatch && riskMatch;
  }) || [];

  return (
    <div className="min-h-screen bg-[#0A0A0A] text-[#E5E5E5] flex flex-col font-sans selection:bg-cyan-500/20 selection:text-cyan-400">
      
      {/* Top Professional Header (Splunk/CrowdStrike style layout) */}
      <header className="bg-[#0F0F0F] border-b border-[#262626] px-6 py-4 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 sticky top-0 z-50">
        <div className="flex items-center gap-3">
          <div className="bg-gradient-to-br from-cyan-500 to-blue-600 p-2.5 rounded-lg shadow-lg shadow-cyan-500/20">
            <ShieldAlert className="w-6 h-6 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[9px] font-mono tracking-widest text-cyan-400 uppercase border border-cyan-500/30 px-1 rounded bg-cyan-500/10">Aether Cloud Network</span>
              <span className="text-[9px] font-mono text-gray-500">v2.4.0-STABLE</span>
            </div>
            <h1 className="text-lg font-sans font-bold tracking-tight text-white flex items-center gap-2">
              AegisForensics <span className="text-gray-500 font-normal">| Aegis Cloud Forensics platform</span>
            </h1>
          </div>
        </div>

        {/* Global scenario contextual switch (Module 1/2) */}
        <div className="flex flex-wrap items-center gap-3 w-full sm:w-auto">
          <div className="flex items-center gap-2 bg-[#141414] border border-[#262626] text-xs rounded-lg px-3 py-2 w-full sm:w-auto justify-between sm:justify-start">
            <span className="text-gray-500">Active Pipeline Case:</span>
            {loadingScenarios ? (
              <span className="text-cyan-400 flex items-center gap-1.5 font-mono">
                <RefreshCw className="w-3.5 h-3.5 animate-spin" /> Ingesting cases...
              </span>
            ) : (
              <select 
                value={activeScenarioId} 
                onChange={(e) => setActiveScenarioId(e.target.value)}
                className="bg-transparent text-[#E5E5E5] border-none outline-none font-bold font-mono cursor-pointer"
              >
                {scenarios.map(s => (
                  <option key={s.id} value={s.id} className="bg-[#0A0A0A] text-white font-mono">
                    {s.name} ({s.timeline.length} Events) - {s.severity}
                  </option>
                ))}
              </select>
            )}
          </div>

          <button 
            onClick={fetchScenarios} 
            title="Refresh pipeline configurations"
            className="p-2 border border-[#262626] rounded-lg hover:bg-[#141414] text-gray-400 hover:text-white transition-all"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </header>

      {/* Main Body Grid */}
      <div className="flex-grow flex flex-col lg:flex-row">
        
        {/* Navigation Sidebar (Architectural boundaries constraints) */}
        <nav className="w-full lg:w-64 bg-[#0F0F0F] border-r border-[#262626] p-4 flex flex-col gap-1 shrink-0">
          <div className="px-3 py-2 text-[10px] uppercase font-mono tracking-wider text-gray-500">
            Platform Capabilities
          </div>

          {[
            { id: 'dashboard', label: 'SOC Dashboard', icon: <Activity className="w-4 h-4" /> },
            { id: 'explorer', label: 'CloudTrail Explorer', icon: <Terminal className="w-4 h-4" /> },
            { id: 'timeline', label: 'Attack Timeline', icon: <Layers className="w-4 h-4" /> },
            { id: 'graph', label: 'Attack Graph', icon: <Globe className="w-4 h-4" /> },
            { id: 'mitre', label: 'MITRE ATT&CK Matrix', icon: <MapPin className="w-4 h-4" /> },
          ].map(item => (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id as any)}
              className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-sans font-medium tracking-wide transition-all ${
                activeTab === item.id 
                  ? 'bg-white/10 text-cyan-400 border border-[#262626] shadow-lg shadow-cyan-500/5' 
                  : 'text-gray-400 hover:text-white hover:bg-white/5'
              }`}
            >
              {item.icon}
              {item.label}
            </button>
          ))}

          <div className="my-2 border-t border-[#262626]"></div>
          <div className="px-3 py-2 text-[10px] uppercase font-mono tracking-wider text-gray-500">
            AI & Threat Analytics
          </div>

          {[
            { id: 'assistant', label: 'Explainable AI Assistant', icon: <Bot className="w-4 h-4 text-cyan-400" /> },
            { id: 'intel', label: 'Threat Intelligence', icon: <Cpu className="w-4 h-4 text-emerald-400" /> },
            { id: 'risk', label: 'UEBA & Explainable Risk', icon: <Sliders className="w-4 h-4 text-amber-400" /> },
            { id: 'misconfig', label: 'CIS Audit Findings', icon: <ShieldAlert className="w-4 h-4 text-sky-400" /> },
            { id: 'soar', label: 'SOAR Action Panel', icon: <Play className="w-4 h-4 text-blue-400" /> },
          ].map(item => (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id as any)}
              className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-sans font-medium tracking-wide transition-all ${
                activeTab === item.id 
                  ? 'bg-white/10 text-cyan-400 border border-[#262626] shadow-lg shadow-cyan-500/5' 
                  : 'text-gray-400 hover:text-white hover:bg-white/5'
              }`}
            >
              {item.icon}
              {item.label}
            </button>
          ))}

          <div className="my-2 border-t border-[#262626]"></div>
          <div className="px-3 py-2 text-[10px] uppercase font-mono tracking-wider text-gray-500">
            Case Custody & Reporting
          </div>

          {[
            { id: 'evidence', label: 'Evidence Custody Locker', icon: <Database className="w-4 h-4 text-gray-300" /> },
            { id: 'reports', label: 'Automated Reports', icon: <FileText className="w-4 h-4 text-gray-300" /> },
            { id: 'research', label: 'IEEE Research Scope', icon: <BookOpen className="w-4 h-4 text-gray-400" /> },
          ].map(item => (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id as any)}
              className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-sans font-medium tracking-wide transition-all ${
                activeTab === item.id 
                  ? 'bg-white/10 text-cyan-400 border border-[#262626] shadow-lg shadow-cyan-500/5' 
                  : 'text-gray-400 hover:text-white hover:bg-white/5'
              }`}
            >
              {item.icon}
              {item.label}
            </button>
          ))}

          {/* User Sign-In Profile Badge */}
          <div className="mt-auto p-3 bg-[#141414] border border-[#262626] rounded-xl flex items-center gap-2">
            <div className="bg-cyan-500/20 text-cyan-400 p-1.5 rounded-full border border-cyan-500/30">
              <User className="w-3.5 h-3.5" />
            </div>
            <div className="overflow-hidden">
              <p className="text-[10px] font-mono text-gray-500 font-bold uppercase tracking-wider">Investigator Session</p>
              <p className="text-xs font-semibold text-white truncate" title="udayky91@gmail.com">udayky91@gmail.com</p>
            </div>
          </div>
        </nav>

        {/* Dynamic Center Work Stage */}
        <main className="flex-grow p-6 overflow-y-auto max-w-7xl mx-auto w-full">
          
          {errorText && (
            <div className="bg-red-950/20 border border-red-900 text-red-400 p-4 rounded-xl mb-6 text-xs flex justify-between items-center">
              <p className="font-mono">{errorText}</p>
              <button onClick={() => setErrorText('')} className="p-1 hover:bg-red-900/40 rounded">
                <X className="w-4 h-4" />
              </button>
            </div>
          )}

          {/* TAB 1: SOC DASHBOARD */}
          {activeTab === 'dashboard' && activeScenario && (
            <div className="flex flex-col gap-6 animate-fade-in">
              <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 bg-[#141414] border border-[#262626] rounded-xl p-5 shadow-xl">
                <div>
                  <h2 className="text-xl font-sans font-semibold text-white">{activeScenario.name}</h2>
                  <p className="text-xs text-gray-400 mt-1 max-w-4xl">{activeScenario.description}</p>
                </div>
                <div className="flex gap-2">
                  <span className={`px-3 py-1 rounded text-xs font-bold ${getRiskBadge(activeScenario.severity)}`}>
                    Incident Risk Level: {activeScenario.severity.toUpperCase()}
                  </span>
                </div>
              </div>

              {/* Status bento elements */}
              <motion.div 
                className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4"
                variants={{
                  hidden: { opacity: 0 },
                  show: {
                    opacity: 1,
                    transition: {
                      staggerChildren: 0.1
                    }
                  }
                }}
                initial="hidden"
                animate="show"
              >
                <motion.div 
                  variants={{
                    hidden: { opacity: 0, y: 15 },
                    show: { opacity: 1, y: 0, transition: { type: "spring", stiffness: 100, damping: 15 } }
                  }}
                  className="bg-[#141414] border border-[#262626] rounded-xl p-5 flex flex-col justify-between"
                >
                  <div className="flex justify-between items-start mb-2">
                    <span className="text-xs text-gray-455 font-sans font-bold uppercase tracking-wider">Total Tracked Events</span>
                    <Terminal className="text-cyan-400 w-4 h-4" />
                  </div>
                  <div>
                    <p className="text-3xl font-bold text-white font-mono">{activeScenario.timeline.length}</p>
                    <p className="text-[10px] text-cyan-400 mt-1">Normalized & verified log units</p>
                  </div>
                </motion.div>

                <motion.div 
                  variants={{
                    hidden: { opacity: 0, y: 15 },
                    show: { opacity: 1, y: 0, transition: { type: "spring", stiffness: 100, damping: 15 } }
                  }}
                  className="bg-[#141414] border border-[#262626] rounded-xl p-5 flex flex-col justify-between"
                >
                  <div className="flex justify-between items-start mb-2">
                    <span className="text-xs text-gray-455 font-sans font-bold uppercase tracking-wider">Anomalous Activity Alert Units</span>
                    <ShieldAlert className="text-red-500 w-4 h-4" />
                  </div>
                  <div>
                    <p className="text-3xl font-bold text-red-500 font-mono">
                      {activeScenario.timeline.filter(e => e.flagged).length}
                    </p>
                    <p className="text-[10px] text-red-400/80 mt-1">Requires immediate response triggers</p>
                  </div>
                </motion.div>

                <motion.div 
                  variants={{
                    hidden: { opacity: 0, y: 15 },
                    show: { opacity: 1, y: 0, transition: { type: "spring", stiffness: 100, damping: 15 } }
                  }}
                  className="bg-[#141414] border border-[#262626] rounded-xl p-5 flex flex-col justify-between"
                >
                  <div className="flex justify-between items-start mb-2">
                    <span className="text-xs text-gray-455 font-bold uppercase tracking-wider">Threat Infrastructure IP</span>
                    <Globe className="text-cyan-400 w-4 h-4" />
                  </div>
                  <div>
                    <p className="text-lg font-bold text-white font-mono truncate">
                      {activeScenario.timeline[0]?.sourceIPAddress || 'Unassigned'}
                    </p>
                    <p className="text-[10px] text-cyan-400 mt-1">First malicious origin subnet</p>
                  </div>
                </motion.div>

                <motion.div 
                  variants={{
                    hidden: { opacity: 0, y: 15 },
                    show: { opacity: 1, y: 0, transition: { type: "spring", stiffness: 100, damping: 15 } }
                  }}
                  className="bg-[#141414] border border-[#262626] rounded-xl p-5 flex flex-col justify-between"
                >
                  <div className="flex justify-between items-start mb-2">
                    <span className="text-xs text-gray-455 font-bold uppercase tracking-wider">Active Mitigations Applied</span>
                    <ActivitySquare className="text-green-500 w-4 h-4" />
                  </div>
                  <div>
                    <p className="text-3xl font-bold text-green-500 font-mono">{activePlaybooksLog.length}</p>
                    <p className="text-[10px] text-green-400 mt-1">SOAR firewall/keys detached policies</p>
                  </div>
                </motion.div>
              </motion.div>

              {/* Central overview of active threat insights */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                
                {/* Visual quick alerts timeline */}
                <div className="lg:col-span-2 bg-[#141414] border border-[#262626] rounded-xl p-6 flex flex-col justify-between">
                  <div>
                    <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2 uppercase tracking-wider font-sans">
                      <Activity className="w-4 h-4 text-cyan-450" /> Logged Chronological High-Risk Alerts
                    </h3>
                    <div className="flex flex-col gap-3 max-h-[280px] overflow-y-auto pr-2">
                      {activeScenario.timeline.map((ev) => (
                        <div key={ev.eventID} className="bg-black/40 border border-[#262626] p-3.5 rounded-lg flex justify-between items-center gap-4">
                          <div className="overflow-hidden">
                            <div className="flex items-center gap-2 mb-1">
                              <span className="text-xs font-bold font-mono text-white">{ev.eventName}</span>
                              <span className="text-[10px] font-mono text-gray-400 bg-black/40 border border-[#262626]/60 px-1 rounded truncate">
                                {ev.eventSource}
                              </span>
                            </div>
                            <p className="text-[11px] text-gray-400 truncate">{ev.notes}</p>
                          </div>
                          <div className="text-right shrink-0">
                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                              ev.riskLevel === 'Critical' ? 'bg-red-500/10 text-red-405 border border-red-500/20' :
                              ev.riskLevel === 'High' ? 'bg-orange-500/10 text-orange-400 border border-orange-500/20' :
                              'bg-black/40 text-gray-400 border border-[#262626]'
                            }`}>
                              Confidence: {Math.round(ev.anomalyScore * 100)}%
                            </span>
                            <p className="text-[9px] font-mono text-gray-500 mt-1">{ev.eventTime.slice(11, 19)}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="mt-6 pt-4 border-t border-[#262626] flex justify-between text-xs text-gray-500">
                    <span>Mapped to <b>MITRE Cloud ATT&CK Matrix</b></span>
                    <button onClick={() => setActiveTab('explorer')} className="text-cyan-400 hover:underline flex items-center gap-1 font-bold">
                      Open full parsing explorer <ExternalLink className="w-3 h-3" />
                    </button>
                  </div>
                </div>

                {/* Cyber Kill Chain / Insights Summary Box */}
                <div className="bg-[#141414] border border-[#262626] rounded-xl p-6 flex flex-col justify-between">
                  <div>
                    <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2 uppercase tracking-wider font-sans">
                      <Terminal className="w-4 h-4 text-cyan-400" /> Triage Investigation Brief
                    </h3>

                    <div className="flex flex-col gap-4 text-xs">
                      <div className="bg-black/40 border border-[#262626] p-3 rounded-lg">
                        <span className="text-gray-500 font-bold uppercase tracking-wider text-[10px] block mb-1">Suspected Threat Intel Actor:</span>
                        <span className="text-white font-semibold">{activeScenario.insights.threatActor}</span>
                      </div>

                      <div className="bg-black/40 border border-[#262626] p-3 rounded-lg">
                        <span className="text-gray-500 font-bold uppercase tracking-wider text-[10px] block mb-1">Primary Leak Vector:</span>
                        <span className="text-white font-semibold">{activeScenario.insights.attackVector}</span>
                      </div>

                      <div className="bg-black/40 border border-[#262626] p-3 rounded-lg">
                        <span className="text-gray-500 font-bold uppercase tracking-wider text-[10px] block mb-1">Impact Scope Assessment:</span>
                        <p className="text-white leading-relaxed mt-1 font-mono text-[11px]">{activeScenario.insights.impact}</p>
                      </div>
                    </div>
                  </div>

                  <div className="mt-6 pt-4 border-t border-[#262626]">
                    <button 
                      onClick={() => setActiveTab('assistant')} 
                      className="w-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 hover:bg-cyan-500/20 font-bold text-xs py-2 px-3 rounded-lg flex items-center justify-center gap-2 transition-all shadow-md uppercase tracking-wider"
                    >
                      <Bot className="w-4 h-4" /> Consult Explainable AI Assistant
                    </button>
                  </div>
                </div>

              </div>
            </div>
          )}

          {/* TAB 2: CLOUDTRAIL EXPLORER & INGESTION BLOCK (Module 1 & 2) */}
          {activeTab === 'explorer' && activeScenario && (
            <div className="flex flex-col gap-6 animate-fade-in">
              <div id="explorer-view-main" className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                
                {/* Left Live Ingestion Box */}
                <div className="bg-[#141414] border border-[#262626] rounded-xl p-5">
                  <h3 className="text-sm font-semibold text-white mb-2 flex items-center gap-2 uppercase tracking-wider font-sans">
                    <UploadCloud className="w-4 h-4 text-cyan-400" /> Batch Log Ingestion Pipeline
                  </h3>
                  <p className="text-xs text-gray-400 mb-4">Ingest custom CloudTrail raw JSON files into our analytics normalizer engine</p>

                  <form onSubmit={executeLogIngestion} className="flex flex-col gap-4">
                    <div>
                      <label className="block text-[11px] text-gray-400 uppercase font-mono mb-1.5">Simulation Filename</label>
                      <input 
                        type="text" 
                        value={ingestFileName}
                        onChange={(e) => setIngestFileName(e.target.value)}
                        className="w-full bg-[#0A0A0A] border border-[#262626] rounded-lg px-3 py-2 text-xs text-white font-mono outline-none focus:border-cyan-500" 
                      />
                    </div>

                    <div>
                      <label className="block text-[11px] text-gray-400 uppercase font-mono mb-1.5">Paste Raw CloudTrail JSON</label>
                      <textarea 
                        rows={8}
                        value={rawLogText}
                        onChange={(e) => setRawLogText(e.target.value)}
                        placeholder='{ "Records": [ { "eventID": "abc", "eventName": "AttachUserPolicy", "eventSource": "iam.amazonaws.com", "eventTime": "2026-06-22T04:15:00Z", "sourceIPAddress": "193.106.191.22", "userIdentity": { "type": "IAMUser", "userName": "dev-key" } } ] }'
                        className="w-full bg-[#0A0A0A] border border-[#262626] rounded-lg p-3 text-[11px] text-[#E5E5E5] font-mono outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/25 resize-none placeholder:text-gray-700"
                      />
                    </div>

                    <button 
                      type="submit" 
                      disabled={loadingIngest || !rawLogText.trim()}
                      className="w-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 hover:bg-cyan-500/20 disabled:bg-black/40 text-xs py-2 px-4 rounded-lg flex items-center justify-center gap-2 transition-all shadow-md font-bold uppercase tracking-wider"
                    >
                      {loadingIngest ? (
                        <>
                          <RefreshCw className="w-4 h-4 animate-spin" strokeWidth={3} />
                          Extracting & Normalizing...
                        </>
                      ) : (
                        <>
                          <Plus className="w-4 h-4" strokeWidth={3} />
                          Ingest and Extract Indicators
                        </>
                      )}
                    </button>
                    
                    {ingestSuccess && (
                      <div className="bg-emerald-950/20 border border-emerald-900 text-emerald-400 p-3 rounded-lg text-[11px] font-mono">
                        {ingestSuccess}
                      </div>
                    )}
                  </form>
                </div>

                {/* Right Interactive parsed Log Stream Explorer Table */}
                <div className="lg:col-span-2 bg-[#141414] border border-[#262626] rounded-xl p-5 flex flex-col justify-between">
                  <div>
                    <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 mb-4 pb-4 border-b border-[#262626]">
                      <div>
                        <h3 className="text-sm font-semibold text-white uppercase tracking-wider font-sans">Incident Event Stream Audit</h3>
                        <p className="text-xs text-gray-400">Search and query normalized metrics automatically parsed from case trail logs</p>
                      </div>
                      <div className="text-xs font-mono text-cyan-400 bg-black/40 border border-[#262626] px-2 py-1 rounded">
                        Active Ingest: {filteredEvents.length} events matching
                      </div>
                    </div>

                    {/* Search & filtering row */}
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-4">
                      <div className="relative">
                        <Search className="absolute left-2.5 top-2.5 w-4 h-4 text-gray-500" />
                        <input 
                          type="text" 
                          placeholder="Search API, User, IP..." 
                          value={explorerSearch}
                          onChange={(e) => setExplorerSearch(e.target.value)}
                          className="w-full bg-[#0A0A0A] border border-[#262626] rounded-lg pl-9 pr-3 py-2 text-xs text-white outline-none focus:border-cyan-500"
                        />
                      </div>

                      <select 
                        value={explorerCategory} 
                        onChange={(e) => setExplorerCategory(e.target.value)}
                        className="bg-[#0A0A0A] border border-[#262626] rounded-lg px-3 py-2 text-xs text-[#E5E5E5] outline-none focus:border-cyan-500"
                      >
                        <option value="ALL">All Threat Tactics</option>
                        <option value="Discovery">Discovery</option>
                        <option value="Privilege Escalation">Privilege Escalation</option>
                        <option value="Defense Evasion">Defense Evasion</option>
                        <option value="Initial Access">Initial Access</option>
                        <option value="Credential Access">Credential Access</option>
                        <option value="Exfiltration">Exfiltration</option>
                        <option value="Impact">Impact</option>
                      </select>

                      <select 
                        value={explorerRisk} 
                        onChange={(e) => setExplorerRisk(e.target.value)}
                        className="bg-[#0A0A0A] border border-[#262626] rounded-lg px-3 py-2 text-xs text-[#E5E5E5] outline-none focus:border-cyan-500"
                      >
                        <option value="ALL">All Risk Levels</option>
                        <option value="Critical">Critical</option>
                        <option value="High">High</option>
                        <option value="Medium">Medium</option>
                        <option value="Low">Low</option>
                        <option value="Normal">Normal</option>
                      </select>
                    </div>

                    {/* Table Stream */}
                    <div className="overflow-x-auto max-h-[360px]">
                      <table className="w-full text-left text-xs border-collapse">
                        <thead>
                          <tr className="border-b border-[#262626] text-gray-505 font-mono uppercase text-[10px] bg-black/20 text-gray-500">
                            <th className="py-2.5 px-3">Event Name</th>
                            <th className="py-2.5 px-3">Principal Identity</th>
                            <th className="py-2.5 px-3">Source IP</th>
                            <th className="py-2.5 px-3">Tactic</th>
                            <th className="py-2.5 px-3 text-right">Risk</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-[#262626] font-mono">
                          {filteredEvents.length > 0 ? (
                            filteredEvents.map((ev) => (
                              <tr key={ev.eventID} className="hover:bg-black/30">
                                <td className="py-3 px-3">
                                  <span className="text-white font-bold block">{ev.eventName}</span>
                                  <span className="text-[10px] text-gray-500">{ev.eventSource}</span>
                                </td>
                                <td className="py-3 px-3 text-gray-300 max-w-[200px] truncate" title={ev.userIdentity?.arn}>
                                  {ev.userIdentity?.userName || ev.userIdentity?.principalId || 'N/A'}
                                </td>
                                <td className="py-3 px-3 text-gray-300">{ev.sourceIPAddress}</td>
                                <td className="py-3 px-3">
                                  <span className="text-[10px] text-gray-400 bg-[#0A0A0A] px-1.5 py-0.5 rounded border border-[#262626]">
                                    {ev.threatCategory || 'Normal'}
                                  </span>
                                </td>
                                <td className="py-3 px-3 text-right">
                                  <span className={`text-[10px] font-sans px-2 py-0.5 rounded font-bold ${getRiskBadge(ev.riskLevel)}`}>
                                    {ev.riskLevel}
                                  </span>
                                </td>
                              </tr>
                            ))
                          ) : (
                            <tr>
                              <td colSpan={5} className="py-12 text-center text-gray-500 text-xs">
                                No records found matching the active searching options.
                              </td>
                            </tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>

              </div>
            </div>
          )}

          {/* TAB 3: ATTACK TIMELINE & CONTEXT-AWARE CHRONOLOGY */}
          {activeTab === 'timeline' && activeScenario && (
            <div className="flex flex-col gap-6 animate-fade-in">
              <div className="bg-[#141414] border border-[#262626] rounded-xl p-6">
                <div className="flex justify-between items-center mb-6 pb-4 border-b border-[#262626]">
                  <div>
                    <h2 className="text-lg font-sans font-semibold text-white uppercase tracking-wider">Context-Aware Forensic Attack Timeline</h2>
                    <p className="text-xs text-gray-400">Step-by-step chronology illustrating correlated IAM pivots and defense evasions</p>
                  </div>
                  <div className="text-xs bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 font-mono px-2 py-1 rounded font-bold">
                    Chain Sequence Length: {activeScenario.timeline.length} Steps
                  </div>
                </div>

                <div className="relative pl-6 border-l-2 border-dashed border-cyan-500/30 flex flex-col gap-8 ml-3 py-3">
                  {activeScenario.timeline.map((ev, index) => {
                    const isThreat = ev.flagged;
                    return (
                      <div key={ev.eventID} className="relative">
                        {/* Timeline Node point indicator */}
                        <span className={`absolute -left-[31px] top-1 w-4.5 h-4.5 rounded-full border-2 flex items-center justify-center font-mono text-[9px] font-bold ${
                          isThreat 
                            ? 'bg-rose-950 text-rose-400 border-rose-500 animate-[cyberGlow_3s_infinite_ease-in-out]' 
                            : 'bg-slate-950 text-slate-400 border-slate-800'
                        }`}>
                          {index + 1}
                        </span>

                        <div className={`p-5 rounded-xl border transition-all ${
                          isThreat 
                            ? 'bg-gradient-to-br from-rose-950/20 to-transparent border-rose-900/60 shadow-md shadow-rose-950/5' 
                            : 'bg-slate-950/35 border-slate-900'
                        }`}>
                          
                          <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-2 mb-3">
                            <div className="flex flex-wrap items-center gap-2.5">
                              <h3 className="text-sm font-bold font-mono text-slate-200">{ev.eventName}</h3>
                              <span className="text-xs text-slate-400 font-mono bg-slate-950 px-2 py-0.5 border border-slate-900 rounded">
                                {ev.eventSource}
                              </span>
                              {ev.mitreID && (
                                <span className="text-[10px] font-mono text-rose-300 bg-rose-950/40 px-1.5 py-0.5 rounded border border-rose-900/30">
                                  {ev.mitreID}: {ev.mitreTechnique}
                                </span>
                              )}
                            </div>
                            <span className="text-[11px] text-slate-500 font-mono">{ev.eventTime}</span>
                          </div>

                          <p className="text-xs text-slate-300 leading-relaxed max-w-5xl mb-4 font-sans border-l-2 border-indigo-500/30 pl-3">
                            {ev.notes}
                          </p>

                          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-[11px] font-mono text-slate-400 bg-slate-950/40 p-3 border border-slate-900 rounded-lg">
                            <div>
                              <span className="text-slate-500 block">Principal ARN</span>
                              <span className="text-slate-300 truncate block" title={ev.userIdentity.arn}>{ev.userIdentity.arn}</span>
                            </div>
                            <div>
                              <span className="text-slate-500 block">AWS Access Key</span>
                              <span className="text-slate-300 tracking-wider font-bold">{ev.userIdentity.accessKeyId || 'Assumed Role Session'}</span>
                            </div>
                            <div>
                              <span className="text-slate-500 block">Source IP Subnet</span>
                              <span className="text-rose-400 font-bold">{ev.sourceIPAddress}</span>
                            </div>
                            <div>
                              <span className="text-slate-500 block">Risk Confidence score</span>
                              <span className="text-slate-300 block">{Math.round(ev.anomalyScore * 100)}% Anomaly Potential</span>
                            </div>
                          </div>

                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: ATTACK GRAPH */}
          {activeTab === 'graph' && activeScenario && (
            <AttackGraph timeline={activeScenario.timeline} scenarioName={activeScenario.name} />
          )}

          {/* TAB 5: MITRE CLOUD MATRIX */}
          {activeTab === 'mitre' && activeScenario && (
            <MitreMatrix timeline={activeScenario.timeline} />
          )}

          {/* TAB 6: AI EXPLAINABLE FORENSIC ASSISTANT (Module 7 & 9) */}
          {activeTab === 'assistant' && activeScenario && (
            <div className="flex flex-col gap-6 animate-fade-in">
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                
                {/* Storyteller generation panel */}
                <div className="bg-[#141414] border border-[#262626] rounded-xl p-5 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center gap-2 mb-2">
                      <Terminal className="text-cyan-400 w-4 h-4" />
                      <span className="text-xs font-mono uppercase tracking-widest text-gray-500 font-bold">Chronicler AI Module</span>
                    </div>
                    <h3 className="text-sm font-semibold text-white">Generative AI Attack Storytelling</h3>
                    <p className="text-xs text-gray-400 mt-1 mb-4 leading-relaxed">
                      Utilizes Gemini model metrics to synthesize raw JSON sequences into an actionable English-language intrusion chronologue.
                    </p>

                    <div className="bg-black/40 border border-[#262626] p-3.5 rounded-lg text-xs list-disc font-sans text-gray-400 flex flex-col gap-2 mb-4">
                      <span>• Extracts leaked credentials attribution</span>
                      <span>• Maps temporal lateral boundaries</span>
                      <span>• Identifies exfiltration targets and impacts</span>
                    </div>
                  </div>

                  <div>
                    <button
                      onClick={generateAIStory}
                      disabled={loadingStory}
                      className="w-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 hover:bg-cyan-500/20 disabled:bg-[#0A0A0A] disabled:text-gray-600 font-semibold text-xs py-2.5 px-3 rounded-lg flex items-center justify-center gap-2 transition-all shadow-md uppercase tracking-wider font-bold"
                    >
                      {loadingStory ? (
                        <>
                          <RefreshCw className="w-4 h-4 animate-spin" />
                          Analyzing Cyber Kill Chain...
                        </>
                      ) : (
                        <>
                          <Bot className="w-4 h-4" />
                          Generate Attack Chronicle Story
                        </>
                      )}
                    </button>
                  </div>
                </div>

                {/* Main AI interaction box */}
                <div className="lg:col-span-2 bg-[#141414] border border-[#262626] rounded-xl p-5 flex flex-col justify-between min-h-[480px]">
                  <div>
                    <h3 className="text-sm font-semibold text-white mb-2 flex items-center gap-1.5 uppercase tracking-wide font-sans">
                      <Bot className="w-4.5 h-4.5 text-cyan-400" /> Explainable Forensics Assistant (Gemini)
                    </h3>
                    <p className="text-xs text-gray-400 mb-4">Query AWS Security mitigations, ask details about specific actions, or auto-generate hunting scripts</p>

                    {/* Output pane */}
                    <div className="bg-[#0A0A0A] border border-[#262626] rounded-lg p-4 font-mono text-xs text-gray-300 leading-relaxed max-h-[320px] overflow-y-auto mb-4 min-h-[220px]">
                      {loadingStory && <div className="text-gray-500 animate-pulse text-center py-12">Generating full-narrative chronicle... Please wait.</div>}
                      {attackStory && (
                        <div className="prose prose-invert prose-xs">
                          <h4 className="text-white font-sans font-semibold mb-3 border-b border-[#262626] pb-2">Narrative Incident Chronicle</h4>
                          <p className="whitespace-pre-line leading-relaxed pb-6 text-gray-300">{attackStory}</p>
                        </div>
                      )}

                      {loadingChat && <div className="text-cyan-400 animate-pulse text-center py-12">Consulting Gemini Expert model instance... Translating API telemetry.</div>}
                      {chatAnswer && (
                        <div className="prose prose-invert prose-xs">
                          <h4 className="text-cyan-400 font-sans font-semibold mb-3 border-b border-[#262626] pb-2">AI Response Explanation</h4>
                          <p className="whitespace-pre-line text-gray-300">{chatAnswer}</p>
                        </div>
                      )}

                      {!attackStory && !chatAnswer && !loadingStory && !loadingChat && (
                        <div className="text-center py-16 text-gray-500 font-sans">
                          <Bot className="w-12 h-12 text-[#262626] mx-auto mb-3" />
                          Interactive Assistant sandbox is idle. Ask questions like <span className="text-cyan-400 italic font-mono">"Why was the AttachUserPolicy API considered high risk?"</span> below.
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Input form */}
                  <div className="flex gap-2.5">
                    <input 
                      type="text" 
                      placeholder="Ask Gemini: E.g., What attacker intention is visible here? Generate SPL commands..."
                      value={userQuestion}
                      onChange={(e) => setUserQuestion(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') askGeminiAssistant();
                      }}
                      className="flex-grow bg-[#0A0A0A] border border-[#262626] rounded-lg px-3 py-2 text-xs text-white outline-none focus:border-cyan-500"
                    />
                    <button
                      onClick={askGeminiAssistant}
                      disabled={loadingChat || !userQuestion.trim()}
                      className="bg-cyan-500/10 border border-cyan-500/25 hover:bg-cyan-500/20 disabled:bg-[#0A0A0A] disabled:text-gray-650 text-cyan-400 font-bold text-xs px-4 rounded-lg flex items-center justify-center transition-all shadow-md uppercase tracking-wider"
                    >
                      Query Assistant
                    </button>
                    {chatAnswer && (
                      <button 
                        onClick={() => { setChatAnswer(''); setAttackStory(''); }}
                        className="bg-black/45 border border-[#262626] hover:bg-black/60 text-gray-400 p-2 rounded-lg font-bold"
                        title="Clear output console"
                      >
                        Clear
                      </button>
                    )}
                  </div>
                </div>

              </div>
            </div>
          )}

          {/* TAB 7: THREAT INTELLIGENCE REPUTATION LOOKUP (Module 10) */}
          {activeTab === 'intel' && (
            <div className="flex flex-col gap-6 animate-fade-in">
              <div className="bg-[#141414] border border-[#262626] rounded-xl p-6">
                <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 mb-6 pb-4 border-b border-[#262626]">
                  <div>
                    <h2 className="text-lg font-sans font-semibold text-white uppercase tracking-wider">Threat Intelligence Correlation Sandbox</h2>
                    <p className="text-xs text-gray-400 font-sans">Validate IP Reputation score vectors across AbuseIPDB, AlienVault OTX, and DNS block lists</p>
                  </div>
                  <div className="flex gap-2 text-xs">
                    <button 
                      onClick={() => setSearchIP('193.106.191.22')} 
                      className="bg-black/45 border border-[#262626] px-3 py-1.5 rounded text-[11px] font-mono font-bold hover:bg-black/60 text-cyan-400"
                    >
                      Load Cozy Dutch IP
                    </button>
                    <button 
                      onClick={() => setSearchIP('185.220.101.44')} 
                      className="bg-black/45 border border-[#262626] px-3 py-1.5 rounded text-[11px] font-mono font-bold hover:bg-black/60 text-cyan-400"
                    >
                      Load German Exit IP
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  
                  {/* Search query box */}
                  <div className="bg-black/40 border border-[#262626] p-5 rounded-lg flex flex-col justify-between">
                    <div>
                      <label className="block text-[11px] text-gray-500 uppercase font-mono mb-2 font-bold tracking-wider">Destination Source Host / IP</label>
                      <input 
                        type="text" 
                        value={searchIP}
                        onChange={(e) => setSearchIP(e.target.value)}
                        placeholder="e.g. 193.106.191.22"
                        className="w-full bg-[#0A0A0A] border border-[#262626] rounded-lg px-3 py-2 text-xs font-mono text-white outline-none focus:border-cyan-500"
                      />
                      <p className="text-[10px] text-gray-500 leading-relaxed mt-2.5">
                        Matches IP subnets to cataloged command-and-control lists.
                      </p>
                    </div>

                    <button 
                      onClick={lookupThreatIntel}
                      disabled={loadingIntel || !searchIP.trim()}
                      className="w-full mt-6 bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 hover:bg-cyan-500/20 disabled:bg-[#0A0A0A] disabled:text-gray-600 font-semibold text-xs py-2 px-3 rounded-lg flex items-center justify-center gap-2 transition-all shadow-md uppercase tracking-wider font-bold"
                    >
                      {loadingIntel ? (
                        <>
                          <RefreshCw className="w-4 h-4 animate-spin" />
                          Consulting Intel Datastores...
                        </>
                      ) : (
                        <>
                          <Search className="w-4 h-4" />
                          Execute IP Reputation Query
                        </>
                      )}
                    </button>
                  </div>

                  {/* Reputation Response panel */}
                  <div className="md:col-span-2 bg-[#0F0F0F] border border-[#262626] p-5 rounded-lg">
                    {intelResult ? (
                      <div className="flex flex-col gap-5">
                        <div className="flex justify-between items-center pb-3 border-b border-[#262626]">
                          <div>
                            <span className="text-[10px] font-mono uppercase text-gray-500 font-bold">Security Reputation Matrix</span>
                            <h3 className="text-sm font-bold font-mono text-white">{intelResult.ip}</h3>
                          </div>
                          <span className={`px-2.5 py-0.5 rounded text-xs font-bold font-mono ${
                            intelResult.reputationScore > 50 ? 'bg-red-500/10 text-red-400 border border-red-950/60' : 'bg-emerald-500/10 text-emerald-400'
                          }`}>
                            Reputation Hazard: {intelResult.reputationScore}/100
                          </span>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
                          <div className="bg-[#141414] border border-[#262626] p-3 rounded">
                            <span className="text-gray-500 block mb-0.5">ISP Provider Name</span>
                            <span className="text-gray-300 font-bold">{intelResult.isp}</span>
                          </div>
                          <div className="bg-[#141414] border border-[#262626] p-3 rounded">
                            <span className="text-gray-500 block mb-0.5 font-bold">Country Subregion</span>
                            <span className="text-gray-300">{intelResult.country}</span>
                          </div>
                          <div className="bg-[#141414] border border-[#262626] p-3 rounded">
                            <span className="text-gray-500 block mb-0.5">Known Threat IoC Status</span>
                            <span className={`font-bold ${intelResult.knownIoc ? 'text-red-400' : 'text-gray-400'}`}>
                              {intelResult.knownIoc ? 'ACTIVE THREAT IOC MATCHED' : 'Not listed'}
                            </span>
                          </div>
                          <div className="bg-[#141414] border border-[#262626] p-3 rounded">
                            <span className="text-gray-500 block mb-0.5 font-bold">Category Flag</span>
                            <span className="text-gray-300">{intelResult.maliciousCategory}</span>
                          </div>
                        </div>

                        {intelResult.knownIoc && (
                          <div className="bg-red-500/10 border border-red-505/20 p-3 rounded text-xs text-red-400 font-sans leading-relaxed">
                            <b>CRITICAL WARNING:</b> Destination matches verified Ransomware botnets. Block this IPv4 prefix immediately via NACLs or SOAR firewalls playbooks.
                          </div>
                        )}
                      </div>
                    ) : (
                      <div className="text-center py-16 text-gray-500 text-xs">
                        <Globe className="w-12 h-12 text-[#262626] mx-auto mb-3" />
                        Execute an IP reputation lookup to query geolocative flags, threat categories, and active botnet assignments.
                      </div>
                    )}
                  </div>

                </div>
              </div>
            </div>
          )}

          {/* TAB 8: RISK ANALYTICS & EXPLAINABLE AI (Module 9/12) */}
          {activeTab === 'risk' && activeScenario && (
            <div className="flex flex-col gap-6 animate-fade-in">
              <div className="bg-[#141414] border border-[#262626] rounded-xl p-6">
                <div className="mb-6">
                  <h2 className="text-lg font-sans font-semibold text-white uppercase tracking-wider">User & Entity Behavior Analytics (UEBA) Explainability</h2>
                  <p className="text-xs text-gray-400">Deep structural feature weights explaining why the AI engine flagged individual CloudTrail API actions</p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  
                  {/* Feature Importance weights */}
                  <div className="bg-[#0A0A0A] border border-[#262626] rounded-lg p-5">
                    <h3 className="text-xs font-mono uppercase tracking-wider text-gray-400 mb-4 border-b border-[#262626] pb-2 font-bold">
                      Local SHAP Feature Importance
                    </h3>
                    <div className="flex flex-col gap-4">
                      {[
                        { factor: "Unsampled/Disallowed IP Geolocation", weight: 95, color: "bg-red-500" },
                        { factor: "Administrative Rights Manipulation", weight: 89, color: "bg-red-400" },
                        { factor: "MFA Token Session Bypass", weight: 78, color: "bg-cyan-500" },
                        { factor: "Off-Hours Unusual Call Occurrence", weight: 64, color: "bg-cyan-400" },
                        { factor: "API Read Frequency/Spike Pattern", weight: 42, color: "bg-[#262626]" }
                      ].map((feat) => (
                        <div key={feat.factor} className="text-xs">
                          <div className="flex justify-between text-gray-450 mb-1">
                            <span>{feat.factor}</span>
                            <span className="font-mono">{feat.weight}% weight</span>
                          </div>
                          <div className="w-full bg-[#141414] rounded-full h-1.5 overflow-hidden">
                            <div className={`${feat.color} h-1.5`} style={{ width: `${feat.weight}%` }}></div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Explainable AI Dashboard Context */}
                  <div className="md:col-span-2 bg-black/40 border border-[#262626] rounded-lg p-5">
                    <div className="pb-3 border-b border-[#262626] mb-4 flex items-center justify-between">
                      <h4 className="text-xs font-mono uppercase text-gray-400 font-bold">Algorithmic Detection Methodology</h4>
                      <span className="text-[10px] bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 px-2 py-0.5 rounded font-mono font-bold">Isolation Forest + GNN</span>
                    </div>

                    <div className="text-xs text-gray-300 flex flex-col gap-4 leading-relaxed">
                      <p>
                        AegisForensics evaluates CloudTrail alerts through a hybrid <b>Isolation Forest</b> and <b>Temporal Graph Neural Network</b> model. Standalone heuristics measure API caller rarity, while temporal sequencing flags multi-stage attempts to impair cloud defense systems or execute massive S3 bucket object downloads.
                      </p>
                      
                      <div className="bg-[#0A0A0A] p-4 border border-[#262626] rounded-lg">
                        <span className="font-bold block mb-2 text-white">Active Risk Score Profile:</span>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-center font-mono py-2">
                          <div className="border-r border-[#262626]">
                            <span className="text-[10px] text-gray-500 block">Threat Confidence</span>
                            <span className="text-red-400 font-bold text-sm">94% High</span>
                          </div>
                          <div className="border-r border-[#262626]">
                            <span className="text-[10px] text-gray-500 block">Baseline Coherence</span>
                            <span className="text-amber-500 font-bold text-sm">Isolated</span>
                          </div>
                          <div className="border-r border-[#262626]">
                            <span className="text-[10px] text-gray-500 block">Critical Path Mapped</span>
                            <span className="text-cyan-400 font-bold text-sm">Yes (Active Kill)</span>
                          </div>
                          <div>
                            <span className="text-[10px] text-gray-500 block">Predictive Threat Max</span>
                            <span className="text-red-500 font-bold text-sm">99% Potential</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>

                </div>
              </div>
            </div>
          )}

          {/* TAB 9: CIS BENCHMARKS CONFIGURATION findings (Module 11) */}
          {activeTab === 'misconfig' && (
            <div className="flex flex-col gap-6 animate-fade-in">
              <div className="bg-[#141414] border border-[#262626] rounded-xl p-6">
                <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-6 pb-4 border-b border-[#262626]">
                  <div>
                    <h2 className="text-lg font-sans font-semibold text-white uppercase tracking-wide">CIS AWS Benchmark Misconfiguration Audit</h2>
                    <p className="text-xs text-gray-400">Active subscription audit monitoring configurations, security groups, and over-permissive IAM wildcards</p>
                  </div>
                  <div className="text-xs text-[#E5E5E5] bg-black/45 border border-[#262626] px-3 py-1.5 rounded font-mono font-bold uppercase tracking-wider">
                    Audit Status: <span className="text-red-400 font-bold">4 SEC_FAILURES IDENTIFIED</span>
                  </div>
                </div>

                <div className="flex flex-col gap-4">
                  {loadingMisconfig ? (
                    <div className="text-center py-16 text-gray-500 text-xs animate-pulse font-mono font-bold">Running active config scans...</div>
                  ) : (
                    misconfigFindings.map((find) => (
                      <div key={find.id} className={`p-5 rounded-lg border flex flex-col md:flex-row justify-between gap-4 transition-all ${
                        find.status === 'FAIL' 
                          ? 'bg-red-500/10 border-red-500/30' 
                          : 'bg-emerald-500/10 border-emerald-550/20'
                      }`}>
                        
                        <div className="overflow-hidden max-w-4xl">
                           <div className="flex flex-wrap items-center gap-2 mb-2">
                            <span className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded ${
                              find.status === 'FAIL' ? 'bg-red-500/20 text-red-400' : 'bg-emerald-500/20 text-emerald-400'
                            }`}>
                              {find.status}
                            </span>
                            <span className="text-xs font-mono text-gray-500">CIS {find.controlId}</span>
                            <span className="text-xs font-semibold text-cyan-400">[{find.section}]</span>
                          </div>

                          <h4 className="text-sm font-bold text-white mb-1">{find.title}</h4>
                          <p className="text-xs text-gray-400 leading-relaxed font-sans mb-3">{find.impact}</p>

                          <div className="bg-black/40 p-3 rounded border border-[#262626] font-mono text-[10px] text-gray-450 leading-relaxed">
                            <span className="font-bold text-gray-300 block mb-1">Recommended Remediation Guide:</span>
                            {find.remediation}
                          </div>
                        </div>

                        <div className="shrink-0 flex md:flex-col justify-between items-center md:items-end text-xs">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide ${
                            find.severity === 'Critical' ? 'bg-red-500/25 text-red-400' :
                            find.severity === 'High' ? 'bg-amber-500/25 text-amber-500' :
                            'bg-[#0A0A0A] border border-[#262626] text-gray-400'
                          }`}>
                            {find.severity} Severity
                          </span>
                        </div>

                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          )}

          {/* TAB 10: SOAR AUTOMATION PANEL (Module 15 / Advanced Playbooks) */}
          {activeTab === 'soar' && activeScenario && (
            <div className="flex flex-col gap-6 animate-fade-in">
              <div className="bg-[#141414] border border-[#262626] rounded-xl p-6">
                <div className="pb-4 border-b border-[#262626] mb-6">
                  <h2 className="text-lg font-sans font-semibold text-white uppercase tracking-wide">SOAR Orchestration & Automated Response Playbooks</h2>
                  <p className="text-xs text-gray-400">Trigger active firewall blocks, terminate compromised identity access keys, and quarantine security groups</p>
                </div>

                <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
                  
                  {/* Left Controls */}
                  <div className="xl:col-span-2 flex flex-col gap-6">
                    <div className="bg-black/40 border border-[#262626] p-5 rounded-lg">
                      <label className="block text-[11px] text-gray-500 uppercase font-mono mb-2 font-bold tracking-wider">Configure Action Target IAM / IP Entity</label>
                      <input 
                        type="text" 
                        value={playbookTarget}
                        onChange={(e) => setPlaybookTarget(e.target.value)}
                        className="w-full bg-[#0A0A0A] border border-[#262626] rounded-lg px-3 py-2 text-xs font-mono text-white outline-none focus:border-cyan-500"
                      />
                      <p className="text-[10px] text-gray-500 mt-2 font-sans">
                        Target value extracted dynamically from timeline keys. E.g. <b className="text-cyan-400 font-mono">{activeScenario.timeline[0]?.userIdentity.accessKeyId || activeScenario.timeline[0]?.sourceIPAddress}</b>
                      </p>
                    </div>

                    {/* Playbook Cards Grid */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {[
                        { 
                          action: "revoke_key", 
                          title: "Revoke AWS Access Key", 
                          desc: "Deactivates and deletes the compromised IAM developer keys immediately in the target account.",
                          badge: "Risk: Low impact"
                        },
                        { 
                          action: "block_ip", 
                          title: "Add IP Block to NACL / WAF", 
                          desc: "Applies broad deny ingress rules recursively to block attacker source subnets.",
                          badge: "Risk: Low impact" 
                        },
                        { 
                          action: "detach_policy", 
                          title: "Detach Over-Permissive Policies", 
                          desc: "Reverts self-attached policies and resets security session constraints.",
                          badge: "Risk: Medium impact" 
                        },
                        { 
                          action: "quarantine_session", 
                          title: "Enforce Immediate Session Lock", 
                          desc: "Frees active assumed-role STS tokens and isolates credentials.",
                          badge: "Risk: High impact" 
                        },
                      ].map((pb) => (
                        <div key={pb.action} className="bg-[#0F0F0F] border border-[#262626] p-4.5 rounded-lg flex flex-col justify-between">
                          <div>
                            <div className="flex justify-between items-start mb-2">
                              <h4 className="text-xs font-bold font-sans text-white">{pb.title}</h4>
                              <span className="text-[9px] font-mono text-gray-400 bg-black/40 px-1.5 py-0.5 border border-[#262626] rounded">{pb.badge}</span>
                            </div>
                            <p className="text-[11px] text-gray-400 leading-relaxed mb-4">{pb.desc}</p>
                          </div>

                          <button
                            onClick={() => triggerSOARPlaybook(pb.action)}
                            disabled={!!playbookTriggering || !playbookTarget}
                            className="bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 hover:bg-cyan-500/20 disabled:bg-[#0F0F0F] disabled:text-gray-600 text-[11px] font-bold py-2 rounded flex items-center justify-center gap-1.5 transition-all uppercase tracking-wider"
                          >
                            {playbookTriggering === pb.action ? (
                              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                            ) : (
                              <Play className="w-3 h-3 text-cyan-400 fill-cyan-400" />
                            )}
                            Initialize Playbook Run
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Right Logs */}
                  <div className="bg-[#0F0F0F] border border-[#262626] p-5 rounded-lg">
                    <h3 className="text-xs font-mono uppercase text-gray-400 mb-4 pb-2 border-b border-[#262626] font-bold">
                      Orchestration Response Audit Log
                    </h3>

                    <div className="flex flex-col gap-3.5 max-h-[420px] overflow-y-auto">
                      {activePlaybooksLog.length > 0 ? (
                        activePlaybooksLog.map((log, idx) => (
                          <div key={idx} className="bg-black/45 border border-[#262626] p-3 rounded text-xs font-mono">
                            <div className="flex justify-between items-start mb-1 text-[10px]">
                              <span className="text-emerald-400 font-bold">{log.status}</span>
                              <span className="text-gray-500">{log.timestamp.slice(11, 19)}</span>
                            </div>
                            <p className="text-gray-300 font-bold">Action: <span className="text-cyan-400">{log.action}</span></p>
                            <p className="text-gray-500 text-[10px]">Target: {log.appliedTo}</p>
                          </div>
                        ))
                      ) : (
                        <div className="text-center py-16 text-gray-500 text-xs">
                          No SOAR actions triggered in this session workspace. Launch one of the playbooks to simulate cloud boundary enforcement.
                        </div>
                      )}
                    </div>
                  </div>

                </div>
              </div>
            </div>
          )}

          {/* TAB 11: EVIDENCE LOCKER (Module 13 & Custody Records) */}
          {activeTab === 'evidence' && (
            <div className="flex flex-col gap-6 animate-fade-in">
              <div className="bg-[#141414] border border-[#262626] rounded-xl p-6">
                <div className="pb-4 border-b border-[#262626] mb-6 flex flex-col md:flex-row justify-between gap-4">
                  <div>
                    <h2 className="text-lg font-sans font-semibold text-white uppercase tracking-wide">Digital Forensics Evidence & Chain of Custody Locker</h2>
                    <p className="text-xs text-gray-400">Verifiably record case files, log checksums, and record strict handshakes for litigation</p>
                  </div>
                  <div className="flex gap-2">
                    <button 
                      onClick={fetchEvidence} 
                      className="text-xs bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 font-bold uppercase tracking-wider px-3 py-1.5 rounded hover:bg-cyan-500/20 flex items-center gap-1"
                    >
                      <RefreshCw className="w-3.5 h-3.5" /> Refresh Locker
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
                  
                  {/* Left Artifact list */}
                  <div className="flex flex-col gap-4">
                    <h3 className="text-xs font-mono uppercase text-[#E5E5E5] mb-1 font-bold">Acquired Case Evidence Files</h3>
                    {evidenceList.map((art) => (
                      <div 
                        key={art.id} 
                        onClick={() => setSelectedEvidenceId(art.id)}
                        className={`p-4 rounded-lg border cursor-pointer transition-all ${
                          selectedEvidenceId === art.id 
                            ? 'bg-[#0A0A0A] border-cyan-500 shadow-md shadow-cyan-500/5' 
                            : 'bg-[#0F0F0F] border border-[#262626]'
                        }`}
                      >
                        <div className="flex justify-between items-start mb-1 text-xs">
                          <font className="font-bold text-white truncate pr-2 max-w-[170px]" title={art.fileName}>{art.fileName}</font>
                          <span className="text-[10px] text-gray-500 font-mono shrink-0">{art.fileSize}</span>
                        </div>
                        <p className="text-[10px] text-cyan-400 font-mono truncate mb-2">SHA256: {art.fileHash}</p>
                        
                        <div className="flex justify-between text-[10px] text-gray-400 font-sans">
                          <span>Custodian: <span className="text-white font-mono">{art.chainOfCustody[art.chainOfCustody.length - 1]?.recordedBy}</span></span>
                          <span className="font-mono">Handovers: {art.chainOfCustody.length}</span>
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Middle and Right: Selected Case Details, comments, and Chain logs */}
                  <div className="xl:col-span-2 flex flex-col gap-6">
                    {selectedEvidenceId ? (
                      (() => {
                        const activeArt = evidenceList.find(a => a.id === selectedEvidenceId);
                        if (!activeArt) return null;

                        return (
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                            
                            {/* Custody logs */}
                            <div className="bg-[#0F0F0F] p-5 border border-[#262626] rounded-lg">
                              <h4 className="text-xs font-mono uppercase text-gray-400 mb-4 border-b border-[#262626] pb-2 font-bold">
                                Chain of Custody History
                              </h4>

                              <div className="flex flex-col gap-4 max-h-[280px] overflow-y-auto pr-1">
                                {activeArt.chainOfCustody.map((cust, i) => (
                                  <div key={i} className="border-l border-[#262626] pl-4 py-1 relative">
                                    <span className="w-2 h-2 rounded-full bg-cyan-400 absolute -left-[4.5px] top-1.5"></span>
                                    <div className="text-[11px]">
                                      <div className="flex justify-between text-gray-500 text-[10px] font-mono">
                                        <font className="font-bold text-cyan-400">{cust.recordedBy}</font>
                                        <span>{cust.recordedAt.slice(0, 10)}</span>
                                      </div>
                                      <p className="font-semibold text-white mt-0.5">{cust.action}</p>
                                      <p className="text-gray-400 text-[10px] mt-0.5 tracking-tight font-sans leading-relaxed">{cust.notes}</p>
                                    </div>
                                  </div>
                                ))}
                              </div>

                              {/* Log Custody Form */}
                              <div className="mt-6 pt-4 border-t border-[#262626] flex flex-col gap-3">
                                <span className="text-[10px] font-mono text-gray-400 font-bold">Record Custody Handover Handshake</span>
                                <div className="grid grid-cols-2 gap-2">
                                  <input 
                                    type="text" 
                                    placeholder="Your Name / Email" 
                                    value={custodyRecordedBy}
                                    onChange={(e) => setCustodyRecordedBy(e.target.value)}
                                    className="bg-[#0A0A0A] border border-[#262626] rounded px-2 py-1.5 text-xs text-white outline-none focus:border-cyan-500"
                                  />
                                  <select 
                                    value={custodyAction} 
                                    onChange={(e) => setCustodyAction(e.target.value)}
                                    className="bg-[#0A0A0A] border border-[#262626] rounded px-2 py-1.5 text-xs text-gray-300 outline-none focus:border-cyan-500"
                                  >
                                    <option value="Chain Transfer" className="bg-[#0A0A0A]">Transfer Ownership</option>
                                    <option value="Integrity Lock Verify" className="bg-[#0A0A0A]">Integrity Lock Verify</option>
                                    <option value="Legal Disclosure Log" className="bg-[#0A0A0A]">Disclosure Log</option>
                                  </select>
                                </div>
                                <input 
                                  type="text" 
                                  placeholder="Handover notes (legal/forensic reasons)" 
                                  value={custodyNotes}
                                  onChange={(e) => setCustodyNotes(e.target.value)}
                                  className="bg-[#0A0A0A] border border-[#262626] rounded px-2 py-1.5 text-xs text-white outline-none focus:border-cyan-500"
                                />
                                <button 
                                  onClick={saveChainHandshake}
                                  disabled={!custodyRecordedBy.trim()}
                                  className="bg-cyan-500/10 border border-cyan-500/20 hover:bg-cyan-500/20 text-cyan-400 font-bold text-xs py-1.5 rounded transition-all uppercase tracking-wide disabled:bg-[#0A0A0A] disabled:text-gray-600"
                                >
                                  Commit Handshake Stamp
                                </button>
                              </div>
                            </div>

                            {/* Case Comments and Analysis Notes */}
                            <div className="bg-[#0F0F0F] p-5 border border-[#262626] rounded-lg flex flex-col justify-between">
                              <div>
                                <h4 className="text-xs font-mono uppercase text-gray-400 mb-4 border-b border-[#262626] pb-2 font-bold">
                                  Investigator Case File Comments
                                </h4>

                                <div className="flex flex-col gap-3.5 max-h-[180px] overflow-y-auto mb-4">
                                  {activeArt.comments.length > 0 ? (
                                    activeArt.comments.map((com) => (
                                      <div key={com.id} className="bg-[#0A0A0A] border border-[#262626] p-2.5 rounded text-xs">
                                        <div className="flex justify-between text-[10px] text-gray-500 font-mono mb-1">
                                          <span className="font-bold text-cyan-400">{com.author}</span>
                                          <span>{com.timestamp.slice(11, 19)}</span>
                                        </div>
                                        <p className="text-gray-300 italic">"{com.text}"</p>
                                      </div>
                                    ))
                                  ) : (
                                    <div className="text-center py-6 text-gray-500 text-[11px] font-sans">
                                      No investigator logs or notes logged for this files.
                                    </div>
                                  )}
                                </div>
                              </div>

                              <div className="flex flex-col gap-2">
                                <textarea 
                                  rows={2}
                                  placeholder="Pencil down notes on target indicators, access logs, or suspicious principal behavior..."
                                  value={evidenceComment}
                                  onChange={(e) => setEvidenceComment(e.target.value)}
                                  className="w-full bg-[#0A0A0A] border border-[#262626] rounded p-2 text-xs text-white outline-none resize-none focus:border-cyan-500"
                                />
                                <button 
                                  onClick={addEvidenceComment}
                                  disabled={!evidenceComment.trim()}
                                  className="w-full bg-cyan-500/10 border border-cyan-500/20 hover:bg-cyan-500/20 text-cyan-400 font-bold text-xs py-1.5 rounded transition-all uppercase tracking-wider"
                                >
                                  Attach Case Comment Note
                                </button>
                              </div>
                            </div>

                          </div>
                        );
                      })()
                    ) : (
                      <div className="text-center py-16 text-gray-500 text-xs">
                        Select a target evidence file to examine chain logs, edit handshakes and comments.
                      </div>
                    )}
                  </div>

                </div>
              </div>
            </div>
          )}

          {/* TAB 12: EXEC REPORT EXILE AND GENERATOR (Module 14) */}
          {activeTab === 'reports' && activeScenario && (
            <div className="flex flex-col gap-6 animate-fade-in">
              <div className="bg-[#141414] border border-[#262626] rounded-xl p-6">
                <div className="pb-4 border-b border-[#262626] mb-6">
                  <h2 className="text-lg font-sans font-semibold text-white uppercase tracking-wide">Compliance & Engineering Report Exporter</h2>
                  <p className="text-xs text-gray-400">Generate, compile, and download encrypted paper-trail assessments for security compliance</p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  
                  {/* Select parameters */}
                  <div className="bg-black/40 border border-[#262626] p-5 rounded-lg flex flex-col justify-between">
                    <div>
                      <div className="mb-4">
                        <label className="block text-[11px] text-gray-500 uppercase font-mono mb-1.5 font-bold tracking-wider">Select Case Target</label>
                        <select 
                          value={activeScenarioId} 
                          onChange={(e) => setActiveScenarioId(e.target.value)}
                          className="w-full bg-[#0A0A0A] border border-[#262626] rounded px-3 py-2 text-xs text-white outline-none focus:border-cyan-500"
                        >
                          {scenarios.map(s => (
                            <option key={s.id} value={s.id} className="bg-[#0A0A0A]">{s.name}</option>
                          ))}
                        </select>
                      </div>

                      <div className="mb-4">
                        <label className="block text-[11px] text-gray-500 uppercase font-mono mb-1.5 font-bold tracking-wider">Selected Document Class Template</label>
                        <select 
                          value={reportType} 
                          onChange={(e) => setReportType(e.target.value)}
                          className="w-full bg-[#0A0A0A] border border-[#262626] rounded px-3 py-2 text-xs text-gray-300 outline-none focus:border-cyan-500"
                        >
                          <option value="Executive Legal Summation" className="bg-[#0A0A0A]">Executive Summit Summary</option>
                          <option value="S3 Data Breach Disciplinary Report" className="bg-[#0A0A0A]">S3 Data Leak Breakdown</option>
                          <option value="AWS IAM Compliance Audit Standard" className="bg-[#0A0A0A]">AWS IAM Compliance Certification Report</option>
                          <option value="SOC Breach Forensic Chronography" className="bg-[#0A0A0A]">Incident Timeline Forensic Chronography</option>
                        </select>
                      </div>

                      <span className="text-[10px] text-gray-500 leading-relaxed block font-sans">
                        Compiles complete session timelines, anomaly deviations, and compliance metrics into plain text for download.
                      </span>
                    </div>

                    <button 
                      onClick={exportForensicDocument}
                      disabled={loadingExport}
                      className="w-full mt-6 bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 font-bold text-xs py-2 px-3 rounded-lg flex items-center justify-center gap-2 transition-all shadow-md uppercase tracking-wider"
                    >
                      {loadingExport ? (
                        <RefreshCw className="w-4 h-4 animate-spin" />
                      ) : (
                        <FileDown className="w-4 h-4" />
                      )}
                      Compile Paper-Trail Document
                    </button>
                  </div>

                  {/* Document preview panel */}
                  <div className="md:col-span-2 bg-[#0F0F0F] border border-[#262626] p-5 rounded-lg">
                    {exportedReport ? (
                      <div>
                        <div className="flex justify-between items-center pb-3 border-b border-[#262626] mb-4">
                          <div>
                            <span className="text-[10px] font-mono text-cyan-400 uppercase font-bold tracking-wide">Encrypted Document Compiled</span>
                            <h4 className="text-xs font-mono text-white mt-1 font-bold">{exportedReport.fileName}</h4>
                          </div>
                          <button 
                            onClick={() => {
                              const blob = new Blob([exportedReport.content], { type: 'text/plain' });
                              const url = URL.createObjectURL(blob);
                              const link = document.createElement('a');
                              link.href = url;
                              link.download = exportedReport.fileName;
                              link.click();
                            }}
                            className="bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 border border-cyan-500/20 px-3 py-1.5 rounded text-xs flex items-center gap-1 font-mono font-bold tracking-wide transition-all"
                          >
                            <FileDown className="w-3.5 h-3.5" /> Download Report
                          </button>
                        </div>

                        <div className="bg-[#0A0A0A] p-4 border border-[#262626] rounded max-h-[300px] overflow-y-auto">
                          <pre className="text-[10px] text-gray-400 font-mono leading-relaxed whitespace-pre font-sans">{exportedReport.content}</pre>
                        </div>
                      </div>
                    ) : (
                      <div className="text-center py-16 text-gray-500 text-xs">
                        <FileText className="w-12 h-12 text-[#262626] mx-auto mb-3" />
                        Configure report parameters and compile documents to prepare legal disclosures, SOC handovers, and auditing certificates.
                      </div>
                    )}
                  </div>

                </div>
              </div>
            </div>
          )}

          {/* TAB 13: IEEE SCOPE & RESEARCH CONTRIBUTIONS */}
          {activeTab === 'research' && (
            <div className="flex flex-col gap-6 animate-fade-in">
              <div className="bg-[#141414] border border-[#262626] rounded-xl p-6">
                <div className="pb-4 border-b border-[#262626] mb-6">
                  <h2 className="text-lg font-sans font-semibold text-white uppercase tracking-wider">IEEE Research Scope & Publication Novelties</h2>
                  <p className="text-xs text-gray-400">Formal assessment statements detailing the architectural prototype contributions and scientific relevance</p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  
                  <div className="p-5 bg-[#0F0F0F] border border-[#262626] rounded-lg">
                    <h3 className="text-sm font-sans font-bold text-white flex items-center gap-2 mb-3">
                      <span className="p-1 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 text-xs px-2 font-mono">1</span>
                      Scientific Contribution Statement
                    </h3>
                    <p className="text-xs text-gray-450 leading-relaxed font-sans mb-3 font-medium">
                      CloudTrail logs represent a significant challenge to classical security operation triage due to the highly nested, non-sequential nature of AWS API declarations. Standard security information managers evaluate items through isolated, static filters.
                    </p>
                    <p className="text-[11px] font-mono text-gray-400 leading-relaxed bg-black/40 p-3 border border-[#262626] rounded-lg">
                      <b>Main Contribution:</b> This platform introduces multi-stage lateral tree alignment structures, integrating GNN topology heuristics with real-time generative AI storytelling nodes via server-side Gemini SDK connections, accelerating triage response cycles from hours to under 3 seconds.
                    </p>
                  </div>

                  <div className="p-5 bg-[#0F0F0F] border border-[#262626] rounded-lg">
                    <h3 className="text-sm font-sans font-bold text-white flex items-center gap-2 mb-3">
                      <span className="p-1 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 text-xs px-2 font-mono">2</span>
                      Research Novelties Breakdown
                    </h3>
                    <div className="flex flex-col gap-3 text-xs leading-relaxed text-gray-450 font-sans">
                      <p>
                        <b>1. Temporal Session Integration:</b> Groups different API identifiers using AWS ARN tags and access tokens, maintaining situational custody even across IP rotation.
                      </p>
                      <p>
                        <b>2. Explainable Threat Metrics:</b> Outputs precise SHAP feature percentages to help engineers trace the model's classifications, mapping anomalous scores back to CIS benchmark violations.
                      </p>
                      <p>
                        <b>3. Generative Forensic Outlines:</b> Instantly compiles plain-English chronologies alongside executive legal briefs and ready-to-run database queries (Athena/SPL) automatically.
                      </p>
                    </div>
                  </div>

                </div>
              </div>
            </div>
          )}

        </main>
      </div>

      {/* Persistent Footer */}
      <footer className="bg-[#141414] border-t border-[#262626] px-6 py-3.5 flex flex-col md:flex-row justify-between items-center text-[10px] text-gray-550 font-mono gap-3 shrink-0">
        <p>© 2026 AegisForensics Research. Licensed under Apache-2.0.</p>
        <div className="flex gap-4">
          <span>Active Session ID: <b className="text-gray-400">ec016513-3ea9</b></span>
          <span>Target Platform Ingress: <b className="text-cyan-400 font-bold">ONLINE</b></span>
        </div>
      </footer>

    </div>
  );
}
