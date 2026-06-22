/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { motion } from 'motion/react';
import { 
  Shield, 
  Lock, 
  Key, 
  Terminal, 
  User, 
  Cpu, 
  Check, 
  X, 
  Eye, 
  EyeOff, 
  Radio, 
  ChevronRight,
  Database,
  RefreshCw,
  Server
} from 'lucide-react';

interface LoginScreenProps {
  onLoginSuccess: (operatorEmail: string) => void;
}

export default function LoginScreen({ onLoginSuccess }: LoginScreenProps) {
  const [email, setEmail] = useState('');
  const [passcode, setPasscode] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  
  // Custom interactive authorization sequence
  const [isVerifying, setIsVerifying] = useState(false);
  const [verificationStep, setVerificationStep] = useState(0);
  const [logLines, setLogLines] = useState<string[]>([]);

  // Simulation steps for realistic cloud forensics loading
  const steps = [
    { text: "Initializing CloudTrace local sandbox environment...", delay: 400 },
    { text: "Establishing secure multi-tenant operator interface...", delay: 350 },
    { text: "Authenticating token against AWS Principal policies...", delay: 450 },
    { text: "Handshake verified. Fetching incident scenario catalogs...", delay: 350 },
    { text: "Bootstrapping state... Transitioning to SOC Dashboard...", delay: 300 }
  ];

  // Live timer for authenticity
  const [currentTime, setCurrentTime] = useState('');
  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setCurrentTime(now.getUTCFullYear() + '-' + 
                    String(now.getUTCMonth() + 1).padStart(2, '0') + '-' + 
                    String(now.getUTCDate()).padStart(2, '0') + ' ' + 
                    String(now.getUTCHours()).padStart(2, '0') + ':' + 
                    String(now.getUTCMinutes()).padStart(2, '0') + ':' + 
                    String(now.getUTCSeconds()).padStart(2, '0') + ' UTC');
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const handleAutofill = () => {
    setEmail('operator@cloudtrace.internal');
    setPasscode('CT-9941-SECURE');
    setErrorMsg('');
  };

  const handleLoginSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!email) {
      setErrorMsg('Operator IAM principal identifier is required.');
      return;
    }
    if (!passcode) {
      setErrorMsg('Secure Session Passcode is required.');
      return;
    }

    // Accept anything with @ and any secure passcode as a real-world simulator,
    // but check autofill values specifically for default validation feedback.
    if (email.toLowerCase() === 'operator@cloudtrace.internal' && passcode !== 'CT-9941-SECURE') {
      setErrorMsg('Invalid session passcode for operator credential. Please make sure case-sensitivity is accurate.');
      return;
    }

    // Trigger authentic verification loader loop
    setErrorMsg('');
    setIsVerifying(true);
    setVerificationStep(0);
    setLogLines([`[${new Date().toISOString().substring(11, 19)}] SYS_BOOT: Spawning login subprocess...`]);
  };

  useEffect(() => {
    if (!isVerifying) return;

    if (verificationStep < steps.length) {
      const currentStep = steps[verificationStep];
      const timer = setTimeout(() => {
        setLogLines(prev => [
          ...prev, 
          `[${new Date().toISOString().substring(11, 19)}] OK: ${currentStep.text}`
        ]);
        setVerificationStep(prev => prev + 1);
      }, currentStep.delay);
      return () => clearTimeout(timer);
    } else {
      // Completed all secure validation stages, transition user into main app view
      const timer = setTimeout(() => {
        onLoginSuccess(email || "operator@cloudtrace.internal");
      }, 200);
      return () => clearTimeout(timer);
    }
  }, [isVerifying, verificationStep]);

  return (
    <div id="login-container" className="min-h-screen bg-[#070707] text-[#E5E5E5] flex flex-col items-center justify-center relative overflow-hidden font-sans p-4 select-none">
      
      {/* Dynamic Ambient Cyber Grid Background */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#0f0f0f_1px,transparent_1px),linear-gradient(to_bottom,#0f0f0f_1px,transparent_1px)] bg-[size:40px_40px] pointer-events-none opacity-40" />
      
      {/* Decorative Aurora Glow */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none animate-pulse" />
      <div className="absolute bottom-10 left-10 w-72 h-72 bg-blue-500/5 rounded-full blur-3xl pointer-events-none" />

      <div className="w-full max-w-lg z-10">
        {/* Connection status bar top */}
        <div className="mb-6 flex justify-between items-center text-[10px] font-mono text-gray-400 bg-[#141414] border border-[#262626] rounded-full px-4 py-1.5 shadow-sm">
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
            <span className="font-bold text-cyan-400 shrink-0 uppercase">CloudTrace Ingress Gateway</span>
          </div>
          <div className="hidden sm:block truncate max-w-[200px]">NODE: forensics-us-east-1a</div>
          <div className="font-semibold text-gray-300">{currentTime}</div>
        </div>

        {/* Central Auth Container Card */}
        <motion.div 
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, ease: 'easeOut' }}
          className="bg-[#0A0A0A]/90 border border-[#262626] rounded-2xl p-6 md:p-8 backdrop-blur-md shadow-2xl relative"
        >
          {/* Logo Brand Header */}
          <div className="flex items-center gap-4 mb-6 pb-6 border-b border-[#262626]/80">
            <div className="relative">
              <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/15" id="login-app-icon">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <div className="absolute -bottom-1 -right-1 bg-black p-0.5 rounded-full border border-[#262626]">
                <Radio className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
              </div>
            </div>
            <div>
              <h2 className="text-xl font-bold font-sans tracking-tight text-white flex items-center gap-2">
                CloudTrace <span className="text-gray-500 text-xs font-normal font-mono border border-[#262626] bg-black px-1.5 py-0.5 rounded">v2.4</span>
              </h2>
              <p className="text-xs text-gray-400 mt-1">
                Intelligent Incident Forensics & Attack Reconstruction Console
              </p>
            </div>
          </div>

          {!isVerifying ? (
            <form onSubmit={handleLoginSubmit} className="space-y-4">
              
              {/* Warnings / Operational guidelines */}
              <div className="bg-amber-500/5 border border-amber-500/20 rounded-xl p-3 text-[11px] leading-relaxed text-amber-200">
                <div className="flex gap-2">
                  <Lock className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                  <div>
                    <span className="font-bold">Secured Federal Access Control System:</span> Operating actions are being dynamically recorded under audit policy AWS-TRACE-2026. Bypass attempts will trigger automated network lockouts.
                  </div>
                </div>
              </div>

              {/* Form Input fields */}
              <div>
                <label className="block text-[11px] font-mono tracking-wider uppercase text-gray-400 font-bold mb-1.5">
                  Operator IAM Principal Identity
                </label>
                <div className="relative">
                  <User className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => {
                      setEmail(e.target.value);
                      setErrorMsg('');
                    }}
                    placeholder="operator@cloudtrace.internal"
                    className="w-full bg-[#121212]/90 border border-[#262626] focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 rounded-xl py-2.5 pl-10 pr-4 text-sm text-[#E5E5E5] placeholder-gray-600 outline-none transition-all font-sans"
                  />
                </div>
              </div>

              <div>
                <div className="flex justify-between items-center mb-1.5">
                  <label className="block text-[11px] font-mono tracking-wider uppercase text-gray-400 font-bold">
                    Secure Session Passcode
                  </label>
                  <span className="text-[10px] text-gray-500 font-mono">256-bit Tokenized</span>
                </div>
                <div className="relative">
                  <Key className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                  <input
                    type={showPassword ? 'text' : 'password'}
                    value={passcode}
                    onChange={(e) => {
                      setPasscode(e.target.value);
                      setErrorMsg('');
                    }}
                    placeholder="•••••••••••••••••"
                    className="w-full bg-[#121212]/90 border border-[#262626] focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 rounded-xl py-2.5 pl-10 pr-10 text-sm text-[#E5E5E5] placeholder-gray-600 outline-none transition-all font-mono"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 p-1 text-gray-500 hover:text-gray-300 transition-colors"
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {/* Error readout */}
              {errorMsg && (
                <div className="bg-red-500/10 border border-red-800/80 rounded-xl p-3 flex gap-2.5 items-start text-xs text-red-400">
                  <X className="w-4 h-4 shrink-0 mt-0.5" />
                  <span className="leading-normal font-sans font-medium">{errorMsg}</span>
                </div>
              )}

              {/* Form buttons */}
              <div className="pt-2 flex flex-col sm:flex-row gap-3">
                <button
                  type="button"
                  onClick={handleAutofill}
                  className="flex-1 border border-dashed border-[#262626] py-2.5 rounded-xl text-xs hover:border-cyan-500/50 hover:bg-[#141414] text-gray-400 hover:text-[#E5E5E5] transition-all font-mono tracking-wide uppercase font-bold text-center flex items-center justify-center gap-1.5"
                >
                  <Server className="w-3.5 h-3.5 text-cyan-400" /> 
                  Quick Demo Access
                </button>

                <button
                  type="submit"
                  className="flex-1 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-bold text-xs py-2.5 rounded-xl uppercase tracking-wider shadow-lg shadow-cyan-500/10 hover:shadow-cyan-500/20 transition-all flex items-center justify-center gap-2 border border-cyan-400/20 font-sans cursor-pointer"
                >
                  <span>Authorize Operator</span>
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>

            </form>
          ) : (
            // Holographic Booting Terminal sequence
            <div className="space-y-4 py-2">
              <div className="flex items-center gap-3 bg-cyan-950/15 border border-cyan-800/25 rounded-xl p-3 text-xs text-cyan-300">
                <RefreshCw className="w-4 h-4 animate-spin shrink-0 text-cyan-400" />
                <div className="font-sans">
                  <span className="font-bold uppercase tracking-wide">Handshaking:</span> Resolving credentials and generating runtime state token...
                </div>
              </div>

              <div className="bg-[#050505] border border-[#1f1f1f] rounded-xl p-4 font-mono text-[10px] space-y-1.5 max-h-52 overflow-y-auto shadow-inner text-gray-400">
                <div className="text-gray-500 pb-1 border-b border-[#141414] mb-2 flex justify-between items-center">
                  <span>SSL/IAM LOG STREAM</span>
                  <span className="animate-pulse text-[8px] px-1.5 bg-cyan-950 text-cyan-400 rounded-full border border-cyan-900">VERIFYING</span>
                </div>
                {logLines.map((line, idx) => (
                  <div key={idx} className="leading-relaxed whitespace-pre-wrap">
                    {line}
                  </div>
                ))}
                {verificationStep < steps.length && (
                  <div className="text-cyan-400 animate-pulse inline-flex items-center gap-1">
                    <span>█</span> <span className="text-[8px] text-gray-600 font-sans">Connecting to AWS Secure API...</span>
                  </div>
                )}
              </div>

              <div className="text-center text-[10px] text-gray-550 font-mono">
                Establishing token context: <span className="text-[#cccccc]">{email.substring(0, 15)}...</span>
              </div>
            </div>
          )}
        </motion.div>

        {/* Security / Organization credits metadata */}
        <div className="mt-6 flex flex-col items-center justify-center gap-2 select-none text-[10px] text-gray-550 font-mono text-center">
          <p>AUTHORIZED INGRESS ENCRYPTED VIA ECDHE-RSA-AES256-GCM-SHA384</p>
          <p className="text-gray-600">Product of CloudTrace Labs Research © 2026. All rights and telemetry reserved.</p>
        </div>
      </div>
    </div>
  );
}
