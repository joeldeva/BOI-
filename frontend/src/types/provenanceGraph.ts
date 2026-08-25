import type { ApkAnalysisResult } from './api';

export type ProvenanceNodeType =
  | 'PERMISSION'
  | 'COMPONENT'
  | 'API'
  | 'DATA'
  | 'RUNTIME_EVENT'
  | 'NETWORK'
  | 'BEHAVIOR'
  | 'BANKING_IMPACT';

export type ProvenanceEdgeType =
  | 'DECLARES'
  | 'INVOKES'
  | 'OBSERVED_AFTER'
  | 'READS'
  | 'TRANSFORMS'
  | 'SENDS_TO'
  | 'SUPPORTS'
  | 'ENABLES';

export type ProvenanceState =
  | 'STATIC'
  | 'INFERRED'
  | 'RUNTIME_CONFIRMED'
  | 'CONTRADICTED'
  | 'IMPACT';

export interface ProvenanceNode {
  id: string;
  type: ProvenanceNodeType;
  label: string;
  sublabel?: string;
  state: ProvenanceState;
  evidenceId?: string;
  sourceEngine?: string;
  description: string;
  confidence?: number;
  hypothesisId?: string;
  metadata?: Record<string, unknown>;
  category?: string;
  layer: number; // 0: Manifest/Perms, 1: Components/APIs, 2: Data/Runtime, 3: Network/Behaviors, 4: Banking Impact
  tags?: string[];
}

export interface ProvenanceEdge {
  id: string;
  source: string;
  target: string;
  type: ProvenanceEdgeType;
  label?: string;
  state?: ProvenanceState;
  animated?: boolean;
}

export interface ProvenanceGraphData {
  nodes: ProvenanceNode[];
  edges: ProvenanceEdge[];
  summary: {
    totalNodes: number;
    totalEdges: number;
    impactCount: number;
    confirmedCount: number;
    staticCount: number;
  };
  impactNodes: ProvenanceNode[];
}

/* =========================================================================
   Deterministic Provenance Graph Builder
   Translates actual analysis findings into an evidence-to-impact DAG.
   ========================================================================= */

export function buildProvenanceGraph(result: ApkAnalysisResult | null | undefined): ProvenanceGraphData {
  if (!result) {
    return {
      nodes: [],
      edges: [],
      summary: { totalNodes: 0, totalEdges: 0, impactCount: 0, confirmedCount: 0, staticCount: 0 },
      impactNodes: [],
    };
  }

  const nodes: ProvenanceNode[] = [];
  const edges: ProvenanceEdge[] = [];
  const nodeMap = new Map<string, ProvenanceNode>();
  const edgeSet = new Set<string>();

  function addNode(node: ProvenanceNode) {
    if (!nodeMap.has(node.id)) {
      nodeMap.set(node.id, node);
      nodes.push(node);
    }
  }

  function addEdge(sourceId: string, targetId: string, type: ProvenanceEdgeType, label?: string, animated = false) {
    if (!nodeMap.has(sourceId) || !nodeMap.has(targetId)) return;
    const key = `${sourceId}->${targetId}:${type}`;
    if (!edgeSet.has(key)) {
      edgeSet.add(key);
      const sourceNode = nodeMap.get(sourceId)!;
      const targetNode = nodeMap.get(targetId)!;
      const isConfirmed = sourceNode.state === 'RUNTIME_CONFIRMED' || targetNode.state === 'RUNTIME_CONFIRMED';
      edges.push({
        id: `e-${edges.length + 1}`,
        source: sourceId,
        target: targetId,
        type,
        label: label || type.toLowerCase().replaceAll('_', ' '),
        animated: animated || isConfirmed,
        state: isConfirmed ? 'RUNTIME_CONFIRMED' : targetNode.state,
      });
    }
  }

  const extraction = result.extraction || ({} as any);
  const permissions = extraction.permissions || { requested: [], flagged_dangerous: [] };
  const components = extraction.components || {};
  const codeSignals = extraction.code_signals || {};
  const network = extraction.network_indicators || { domains: [], ips: [], urls: [] };
  const runtimeEvidence = result.runtime_evidence || [];
  const experimentResults = result.experiment_results || [];
  const aiInvestigation = result.ai_investigation;
  const verifications = aiInvestigation?.hypothesis_verifications || [];
  const hypotheses = aiInvestigation?.hypotheses || [];

  const hasRuntimeConfirmed = (pattern: string) =>
    runtimeEvidence.some(
      (re) =>
        re.evidence_type.toLowerCase().includes(pattern.toLowerCase()) ||
        re.description.toLowerCase().includes(pattern.toLowerCase())
    ) ||
    experimentResults.some(
      (er) =>
        er.status === 'COMPLETED' &&
        (er.summary?.toLowerCase().includes(pattern.toLowerCase()) ||
          er.experiment_type.toLowerCase().includes(pattern.toLowerCase()))
    );

  const isHypothesisConfirmed = (category: string) =>
    verifications.some(
      (v) =>
        v.category.toUpperCase().includes(category.toUpperCase()) &&
        v.verified_status === 'CONFIRMED'
    ) ||
    hypotheses.some(
      (h) =>
        h.category.toUpperCase().includes(category.toUpperCase()) &&
        h.status === 'CONFIRMED'
    );

  /* -------------------------------------------------------------------------
     LAYER 0: Manifest & Permissions (STATIC)
     ------------------------------------------------------------------------- */
  const requested = permissions.requested || [];
  const dangerous = permissions.flagged_dangerous || [];

  if (requested.includes('android.permission.READ_SMS') || dangerous.includes('android.permission.READ_SMS')) {
    addNode({
      id: 'perm_read_sms',
      type: 'PERMISSION',
      label: 'READ_SMS',
      sublabel: 'Dangerous Permission',
      state: 'STATIC',
      evidenceId: 'E-PERM-SMS',
      sourceEngine: 'apk-manifest',
      description: 'Declared capability to read incoming SMS inbox containing transaction OTP tokens.',
      confidence: 1.0,
      layer: 0,
      tags: ['sms', 'otp', 'credential'],
    });
  }

  if (requested.includes('android.permission.RECEIVE_SMS') || dangerous.includes('android.permission.RECEIVE_SMS')) {
    addNode({
      id: 'perm_recv_sms',
      type: 'PERMISSION',
      label: 'RECEIVE_SMS',
      sublabel: 'Dangerous Permission',
      state: 'STATIC',
      evidenceId: 'E-PERM-RECVSMS',
      sourceEngine: 'apk-manifest',
      description: 'Allows app to register high-priority broadcast receivers for incoming SMS notifications.',
      confidence: 1.0,
      layer: 0,
      tags: ['sms', 'broadcast'],
    });
  }

  if (requested.includes('android.permission.SYSTEM_ALERT_WINDOW') || dangerous.includes('android.permission.SYSTEM_ALERT_WINDOW')) {
    addNode({
      id: 'perm_alert_window',
      type: 'PERMISSION',
      label: 'SYSTEM_ALERT_WINDOW',
      sublabel: 'Overlay Permission',
      state: 'STATIC',
      evidenceId: 'E-PERM-OVERLAY',
      sourceEngine: 'apk-manifest',
      description: 'Draw-over-apps permission allowing invisible or deceptive phishing overlays above banking apps.',
      confidence: 1.0,
      layer: 0,
      tags: ['overlay', 'phishing'],
    });
  }

  if (requested.includes('android.permission.REQUEST_INSTALL_PACKAGES') || dangerous.includes('android.permission.REQUEST_INSTALL_PACKAGES')) {
    addNode({
      id: 'perm_install_pkgs',
      type: 'PERMISSION',
      label: 'REQUEST_INSTALL_PACKAGES',
      sublabel: 'Dropper Permission',
      state: 'STATIC',
      evidenceId: 'E-PERM-DROPPER',
      sourceEngine: 'apk-manifest',
      description: 'Allows APK to download and prompt installation of secondary malware payloads (dropper capability).',
      confidence: 1.0,
      layer: 0,
      tags: ['dropper', 'payload'],
    });
  }

  if (requested.includes('android.permission.QUERY_ALL_PACKAGES') || dangerous.includes('android.permission.QUERY_ALL_PACKAGES')) {
    addNode({
      id: 'perm_query_pkgs',
      type: 'PERMISSION',
      label: 'QUERY_ALL_PACKAGES',
      sublabel: 'Reconnaissance Permission',
      state: 'STATIC',
      evidenceId: 'E-PERM-QUERY',
      sourceEngine: 'apk-manifest',
      description: 'Enumerates all installed banking and fintech apps on the device to trigger targeted overlays.',
      confidence: 1.0,
      layer: 0,
      tags: ['recon', 'targeting'],
    });
  }

  if (requested.includes('android.permission.INTERNET') || network.domains.length > 0 || network.ips.length > 0) {
    addNode({
      id: 'perm_internet',
      type: 'PERMISSION',
      label: 'INTERNET',
      sublabel: 'Network Capability',
      state: 'STATIC',
      evidenceId: 'E-PERM-NET',
      sourceEngine: 'apk-manifest',
      description: 'Permits socket and HTTP/HTTPS network connections for outbound exfiltration.',
      confidence: 1.0,
      layer: 0,
      tags: ['network', 'exfiltration'],
    });
  }

  /* -------------------------------------------------------------------------
     LAYER 1: Declared Components & APIs (STATIC / INFERRED)
     ------------------------------------------------------------------------- */
  if (components.sms_receiver) {
    addNode({
      id: 'comp_sms_receiver',
      type: 'COMPONENT',
      label: 'SmsReceiver',
      sublabel: 'BroadcastReceiver',
      state: 'STATIC',
      evidenceId: 'E-COMP-SMS',
      sourceEngine: 'apk-manifest',
      description: 'Exported broadcast receiver listening for android.provider.Telephony.SMS_RECEIVED.',
      confidence: 0.95,
      layer: 1,
      tags: ['component', 'receiver'],
    });
    if (nodeMap.has('perm_read_sms')) addEdge('perm_read_sms', 'comp_sms_receiver', 'DECLARES');
    if (nodeMap.has('perm_recv_sms')) addEdge('perm_recv_sms', 'comp_sms_receiver', 'DECLARES');
  }

  if (components.accessibility_service) {
    addNode({
      id: 'comp_accessibility',
      type: 'COMPONENT',
      label: 'AccessibilityService',
      sublabel: 'Privileged Service',
      state: 'STATIC',
      evidenceId: 'E-COMP-A11Y',
      sourceEngine: 'apk-manifest',
      description: 'Registers accessibility hooks capable of screen scraping, keylogging, and automated button clicks.',
      confidence: 0.95,
      layer: 1,
      tags: ['accessibility', 'automation'],
    });
    if (nodeMap.has('perm_alert_window')) addEdge('perm_alert_window', 'comp_accessibility', 'DECLARES');
  }

  if (components.boot_receiver) {
    addNode({
      id: 'comp_boot_receiver',
      type: 'COMPONENT',
      label: 'BootReceiver',
      sublabel: 'Persistence Hook',
      state: 'STATIC',
      evidenceId: 'E-COMP-BOOT',
      sourceEngine: 'apk-manifest',
      description: 'Receives BOOT_COMPLETED broadcast to automatically restart background spyware on phone reboot.',
      confidence: 0.9,
      layer: 1,
      tags: ['persistence'],
    });
  }

  if (codeSignals.sms_api?.detected) {
    addNode({
      id: 'api_sms_manager',
      type: 'API',
      label: 'SmsManager API',
      sublabel: 'Telephony SDK',
      state: 'STATIC',
      evidenceId: 'E-API-SMS',
      sourceEngine: 'dex-code-signal',
      description: 'Direct DEX invocation of android.telephony.SmsManager for intercepting or sending SMS messages.',
      confidence: 0.95,
      layer: 1,
      tags: ['api', 'sms'],
    });
    if (nodeMap.has('comp_sms_receiver')) addEdge('comp_sms_receiver', 'api_sms_manager', 'INVOKES');
  }

  if (codeSignals.input_injection?.detected) {
    addNode({
      id: 'api_dispatch_gesture',
      type: 'API',
      label: 'dispatchGesture()',
      sublabel: 'UI Automation API',
      state: 'STATIC',
      evidenceId: 'E-API-GESTURE',
      sourceEngine: 'dex-code-signal',
      description: 'Invokes AccessibilityService.dispatchGesture to simulate programmatic taps on banking confirmation modals.',
      confidence: 0.92,
      layer: 1,
      tags: ['api', 'tapjacking'],
    });
    if (nodeMap.has('comp_accessibility')) addEdge('comp_accessibility', 'api_dispatch_gesture', 'INVOKES');
  }

  if (codeSignals.dynamic_code_loading?.detected) {
    addNode({
      id: 'api_dex_loader',
      type: 'API',
      label: 'DexClassLoader',
      sublabel: 'Dynamic Code Loading',
      state: 'STATIC',
      evidenceId: 'E-API-DEX',
      sourceEngine: 'dex-code-signal',
      description: 'Loads encrypted or remote executable DEX classes at runtime, evading static package-time scanners.',
      confidence: 0.95,
      layer: 1,
      tags: ['evasion', 'dynamic_load'],
    });
  }

  if (codeSignals.installed_app_enumeration?.detected) {
    addNode({
      id: 'api_app_enum',
      type: 'API',
      label: 'getInstalledApplications',
      sublabel: 'Package Manager API',
      state: 'STATIC',
      evidenceId: 'E-API-ENUM',
      sourceEngine: 'dex-code-signal',
      description: 'Scans device storage for active banking, cryptocurrency, and 2FA authentication applications.',
      confidence: 0.9,
      layer: 1,
      tags: ['recon'],
    });
    if (nodeMap.has('perm_query_pkgs')) addEdge('perm_query_pkgs', 'api_app_enum', 'INVOKES');
  }

  /* -------------------------------------------------------------------------
     LAYER 2: Sensitive Data & Runtime Observations
     ------------------------------------------------------------------------- */
  const otpObserved = hasRuntimeConfirmed('otp') || hasRuntimeConfirmed('sms');
  const otpState: ProvenanceState = otpObserved ? 'RUNTIME_CONFIRMED' : 'INFERRED';

  if (nodeMap.has('comp_sms_receiver') || nodeMap.has('perm_read_sms') || codeSignals.sms_api?.detected) {
    addNode({
      id: 'data_otp_token',
      type: 'DATA',
      label: 'Incoming SMS / OTP Token',
      sublabel: 'Sensitive Banking Credential',
      state: otpState,
      evidenceId: 'E-DATA-OTP',
      sourceEngine: otpObserved ? 'dynamic-lite' : 'static-inference',
      description: 'Transient one-time authentication codes dispatched by financial institutions for login and fund transfers.',
      confidence: otpObserved ? 0.98 : 0.8,
      layer: 2,
      tags: ['otp', 'token'],
    });
    if (nodeMap.has('comp_sms_receiver')) addEdge('comp_sms_receiver', 'data_otp_token', 'READS');
    if (nodeMap.has('api_sms_manager')) addEdge('api_sms_manager', 'data_otp_token', 'READS');
  }

  if (nodeMap.has('comp_accessibility') || nodeMap.has('perm_alert_window')) {
    const a11yObserved = hasRuntimeConfirmed('accessibility') || hasRuntimeConfirmed('screen');
    addNode({
      id: 'data_screen_buffer',
      type: 'DATA',
      label: 'On-Screen Credentials & PIN',
      sublabel: 'User Input Stream',
      state: a11yObserved ? 'RUNTIME_CONFIRMED' : 'INFERRED',
      evidenceId: 'E-DATA-SCREEN',
      sourceEngine: a11yObserved ? 'dynamic-lite' : 'static-inference',
      description: 'Real-time capture of entered MPIN, account passwords, and credit card numbers from active foreground apps.',
      confidence: a11yObserved ? 0.95 : 0.75,
      layer: 2,
      tags: ['credentials', 'keystrokes'],
    });
    if (nodeMap.has('comp_accessibility')) addEdge('comp_accessibility', 'data_screen_buffer', 'READS');
  }

  /* Add explicit Runtime Observation node if synthetic OTP or SMS dynamic observation exists */
  if (otpObserved || runtimeEvidence.length > 0) {
    const rtItem = runtimeEvidence.find((re) => re.description.toLowerCase().includes('otp') || re.description.toLowerCase().includes('sms')) || runtimeEvidence[0];
    const rtDesc = rtItem ? rtItem.description : 'Synthetic OTP marker injection intercepted by active SMS receiver in sandbox.';
    addNode({
      id: 'runtime_otp_access',
      type: 'RUNTIME_EVENT',
      label: 'Synthetic OTP Marker Intercepted',
      sublabel: 'Dynamic Sandbox Evidence',
      state: 'RUNTIME_CONFIRMED',
      evidenceId: rtItem?.evidence_id || 'RT-001',
      sourceEngine: 'dynamic-lite-sandbox',
      description: rtDesc,
      confidence: rtItem?.confidence || 0.95,
      layer: 2,
      tags: ['runtime', 'confirmed'],
    });
    if (nodeMap.has('data_otp_token')) addEdge('data_otp_token', 'runtime_otp_access', 'OBSERVED_AFTER', 'observed in sandbox', true);
  }

  /* -------------------------------------------------------------------------
     LAYER 3: Network C2 & Attack Behaviors
     ------------------------------------------------------------------------- */
  const c2Domain = network.domains[0] || network.ips[0] || network.urls[0] || (nodeMap.has('perm_internet') ? 'Outbound C2 Channel' : null);
  const netExfilObserved = hasRuntimeConfirmed('network') || hasRuntimeConfirmed('outbound') || hasRuntimeConfirmed('marker');
  const netState: ProvenanceState = netExfilObserved ? 'RUNTIME_CONFIRMED' : 'STATIC';

  if (c2Domain) {
    addNode({
      id: 'net_c2_endpoint',
      type: 'NETWORK',
      label: typeof c2Domain === 'string' && c2Domain.startsWith('http') ? c2Domain : `C2: ${c2Domain}`,
      sublabel: 'Exfiltration Endpoint',
      state: netState,
      evidenceId: 'E-NET-C2',
      sourceEngine: netExfilObserved ? 'dynamic-network-monitor' : 'apk-manifest',
      description: 'Host endpoint receiving outbound HTTP POST exfiltration packets with intercepted tokens and device telemetry.',
      confidence: netExfilObserved ? 0.99 : 0.85,
      layer: 3,
      tags: ['network', 'c2'],
    });
    if (nodeMap.has('perm_internet')) addEdge('perm_internet', 'net_c2_endpoint', 'ENABLES');
    if (nodeMap.has('runtime_otp_access')) addEdge('runtime_otp_access', 'net_c2_endpoint', 'SENDS_TO', 'outbound HTTP POST', true);
    else if (nodeMap.has('data_otp_token')) addEdge('data_otp_token', 'net_c2_endpoint', 'SENDS_TO');
    if (nodeMap.has('data_screen_buffer')) addEdge('data_screen_buffer', 'net_c2_endpoint', 'SENDS_TO');
  }

  const isOtpConfirmed = isHypothesisConfirmed('OTP') || (nodeMap.has('comp_sms_receiver') && otpObserved);
  const otpBehaviorState: ProvenanceState = isOtpConfirmed ? 'RUNTIME_CONFIRMED' : 'INFERRED';

  if (nodeMap.has('comp_sms_receiver') || nodeMap.has('data_otp_token')) {
    addNode({
      id: 'behavior_otp_interception',
      type: 'BEHAVIOR',
      label: 'OTP Interception & Exfiltration',
      sublabel: isOtpConfirmed ? 'Verified Attack Pattern' : 'Inferred Attack Pattern',
      state: otpBehaviorState,
      evidenceId: 'H-OTP-EXFIL',
      sourceEngine: 'ai-hypothesis-verifier',
      description: 'Multi-stage exploit path: SMS receiver captures OTP message, suppresses user notification, and transmits token to remote C2.',
      confidence: isOtpConfirmed ? 0.98 : 0.74,
      layer: 3,
      tags: ['behavior', 'otp_theft'],
    });
    if (nodeMap.has('net_c2_endpoint')) addEdge('net_c2_endpoint', 'behavior_otp_interception', 'SUPPORTS', 'exfiltration channel');
    else if (nodeMap.has('runtime_otp_access')) addEdge('runtime_otp_access', 'behavior_otp_interception', 'SUPPORTS');
  }

  if (nodeMap.has('comp_accessibility') || nodeMap.has('api_dispatch_gesture')) {
    const isA11yConfirmed = isHypothesisConfirmed('ACCESSIBILITY') || isHypothesisConfirmed('OVERLAY');
    addNode({
      id: 'behavior_overlay_hijack',
      type: 'BEHAVIOR',
      label: 'UI Overlay & Click Automation',
      sublabel: isA11yConfirmed ? 'Verified Attack Pattern' : 'Inferred Attack Pattern',
      state: isA11yConfirmed ? 'RUNTIME_CONFIRMED' : 'INFERRED',
      evidenceId: 'H-A11Y-HIJACK',
      sourceEngine: 'ai-hypothesis-verifier',
      description: 'Renders phishing fake login screens over official banking apps and automates button clicks to bypass security prompts.',
      confidence: isA11yConfirmed ? 0.95 : 0.7,
      layer: 3,
      tags: ['behavior', 'overlay'],
    });
    if (nodeMap.has('api_dispatch_gesture')) addEdge('api_dispatch_gesture', 'behavior_overlay_hijack', 'SUPPORTS');
    if (nodeMap.has('data_screen_buffer')) addEdge('data_screen_buffer', 'behavior_overlay_hijack', 'SUPPORTS');
  }

  /* -------------------------------------------------------------------------
     LAYER 4: High-Level Banking Impact Nodes (DETERMINISTIC DERIVATIONS)
     ------------------------------------------------------------------------- */
  const subScores = result.risk?.sub_scores || { credential_theft: 0, payment_manipulation: 0, fraud_impersonation: 0, evasion_resilience: 0 };

  // 1. OTP Theft & Account Takeover
  if (nodeMap.has('behavior_otp_interception') || nodeMap.has('data_otp_token') || subScores.credential_theft >= 40) {
    addNode({
      id: 'impact_otp_theft',
      type: 'BANKING_IMPACT',
      label: 'OTP Theft',
      sublabel: 'Authentication Bypass',
      state: 'IMPACT',
      evidenceId: 'IMPACT-OTP',
      sourceEngine: 'deterministic-risk-engine',
      description: 'Attacker obtains valid real-time one-time passwords, rendering two-factor SMS verification ineffective.',
      confidence: isOtpConfirmed ? 0.98 : 0.85,
      layer: 4,
      tags: ['impact', 'banking', '2fa'],
    });
    if (nodeMap.has('behavior_otp_interception')) addEdge('behavior_otp_interception', 'impact_otp_theft', 'ENABLES');
    else if (nodeMap.has('data_otp_token')) addEdge('data_otp_token', 'impact_otp_theft', 'ENABLES');

    addNode({
      id: 'impact_account_takeover',
      type: 'BANKING_IMPACT',
      label: 'Account Takeover (ATO)',
      sublabel: 'Critical Fraud Consequence',
      state: 'IMPACT',
      evidenceId: 'IMPACT-ATO',
      sourceEngine: 'deterministic-risk-engine',
      description: 'Complete hijacking of victim banking portal session, enabling unauthorized login, beneficiary addition, and password reset.',
      confidence: isOtpConfirmed ? 0.96 : 0.82,
      layer: 4,
      tags: ['impact', 'banking', 'critical'],
    });
    addEdge('impact_otp_theft', 'impact_account_takeover', 'ENABLES', 'enables session hijack', isOtpConfirmed);
  }

  // 2. Credential Theft & Unauthorized Transactions
  if (nodeMap.has('behavior_overlay_hijack') || nodeMap.has('data_screen_buffer') || subScores.payment_manipulation >= 40) {
    addNode({
      id: 'impact_cred_theft',
      type: 'BANKING_IMPACT',
      label: 'Credential Theft',
      sublabel: 'Phishing / Keylogging',
      state: 'IMPACT',
      evidenceId: 'IMPACT-CRED',
      sourceEngine: 'deterministic-risk-engine',
      description: 'Harvesting of user netbanking login credentials, debit card numbers, CVVs, and ATM PINs.',
      confidence: 0.9,
      layer: 4,
      tags: ['impact', 'banking', 'credentials'],
    });
    if (nodeMap.has('behavior_overlay_hijack')) addEdge('behavior_overlay_hijack', 'impact_cred_theft', 'ENABLES');
    else if (nodeMap.has('data_screen_buffer')) addEdge('data_screen_buffer', 'impact_cred_theft', 'ENABLES');

    addNode({
      id: 'impact_unauth_tx',
      type: 'BANKING_IMPACT',
      label: 'Unauthorized Transaction Risk',
      sublabel: 'Direct Financial Loss',
      state: 'IMPACT',
      evidenceId: 'IMPACT-TX',
      sourceEngine: 'deterministic-risk-engine',
      description: 'Automated initiation and approval of rogue wire transfers, IMPS payments, or UPI debit mandates without user consent.',
      confidence: 0.92,
      layer: 4,
      tags: ['impact', 'banking', 'financial_loss'],
    });
    addEdge('impact_cred_theft', 'impact_unauth_tx', 'ENABLES', 'initiates rogue transfers');
    if (nodeMap.has('impact_account_takeover')) {
      addEdge('impact_account_takeover', 'impact_unauth_tx', 'ENABLES', 'executes fund drain');
    }
  }

  // 3. Remote Control / Payload Staging
  if (codeSignals.dynamic_code_loading?.detected || requested.includes('android.permission.REQUEST_INSTALL_PACKAGES')) {
    addNode({
      id: 'impact_remote_control',
      type: 'BANKING_IMPACT',
      label: 'Remote Device Control / Payload Staging',
      sublabel: 'Post-Exploitation Capability',
      state: 'IMPACT',
      evidenceId: 'IMPACT-RMT',
      sourceEngine: 'deterministic-risk-engine',
      description: 'Enables remote adversary to push secondary malware modules or execute arbitrary code bypassing security controls.',
      confidence: 0.88,
      layer: 4,
      tags: ['impact', 'dropper'],
    });
    if (nodeMap.has('api_dex_loader')) addEdge('api_dex_loader', 'impact_remote_control', 'ENABLES');
    if (nodeMap.has('perm_install_pkgs')) addEdge('perm_install_pkgs', 'impact_remote_control', 'ENABLES');
  }

  // 4. Sensitive Data Exfiltration (fallback if internet and data exist)
  if (nodeMap.has('net_c2_endpoint') && !nodeMap.has('impact_otp_theft') && !nodeMap.has('impact_cred_theft')) {
    addNode({
      id: 'impact_data_exfil',
      type: 'BANKING_IMPACT',
      label: 'Sensitive Data Exfiltration',
      sublabel: 'Privacy & Telemetry Breach',
      state: 'IMPACT',
      evidenceId: 'IMPACT-EXFIL',
      sourceEngine: 'deterministic-risk-engine',
      description: 'Unauthorized transmission of device identifiers, app lists, or metadata to external servers.',
      confidence: 0.8,
      layer: 4,
      tags: ['impact', 'exfiltration'],
    });
    addEdge('net_c2_endpoint', 'impact_data_exfil', 'ENABLES');
  }

  const impactNodes = nodes.filter((n) => n.type === 'BANKING_IMPACT');
  const confirmedCount = nodes.filter((n) => n.state === 'RUNTIME_CONFIRMED').length;
  const staticCount = nodes.filter((n) => n.state === 'STATIC').length;

  return {
    nodes,
    edges,
    summary: {
      totalNodes: nodes.length,
      totalEdges: edges.length,
      impactCount: impactNodes.length,
      confirmedCount,
      staticCount,
    },
    impactNodes,
  };
}
