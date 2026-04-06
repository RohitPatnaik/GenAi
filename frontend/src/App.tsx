import { useEffect, useMemo, useState } from 'react';

type Vuln = {
  id?: number;
  cve: string;
  cwe?: string | null;
  title?: string | null;
  description?: string | null;
  has_script?: number;
  script_path?: string | null;
  cvss_score?: number | null;
  severity?: string | null;
};

type FileItem = {
  name: string;
  path: string;
  size: number;
  mtime: number;
};

type Job = {
  id: string;
  status: string;
  stage?: string | null;
  job_name?: string | null;
  target_url?: string | null;
  input_file?: string | null;
  output_file?: string | null;
  started_at?: string | null;
  ended_at?: string | null;
  returncode?: number | null;
  error?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
};

type ScanEvent = {
  id: number;
  job_id: string;
  stage: string;
  level: string;
  message: string;
  created_at: string;
};

type SummaryReport = {
  timestamp: string;
  target_url: string;
  total_vulnerabilities: number;
  successful: number;
  failed: number;
  sandbox_results?: Array<{ cve: string; sandbox_target: string; success: boolean; returncode?: number | null; error?: string | null }>;
  details: Array<{
    cve: string;
    action?: string;
    success?: boolean;
    final_script_path?: string | null;
    attempts?: Array<{ type?: string; test_result?: { success?: boolean } }>;
  }>;
};

const API = 'http://localhost:8000';
const USE_CLIENT_FILTER = false;
const STAGES = [
  { key: 'ingest', name: 'Ingestion', desc: 'Receive scan input' },
  { key: 'parse', name: 'Normalize', desc: 'Parse and normalize scanner data' },
  { key: 'match', name: 'Match', desc: 'Match CVEs and enrich' },
  { key: 'kb', name: 'Knowledgebase', desc: 'Check scripts in KB' },
  { key: 'generate', name: 'Generate', desc: 'LLM script generation' },
  { key: 'sandbox', name: 'Validate', desc: 'Execute and validate scripts' },
  { key: 'report', name: 'Report', desc: 'Aggregate and export findings' },
];

function useClock() {
  const [t, setT] = useState(new Date());
  useEffect(() => {
    const id = setInterval(() => setT(new Date()), 1000);
    return () => clearInterval(id);
  }, []);
  return t.toTimeString().slice(0, 8);
}

async function fetchJson<T>(url: string, timeoutMs = 12000): Promise<T> {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  const res = await fetch(url, { signal: controller.signal });
  clearTimeout(t);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

function sevLabel(v: Vuln) {
  const s = (v.severity || '').toLowerCase();
  if (s) return s;
  if (v.cvss_score == null) return 'unknown';
  if (v.cvss_score >= 9) return 'critical';
  if (v.cvss_score >= 7) return 'high';
  if (v.cvss_score >= 4) return 'medium';
  return 'low';
}

function sevClass(label: string) {
  if (label === 'critical') return 'sev-c';
  if (label === 'high') return 'sev-h';
  if (label === 'medium') return 'sev-m';
  if (label === 'low') return 'sev-l';
  return 'sev-l';
}

function toTime(ts?: string | null) {
  if (!ts) return '--:--:--';
  try {
    return new Date(ts).toTimeString().slice(0, 8);
  } catch {
    return '--:--:--';
  }
}

export default function App() {
  const [view, setView] = useState('dashboard');
  const [clientId] = useState(() => {
    const key = 'vulnops_client_id';
    let id = localStorage.getItem(key);
    if (!id) {
      id = crypto.randomUUID();
      localStorage.setItem(key, id);
    }
    return id;
  });
  const [vulns, setVulns] = useState<Vuln[]>([]);
  const [hasLoaded, setHasLoaded] = useState(false);
  const [loadedViews, setLoadedViews] = useState<Record<string, boolean>>({});
  const [reports, setReports] = useState<FileItem[]>([]);
  const [scriptResults, setScriptResults] = useState<FileItem[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [job, setJob] = useState<Job | null>(null);
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [apiDown, setApiDown] = useState(false);
  const [summary, setSummary] = useState<SummaryReport | null>(null);
  const [reportViewId, setReportViewId] = useState<number | null>(null);
  const [reportViewData, setReportViewData] = useState<SummaryReport | null>(null);
  const [reportLoading, setReportLoading] = useState(false);
  const [reportSelectedCve, setReportSelectedCve] = useState<string | null>(null);
  const [reportResultMap, setReportResultMap] = useState<Record<string, any>>({});
  const [scriptViewId, setScriptViewId] = useState<number | null>(null);
  const [scriptViewData, setScriptViewData] = useState<any | null>(null);
  const [scriptLoading, setScriptLoading] = useState(false);
  const [target, setTarget] = useState('https://pentest-ground.com:4280');
  const [modalOpen, setModalOpen] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [lastIngest, setLastIngest] = useState<{ input_path: string; output_path: string; count: number } | null>(null);
  const [form, setForm] = useState({
    job_name: '',
    priority: 'Medium',
    source_type: 'file',
    exploit_mode: 'Parallel',
    fallback_llm: 'OpenAI GPT-4',
    validation_mode: 'Syntax + safety',
  });
  const clock = useClock();

  const runWithLoading = async <T,>(promise: Promise<T>): Promise<T> => promise;

  const withClient = (url: string) => {
    if (!USE_CLIENT_FILTER) return url;
    const joiner = url.includes('?') ? '&' : '?';
    return `${url}${joiner}client_id=${clientId}`;
  };

  const fetchJsonTracked = async <T,>(url: string, opts?: { silent?: boolean }): Promise<T> => {
    if (opts?.silent) return fetchJson<T>(url);
    return runWithLoading(fetchJson<T>(url));
  };

  const loadReportsAndResults = async (silent: boolean) => {
    try {
      const r = await fetchJsonTracked<{ items: any[] }>(withClient(`${API}/api/reports?lite=1`), { silent });
      if ((r.items || []).length === 0) throw new Error('empty');
      setReports(r.items || []);
    } catch {
      const rAll = await fetchJsonTracked<{ items: any[] }>(`${API}/api/reports?lite=1`, { silent });
      setReports(rAll.items || []);
    }

    try {
      const s = await fetchJsonTracked<{ items: any[] }>(withClient(`${API}/api/script-results?lite=1`), { silent });
      if ((s.items || []).length === 0) throw new Error('empty');
      setScriptResults(s.items || []);
    } catch {
      const sAll = await fetchJsonTracked<{ items: any[] }>(`${API}/api/script-results?lite=1`, { silent });
      setScriptResults(sAll.items || []);
    }
  };

  const logs = useMemo(() => {
    const ordered = [...events].reverse();
    return ordered.slice(-250);
  }, [events]);

  const liveExploited = useMemo(() => {
    const set = new Set<string>();
    for (const l of logs) {
      if (l.stage !== 'sandbox') continue;
      if (!l.message.includes('completed (return code 0)')) continue;
      const m = l.message.match(/CVE-\d{4}-\d+/);
      if (m) set.add(m[0]);
    }
    return set.size;
  }, [logs]);

  const stats = useMemo(() => {
    const crit = vulns.filter(v => sevLabel(v) === 'critical').length;
    const high = vulns.filter(v => sevLabel(v) === 'high').length;
    const med = vulns.filter(v => sevLabel(v) === 'medium').length;
    const low = vulns.filter(v => sevLabel(v) === 'low').length;
    const kb = vulns.filter(v => v.has_script === 1 || v.script_path).length;
    const exploited = summary ? (summary.sandbox_results || []).filter(r => r.success).length : liveExploited;
    return { total: vulns.length, crit, high, med, low, kb, exploited };
  }, [vulns, summary, liveExploited]);

  useEffect(() => {
    let stopped = false;
    const load = async () => {
      if (stopped || apiDown) return;
      try {
        const silent = loadedViews[view] === true;
        if (view === 'dashboard' || view === 'vulns') {
          const v = await fetchJsonTracked<{ items: Vuln[] }>(`${API}/api/vulns`, { silent });
          setVulns(v.items || []);
        }
        let jRes: { items: Job[] } | null = null;
        if (view === 'dashboard') {
          jRes = await fetchJsonTracked<{ items: Job[] }>(withClient(`${API}/api/scan/jobs`), { silent });
          setJobs(jRes.items || []);
        }
        if (view === 'report') {
          await loadReportsAndResults(silent);
        }
        if (jRes) {
          const running = (jRes.items || []).find(x => x.status === 'running');
          if (running && (!job || job.id !== running.id)) {
            setJob(running);
          } else if (!running && (!job && (jRes.items || []).length)) {
            setJob(jRes.items[0]);
          }
        }
        try {
          if (view === 'dashboard') {
          const latest = await fetchJsonTracked<SummaryReport>(withClient(`${API}/api/reports/latest`), { silent });
          setSummary(latest);
          }
        } catch {
          if (view === 'dashboard') setSummary(null);
        }
        if (!hasLoaded) setHasLoaded(true);
        if (!loadedViews[view]) setLoadedViews(prev => ({ ...prev, [view]: true }));
      } catch (e: any) {
        setApiDown(true);
      }
    };
    load();
    const shouldPoll = view === 'dashboard' || view === 'report';
    const intervalMs = view === 'report' ? 15000 : 5000;
    const id = shouldPoll ? setInterval(load, intervalMs) : null;
    return () => {
      stopped = true;
      if (id) clearInterval(id);
    };
  }, [apiDown, view]);

  useEffect(() => {
    if (!job?.id || apiDown) return;
    let stopped = false;
    const poll = async () => {
      if (stopped) return;
      try {
        const j = await fetchJsonTracked<Job>(withClient(`${API}/api/scan/${job.id}`), { silent: true });
        setJob(j);
        const ev = await fetchJsonTracked<{ items: ScanEvent[] }>(withClient(`${API}/api/scan/${job.id}/events`), { silent: true });
        setEvents(ev.items || []);
        if (!stopped) {
          const delay = j.status === 'running' ? 1500 : 3000;
          setTimeout(poll, delay);
        }
      } catch {
        // ignore
      }
    };
    poll();
    return () => {
      stopped = true;
    };
  }, [job?.id]);

  const startScan = async () => {
    let inputFile = lastIngest?.output_path || null;
    let sourcePath = lastIngest?.input_path || null;

    if (form.source_type === 'file' && selectedFile) {
      const fd = new FormData();
      fd.append('file', selectedFile);
      const res = await runWithLoading(fetch(`${API}/api/ingest`, { method: 'POST', body: fd }));
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      inputFile = data.output_path;
      sourcePath = data.input_path;
      setLastIngest({ input_path: data.input_path, output_path: data.output_path, count: data.count });
    }

    const payload = {
      job_name: form.job_name || `SCAN-${Date.now().toString().slice(-6)}`,
      priority: form.priority,
      source_type: form.source_type,
      source_path: sourcePath,
      exploit_mode: form.exploit_mode,
      fallback_llm: form.fallback_llm,
      validation_mode: form.validation_mode,
      target_url: target,
      input_file: inputFile || 'input/norm_input_newt.json',
      client_id: clientId
    };

    const res = await runWithLoading(fetch(`${API}/api/scan/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    }));
    const data = await res.json();
    if (data.job_id) {
      setJob({ id: data.job_id, status: 'running', stage: 'ingest', job_name: payload.job_name, target_url: target });
      setEvents([]);
    }
    setModalOpen(false);
  };

  const openReportPage = async (id: number, jobId?: string) => {
    setReportViewId(id);
    setReportLoading(true);
    setView('reportDetail');
    try {
      const data = await fetchJsonTracked<SummaryReport>(withClient(`${API}/api/report/${id}`));
      setReportViewData(data);
      setReportSelectedCve(null);
      if (jobId) {
        const res = await fetchJsonTracked<{ items: any[] }>(withClient(`${API}/api/script-results?job_id=${jobId}`));
        const map: Record<string, any> = {};
        for (const r of res.items || []) {
          if (r.cve && !map[r.cve]) map[r.cve] = r;
        }
        setReportResultMap(map);
      } else {
        setReportResultMap({});
      }
    } catch {
      setReportViewData(null);
      setReportSelectedCve(null);
      setReportResultMap({});
    } finally {
      setReportLoading(false);
    }
  };

  const openScriptResult = async (id: number) => {
    setScriptViewId(id);
    setScriptLoading(true);
    setView('scriptDetail');
    try {
      const data = await fetchJsonTracked<any>(withClient(`${API}/api/script-result/${id}`));
      setScriptViewData(data);
    } catch {
      setScriptViewData(null);
    } finally {
      setScriptLoading(false);
    }
  };

  const exploitRows = useMemo(() => {
    if (summary) {
      return summary.details.map(d => {
        const src = d.action === 'run' ? 'KB' : 'LLM';
        const validated = !!d.attempts?.some(a => a.test_result?.success);
        const script = d.final_script_path ? d.final_script_path.split(/[\\/]/).pop() || d.cve : d.cve;
        const sb = summary.sandbox_results?.find(r => r.cve === d.cve);
        const sandbox = sb ? (sb.success ? 'VULNERABLE' : 'BLOCKED') : 'QUEUED';
        return { cve: d.cve, script, src, validated, sandbox };
      });
    }

    if (!logs.length) return [] as Array<{ cve: string; script: string; src: string; validated: boolean; sandbox: string }>;

    const statusByCve = new Map<string, { sandbox: string; validated: boolean }>();
    for (const l of logs) {
      if (l.stage !== 'sandbox') continue;
      const m = l.message.match(/CVE-\d{4}-\d+/);
      if (!m) continue;
      const cve = m[0];
      if (l.message.includes('completed (return code 0)')) {
        statusByCve.set(cve, { sandbox: 'VULNERABLE', validated: true });
      } else if (l.message.includes('completed (return code')) {
        statusByCve.set(cve, { sandbox: 'BLOCKED', validated: false });
      }
    }

    return vulns.map(v => {
      const status = statusByCve.get(v.cve);
      const src = v.script_path ? 'KB' : 'LLM';
      const script = v.script_path ? (v.script_path.split(/[\\/]/).pop() || v.cve) : v.cve;
      const finished = job && (job.status === 'finished' || job.status === 'failed');
      const sandbox = status ? status.sandbox : (finished ? 'BLOCKED' : 'QUEUED');
      const validated = status ? status.validated : false;
      return { cve: v.cve, script, src, validated, sandbox };
    });
  }, [summary, logs, vulns, job]);

  const dockerDown = useMemo(() => {
    return logs.some(l => l.level === 'error' && l.message.toLowerCase().includes('docker not running'));
  }, [logs]);

  const currentStageKey = useMemo(() => {
    if (job?.stage) return job.stage;
    if (events.length) return events[events.length - 1].stage;
    return null;
  }, [job?.stage, events]);

  const stageIndex = useMemo(() => {
    if (!currentStageKey) return -1;
    return STAGES.findIndex(s => s.key === currentStageKey);
  }, [currentStageKey]);

  const progressPct = useMemo(() => {
    if (!job || job.status !== 'running') return 0;
    if (stageIndex < 0) return 0;
    if (STAGES.length <= 1) return 0;
    return Math.round((stageIndex / (STAGES.length - 1)) * 100);
  }, [job, stageIndex]);

  const stageState = (idx: number) => {
    if (!job || job.status !== 'running') return 'waiting';
    if (job.status === 'failed' && idx === stageIndex) return 'error';
    if (stageIndex < 0) return 'waiting';
    if (idx < stageIndex) return 'done';
    if (idx === stageIndex) return 'running';
    return 'waiting';
  };

  const badgeFor = (state: string) => {
    if (state === 'running') return 'RUNNING';
    if (state === 'done') return 'DONE';
    if (state === 'error') return 'ERROR';
    return 'WAITING';
  };

  const classifyResult = (
    cve: string,
    action?: string,
    attempts?: Array<any>,
    final_script_path?: string | null,
    fallbackResult?: any
  ) => {
    const lastAttempt = attempts && attempts.length ? attempts[attempts.length - 1] : null;
    const test = lastAttempt?.test_result || fallbackResult;
    const stdout = (test?.stdout || '').toLowerCase();
    const stderr = (test?.stderr || '').toLowerCase();
    const error = (test?.error || '').toLowerCase();
    const returncode = test?.returncode;
    const marker = "[exploit confirmed]";

    const keywordHit =
      stdout.includes('vulnerable') ||
      stdout.includes('exploit succeeded') ||
      stdout.includes('successfully exploited');

    const hasExecError =
      error.includes('docker not running') ||
      error.includes('timeout') ||
      error.includes('connection') ||
      error.includes('network') ||
      stderr.includes('docker not running') ||
      stderr.includes('timeout') ||
      stderr.includes('connection') ||
      stderr.includes('network');

    if (action === 'generate' && !final_script_path && attempts && attempts.length) {
      return { category: 'Generation Failed', reason: 'LLM failed to generate a working script' };
    }

    if (hasExecError) {
      return { category: 'Execution Error', reason: 'Environment or runtime failure' };
    }

    if (returncode === 0 && stdout.includes(marker)) {
      return { category: 'Vulnerable (Confirmed)', reason: 'Exploit confirmed by evidence marker' };
    }

    if (returncode !== undefined && returncode !== null) {
      return { category: 'Not Vulnerable', reason: 'Exploit ran but no confirmation marker' };
    }

    return { category: 'Not Vulnerable', reason: 'No confirmation of vulnerability' };
  };

  const categoryClass = (category: string) => {
    if (category === 'Vulnerable (Confirmed)') return 'finding-vuln';
    if (category === 'Execution Error') return 'finding-execerr';
    if (category === 'Generation Failed') return 'finding-genfail';
    return 'finding-notvuln';
  };

  return (
    <div>
      <div className={`modal-bg ${modalOpen ? 'open' : ''}`}>
        <div className="modal">
          <div className="modal-header">
            <span style={{ fontFamily: 'var(--display)', fontWeight: 700, fontSize: 15, color: '#fff' }}>NEW SCAN JOB</span>
            <span className="modal-close" onClick={() => setModalOpen(false)}>x</span>
          </div>
          <div className="modal-body">
            <div className="row">
              <div className="col">
                <div className="label">Job name</div>
                <input className="input" value={form.job_name} onChange={(e) => setForm({ ...form, job_name: e.target.value })} placeholder="Job name" />
              </div>
              <div className="col">
                <div className="label">Priority</div>
                <select className="select" style={{ width: '100%' }} value={form.priority} onChange={(e) => setForm({ ...form, priority: e.target.value })}>
                  <option>Critical</option>
                  <option>High</option>
                  <option>Medium</option>
                  <option>Low</option>
                </select>
              </div>
            </div>

            <div className="label" style={{ marginBottom: 6 }}>Log source</div>
            <div className="ingest-grid" style={{ marginBottom: 16 }}>
              <div className={`ingest-card ${form.source_type === 'file' ? 'selected' : ''}`} onClick={() => setForm({ ...form, source_type: 'file' })}>
                <div className="ingest-icon">FILE</div>
                <div className="ingest-title">FILE UPLOAD</div>
                <div className="ingest-sub">Browse local file</div>
              </div>
              <div className={`ingest-card ${form.source_type === 'api' ? 'selected' : ''}`} onClick={() => setForm({ ...form, source_type: 'api' })}>
                <div className="ingest-icon">API</div>
                <div className="ingest-title">API ENDPOINT</div>
                <div className="ingest-sub">REST or Webhook</div>
              </div>
              <div className={`ingest-card ${form.source_type === 's3' ? 'selected' : ''}`} onClick={() => setForm({ ...form, source_type: 's3' })}>
                <div className="ingest-icon">S3</div>
                <div className="ingest-title">BLOB / S3</div>
                <div className="ingest-sub">Cloud storage</div>
              </div>
            </div>

            <div className="drop-zone" onClick={() => document.getElementById('file-inp')?.click()}>
              <div style={{ fontSize: 20, opacity: 0.5 }}>UPLOAD</div>
              <div className="drop-text">Drop scanner log file here or click to browse</div>
              <div style={{ fontSize: 10, color: 'var(--text3)', marginTop: 6 }}>.log .txt .json .xml .csv accepted</div>
              <input id="file-inp" type="file" style={{ display: 'none' }} onChange={(e) => setSelectedFile(e.target.files?.[0] || null)} />
            </div>
            {selectedFile && <div className="file-pill">Selected: {selectedFile.name}</div>}

            <div className="row" style={{ marginTop: 16 }}>
              <div className="col">
                <div className="label">Exploit mode</div>
                <select className="select" style={{ width: '100%' }} value={form.exploit_mode} onChange={(e) => setForm({ ...form, exploit_mode: e.target.value })}>
                  <option>Parallel</option>
                  <option>Sequential</option>
                  <option>Orchestrator decides</option>
                </select>
              </div>
              <div className="col">
                <div className="label">Fallback LLM</div>
                <select className="select" style={{ width: '100%' }} value={form.fallback_llm} onChange={(e) => setForm({ ...form, fallback_llm: e.target.value })}>
                  <option>OpenAI GPT-4</option>
                  <option>Anthropic Claude</option>
                  <option>Mistral</option>
                  <option>Auto</option>
                </select>
              </div>
            </div>

            <div className="row">
              <div className="col">
                <div className="label">Script validation</div>
                <select className="select" style={{ width: '100%' }} value={form.validation_mode} onChange={(e) => setForm({ ...form, validation_mode: e.target.value })}>
                  <option>Syntax + safety + human gate</option>
                  <option>Syntax + safety</option>
                  <option>Syntax only</option>
                  <option>Full automated pipeline</option>
                </select>
              </div>
            </div>

            <div className="row">
              <div className="col">
                <div className="label">Target URL</div>
                <input className="input" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="https://target" />
              </div>
            </div>

            <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
              <button className="btn btn-primary" style={{ flex: 1 }} onClick={startScan}>LAUNCH SCAN</button>
              <button className="btn btn-ghost" onClick={() => setModalOpen(false)}>CANCEL</button>
            </div>
          </div>
        </div>
      </div>

      <div className="shell">
        <div className="topbar">
          <div className="logo">VULN<span>OPS</span></div>
          <div style={{ width: 1, height: 20, background: 'var(--border)', margin: '0 4px' }}></div>
          <span style={{ fontSize: 10, color: 'var(--text3)', letterSpacing: '.1em' }}>AI PENTEST ORCHESTRATOR</span>
          <div className="top-status">
            <span className="top-label">SYSTEM</span>
            <div className="pulse"></div>
            <span className="top-label" style={{ color: 'var(--accent4)' }}>ONLINE</span>
            <div style={{ width: 1, height: 16, background: 'var(--border)' }}></div>
            <span className="clock">{clock}</span>
          </div>
        </div>

        <nav className="sidebar">
          <div className="nav-section">Operations</div>
          <div className={`nav-item ${view==='dashboard'?'active':''}`} onClick={() => setView('dashboard')}><span className="nav-icon">D</span>Dashboard</div>
          <div className={`nav-item ${view==='ingest'?'active':''}`} onClick={() => setView('ingest')}><span className="nav-icon">I</span>Ingestion</div>
          <div className={`nav-item ${view==='vulns'?'active':''}`} onClick={() => setView('vulns')}><span className="nav-icon">V</span>Vulnerabilities<span className="nav-badge">{vulns.length}</span></div>

          <div className="nav-section">Analysis</div>
          <div className={`nav-item ${view==='exploits'?'active':''}`} onClick={() => setView('exploits')}><span className="nav-icon">E</span>Exploits</div>
          <div className={`nav-item ${view==='kb'?'active':''}`} onClick={() => setView('kb')}><span className="nav-icon">K</span>Knowledgebase</div>

          <div className="nav-section">Output</div>
          <div className={`nav-item ${view==='report'?'active':''}`} onClick={() => setView('report')}><span className="nav-icon">R</span>Reports<span className="nav-badge green">{reports.length}</span></div>

          <div style={{ marginTop: 'auto', padding: 16 }}>
            <button className="btn btn-primary" style={{ width: '100%', justifyContent: 'center' }} onClick={() => setModalOpen(true)}>+ NEW SCAN</button>
          </div>
        </nav>

        <main className="main">
          {view === 'dashboard' && (
            <div className="view">
              {dockerDown && (
                <div className="banner">Docker is not running. Start Docker Desktop to enable sandbox isolation.</div>
              )}
              <div className="page-header">
                <div>
                  <div className="page-title">Dashboard</div>
                  <div className="page-sub">Real-time pipeline overview</div>
                </div>
                <button className="btn btn-primary" onClick={() => setModalOpen(true)}>+ NEW SCAN</button>
              </div>

              <div className="stat-grid">
                <div className="stat-card">
                  <div className="stat-val blue">{jobs.length}</div>
                  <div className="stat-lbl">Total scans</div>
                  <div className="stat-delta">{job?.status === 'running' ? '1 active' : 'idle'}</div>
                </div>
                <div className="stat-card">
                  <div className="stat-val red">{stats.crit}</div>
                  <div className="stat-lbl">Critical vulns</div>
                  <div className="stat-delta">{stats.high} high</div>
                </div>
                <div className="stat-card">
                  <div className="stat-val yellow">{stats.kb}</div>
                  <div className="stat-lbl">Scripts in KB</div>
                  <div className="stat-delta">{stats.total} total</div>
                </div>
                <div className="stat-card">
                  <div className="stat-val green">{stats.exploited}</div>
                  <div className="stat-lbl">Exploits confirmed</div>
                  <div className="stat-delta">via sandbox</div>
                </div>
              </div>

              <div className="card">
                <div className="card-header">
                  <span className="card-title">Active pipeline — {job?.status === 'running' ? (job.job_name || 'RUNNING') : 'No Active Job'}</span>
                  <span style={{ fontSize: 10, color: 'var(--text3)' }}>{job?.status === 'running' ? `${progressPct}%` : '0%'}</span>
                </div>
                <div className="pipeline">
                  {STAGES.map((s, i) => {
                    const state = stageState(i);
                    return (
                      <div key={s.key} className={`stage ${state}`}>
                        <div className="stage-num">{String(i + 1).padStart(2, '0')}</div>
                        <div className="stage-name">{s.name}</div>
                        <div className="stage-desc">{s.desc}</div>
                        <div className={`stage-badge badge-${state === 'done' ? 'done' : state === 'running' ? 'run' : state === 'error' ? 'err' : 'wait'}`}>
                          {badgeFor(state)}
                        </div>
                      </div>
                    );
                  })}
                </div>
                <div className="prog-wrap">
                  <div className={`prog-bar ${job?.status === 'running' ? 'animate' : ''}`} style={{ width: `${progressPct}%` }} />
                </div>
              </div>

              <div className="card">
                <div className="card-header"><span className="card-title">Live log feed</span><span style={{ fontSize: 10, color: 'var(--text3)' }}>TAIL</span></div>
                <div className="terminal">
                  {logs.length === 0 && <span className="line"><span className="t-data">No logs yet</span></span>}
                  {logs.map((l) => (
                    <span key={l.id} className="line">
                      <span className="t-time">[{toTime(l.created_at)}]</span>{' '}
                      <span className={l.level === 'error' ? 't-err' : l.level === 'warn' ? 't-warn' : l.level === 'info' ? 't-info' : 't-data'}>[{l.stage.toUpperCase()}]</span>{' '}
                      <span className="t-data">{l.message}</span>
                    </span>
                  ))}
                </div>
              </div>
            </div>
          )}

          {view === 'ingest' && (
            <div className="view">
              <div className="page-header">
                <div>
                  <div className="page-title">Ingestion</div>
                  <div className="page-sub">Upload raw scan JSON</div>
                </div>
              </div>
              <div className="card">
                <div className="card-header"><span className="card-title">Upload</span></div>
                <input className="input" type="file" onChange={async (e) => {
                  const f = e.target.files?.[0];
                  if (!f) return;
                  const fd = new FormData();
                  fd.append('file', f);
                  const res = await fetch(`${API}/api/ingest`, { method: 'POST', body: fd });
                  if (!res.ok) return;
                  const data = await res.json();
                  setLastIngest({ input_path: data.input_path, output_path: data.output_path, count: data.count });
                }} />
                {lastIngest && (
                  <div style={{ marginTop: 10, fontSize: 11, color: 'var(--text2)' }}>
                    <div>Input: {lastIngest.input_path}</div>
                    <div>Normalized: {lastIngest.output_path}</div>
                    <div>Items: {lastIngest.count}</div>
                  </div>
                )}
              </div>
            </div>
          )}

          {view === 'vulns' && (
            <div className="view">
              <div className="page-header">
                <div>
                  <div className="page-title">Vulnerabilities</div>
                  <div className="page-sub">DB records</div>
                </div>
              </div>
              <div className="card">
                <table className="table">
                  <thead>
                    <tr><th>CVE</th><th>Title</th><th>Severity</th><th>CVSS</th><th>Script</th></tr>
                  </thead>
                  <tbody>
                    {vulns.map(v => {
                      const label = sevLabel(v);
                      return (
                        <tr key={v.cve}>
                          <td style={{ color: 'var(--accent)' }}>{v.cve}</td>
                          <td>{v.title || v.description || '-'}</td>
                          <td><span className={`sev ${sevClass(label)}`}>{label.toUpperCase()}</span></td>
                          <td>{v.cvss_score ?? '-'}</td>
                          <td>{v.script_path ? 'KB' : '-'}</td>
                        </tr>
                      );
                    })}
                    {!vulns.length && (
                      <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--text3)', padding: 30 }}>No data</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {view === 'exploits' && (
            <div className="view">
              <div className="page-header">
                <div>
                  <div className="page-title">Exploits</div>
                  <div className="page-sub">Generated and validated scripts</div>
                </div>
              </div>
              <div className="card">
                <table className="table">
                  <thead>
                    <tr><th>CVE</th><th>Script</th><th>Source</th><th>Validation</th><th>Sandbox</th></tr>
                  </thead>
                  <tbody>
                    {exploitRows.map(e => (
                      <tr key={e.cve}>
                        <td style={{ color: 'var(--accent)' }}>{e.cve}</td>
                        <td>{e.script}</td>
                        <td>{e.src}</td>
                        <td>{e.validated ? 'PASSED' : 'PENDING'}</td>
                        <td>{e.sandbox}</td>
                      </tr>
                    ))}
                    {!exploitRows.length && (
                      <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--text3)', padding: 30 }}>No exploit data yet</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {view === 'kb' && (
            <div className="view">
              <div className="page-header">
                <div>
                  <div className="page-title">Knowledgebase</div>
                  <div className="page-sub">Script paths from DB</div>
                </div>
              </div>
              <div className="kb-grid">
                {vulns.filter(v => v.script_path).map(v => (
                  <div className="kb-card" key={v.cve}>
                    <div style={{ fontSize: 12, fontWeight: 600, color: '#fff' }}>{v.cve}</div>
                    <div style={{ fontSize: 10, color: 'var(--text2)', marginTop: 6 }}>{v.title}</div>
                    <div style={{ fontSize: 10, color: 'var(--accent)', marginTop: 8 }}>{v.script_path}</div>
                  </div>
                ))}
                {!vulns.filter(v => v.script_path).length && (
                  <div className="kb-card">No scripts in KB</div>
                )}
              </div>
            </div>
          )}

          {view === 'report' && (
            <div className="view">
              <div className="page-header">
                <div>
                  <div className="page-title">Reports</div>
                  <div className="page-sub">Executor + script results</div>
                </div>
              </div>
              <div className="card">
                <div className="card-header"><span className="card-title">Executor reports</span></div>
                <ul style={{ fontSize: 11, color: 'var(--text2)' }}>
                  {reports.map((r: any) => (
                    <li key={r.id} style={{ display: 'flex', justifyContent: 'space-between', gap: 10 }}>
                      <span>report_{r.id} (job {r.job_id})</span>
                      <div style={{ display: 'flex', gap: 8 }}>
                        <button className="btn btn-ghost btn-sm" onClick={() => openReportPage(r.id, r.job_id)}>VIEW</button>
                        <a className="btn btn-ghost btn-sm" href={withClient(`${API}/api/report-file/${r.id}`)}>DOWNLOAD</a>
                      </div>
                    </li>
                  ))}
                  {!reports.length && <li>No reports yet</li>}
                </ul>
              </div>

              <div className="card">
                <div className="card-header"><span className="card-title">Script results</span></div>
                <ul style={{ fontSize: 11, color: 'var(--text2)' }}>
                  {scriptResults.map((r: any) => (
                    <li key={r.id} style={{ display: 'flex', justifyContent: 'space-between', gap: 10 }}>
                      <span>{r.cve} (job {r.job_id})</span>
                      <div style={{ display: 'flex', gap: 8 }}>
                        <button className="btn btn-ghost btn-sm" onClick={() => openScriptResult(r.id)}>VIEW</button>
                        <a className="btn btn-ghost btn-sm" href={withClient(`${API}/api/script-result-file/${r.id}`)}>DOWNLOAD</a>
                      </div>
                    </li>
                  ))}
                  {!scriptResults.length && <li>No script results yet</li>}
                </ul>
              </div>
            </div>
          )}

          {view === 'reportDetail' && (
            <div className="view">
              <div className="page-header">
                <div>
                  <div className="page-title">Report Detail</div>
                  <div className="page-sub">Report {reportViewId ?? '-'}</div>
                </div>
                <button className="btn btn-ghost" onClick={() => setView('report')}>Back to Reports</button>
              </div>
              <div className="card">
                {reportLoading && <div style={{ fontSize: 11, color: 'var(--text2)' }}>Loading…</div>}
                {!reportLoading && !reportViewData && (
                  <div style={{ fontSize: 11, color: 'var(--text3)' }}>Report not found.</div>
                )}
                {!reportLoading && reportViewData && (
                  <div>
                    {(() => {
                      const counts = {
                        vulnerable: 0,
                        notVuln: 0,
                        execErr: 0,
                        genFail: 0
                      };
                      reportViewData.details?.forEach(d => {
                        const cls = classifyResult(d.cve, d.action, d.attempts, d.final_script_path, reportResultMap[d.cve]);
                        if (cls.category === 'Vulnerable (Confirmed)') counts.vulnerable++;
                        else if (cls.category === 'Execution Error') counts.execErr++;
                        else if (cls.category === 'Generation Failed') counts.genFail++;
                        else counts.notVuln++;
                      });
                      return (
                        <div style={{ display: 'flex', gap: 24, marginBottom: 16, flexWrap: 'wrap' }}>
                          <div>
                            <div className="stat-val green" style={{ fontSize: 22 }}>{counts.vulnerable}</div>
                            <div className="stat-lbl">Vulnerable</div>
                          </div>
                          <div>
                            <div className="stat-val yellow" style={{ fontSize: 22 }}>{counts.notVuln}</div>
                            <div className="stat-lbl">Not Vulnerable</div>
                          </div>
                          <div>
                            <div className="stat-val red" style={{ fontSize: 22 }}>{counts.execErr}</div>
                            <div className="stat-lbl">Execution Error</div>
                          </div>
                          <div>
                            <div className="stat-val blue" style={{ fontSize: 22 }}>{counts.genFail}</div>
                            <div className="stat-lbl">Generation Failed</div>
                          </div>
                          <div>
                            <div className="stat-val blue" style={{ fontSize: 22 }}>{reportViewData.total_vulnerabilities}</div>
                            <div className="stat-lbl">Total</div>
                          </div>
                        </div>
                      );
                    })()}
                    <div style={{ fontSize: 11, color: 'var(--text2)', marginBottom: 12 }}>
                      <div>Target: {reportViewData.target_url}</div>
                      <div>Timestamp: {reportViewData.timestamp}</div>
                    </div>
                    <div className="report-section">
                      <div className="report-title">Findings</div>
                      {reportViewData.details?.map((d, i) => {
                        const cls = classifyResult(d.cve, d.action, d.attempts, d.final_script_path, reportResultMap[d.cve]);
                        return (
                        <div key={`${d.cve}-${i}`}>
                          <div
                            className={`finding-card ${categoryClass(cls.category)}`}
                            onClick={() => setReportSelectedCve(prev => (prev === d.cve ? null : d.cve))}
                            style={{ cursor: 'pointer' }}
                          >
                            <div className="finding-title">{d.cve}</div>
                            <div className="finding-meta">
                              <span>Category: {cls.category}</span>
                              <span>Reason: {cls.reason}</span>
                              <span>Script: {d.final_script_path ? d.final_script_path.split(/[\\/]/).pop() : '-'}</span>
                            </div>
                            <div className="finding-body">
                              Attempts: {d.attempts ? d.attempts.length : 0}
                            </div>
                          </div>
                          {reportSelectedCve === d.cve && (() => {
                            const lastAttempt = d.attempts && d.attempts.length ? d.attempts[d.attempts.length - 1] : null;
                            const fallback = reportResultMap[d.cve];
                            const test = lastAttempt?.test_result || fallback;
                            return (
                              <div className="card" style={{ marginTop: 8 }}>
                                <div className="card-header"><span className="card-title">CVE Detail: {d.cve}</span></div>
                                <div className="report-section">
                                  <div className="finding-meta" style={{ marginBottom: 10 }}>
                                    <span>Category: {cls.category}</span>
                                    <span>Return code: {test?.returncode ?? '-'}</span>
                                    <span>Script path: {d.final_script_path || '-'}</span>
                                  </div>
                                  {test?.stdout && (
                                    <div className="finding-card">
                                      <div className="finding-title">Stdout</div>
                                      <div className="finding-body" style={{ whiteSpace: 'pre-wrap' }}>{test.stdout}</div>
                                    </div>
                                  )}
                                  {test?.stderr && (
                                    <div className="finding-card">
                                      <div className="finding-title">Stderr</div>
                                      <div className="finding-body" style={{ whiteSpace: 'pre-wrap' }}>{test.stderr}</div>
                                    </div>
                                  )}
                                  {test?.error && (
                                    <div className="finding-card">
                                      <div className="finding-title">Error</div>
                                      <div className="finding-body">{test.error}</div>
                                    </div>
                                  )}
                                </div>
                              </div>
                            );
                          })()}
                        </div>
                      )})}
                      {!reportViewData.details?.length && (
                        <div style={{ fontSize: 11, color: 'var(--text3)' }}>No details found.</div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {view === 'scriptDetail' && (
            <div className="view">
              <div className="page-header">
                <div>
                  <div className="page-title">Script Result Detail</div>
                  <div className="page-sub">Result {scriptViewId ?? '-'}</div>
                </div>
                <button className="btn btn-ghost" onClick={() => setView('report')}>Back to Reports</button>
              </div>
              <div className="card">
                {scriptLoading && <div style={{ fontSize: 11, color: 'var(--text2)' }}>Loading…</div>}
                {!scriptLoading && !scriptViewData && (
                  <div style={{ fontSize: 11, color: 'var(--text3)' }}>Result not found.</div>
                )}
                {!scriptLoading && scriptViewData && (
                  <div className="report-section">
                    <div className="report-title">{scriptViewData.cve}</div>
                    <div className="finding-meta" style={{ marginBottom: 10 }}>
                      <span>Category: {classifyResult(scriptViewData.cve, 'run', [], scriptViewData.script_path, scriptViewData).category}</span>
                    </div>
                    <div className="finding-meta" style={{ marginBottom: 10 }}>
                      <span>Stage: {scriptViewData.stage || '-'}</span>
                      <span>Status: {scriptViewData.success ? 'SUCCESS' : 'FAILED'}</span>
                      <span>Return code: {scriptViewData.returncode ?? '-'}</span>
                    </div>
                    <div className="finding-body" style={{ marginBottom: 10 }}>
                      Script: {scriptViewData.script_path || '-'}
                    </div>
                    {scriptViewData.error && (
                      <div className="finding-card">
                        <div className="finding-title">Error</div>
                        <div className="finding-body">{scriptViewData.error}</div>
                      </div>
                    )}
                    {scriptViewData.stdout && (
                      <div className="finding-card">
                        <div className="finding-title">Stdout</div>
                        <div className="finding-body" style={{ whiteSpace: 'pre-wrap' }}>{scriptViewData.stdout}</div>
                      </div>
                    )}
                    {scriptViewData.stderr && (
                      <div className="finding-card">
                        <div className="finding-title">Stderr</div>
                        <div className="finding-body" style={{ whiteSpace: 'pre-wrap' }}>{scriptViewData.stderr}</div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

