import axios from "axios";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export const api = axios.create({
  baseURL: `${API_URL}/api/v1`,
  headers: { "Content-Type": "application/json" },
  timeout: 30000,
});

// ─── Types ────────────────────────────────────────────────────────────────────

export type ScanStatus = "pending" | "running" | "completed" | "failed" | "cancelled";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type FindingCategory =
  | "xss" | "sqli" | "lfi" | "ssrf" | "rce" | "idor"
  | "open_redirect" | "csrf" | "xxe" | "ssti"
  | "misconfiguration" | "sensitive_data" | "other";

export interface Target {
  id: string;
  domain: string;
  description?: string;
  is_active: boolean;
  created_at: string;
}

export interface Scan {
  id: string;
  target_id: string;
  status: ScanStatus;
  steps_total: number;
  steps_completed: number;
  current_step?: string;
  assets_found: number;
  findings_count: number;
  error_message?: string;
  created_at: string;
  completed_at?: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  category: FindingCategory;
  severity: Severity;
  title: string;
  description?: string;
  url?: string;
  parameter?: string;
  method?: string;
  template_id?: string;
  is_validated: boolean;
  analyst_notes?: string;
  false_positive: boolean;
  created_at: string;
}

export interface AttackPathNode {
  id: string;
  order: number;
  label: string;
  description?: string;
  validation_command?: string;
}

export interface AttackPath {
  id: string;
  scan_id: string;
  title: string;
  description: string;
  confidence: number;
  impact?: string;
  steps: string[];
  nodes: AttackPathNode[];
  created_at: string;
}

export interface Asset {
  id: string;
  scan_id: string;
  asset_type: "subdomain" | "url" | "endpoint" | "ip";
  value: string;
  ip_address?: string;
  is_alive?: boolean;
  status_code?: number;
  technologies: string[];
  created_at: string;
}

export interface DashboardStats {
  total_targets: number;
  total_scans: number;
  active_scans: number;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  findings_by_category: Record<string, number>;
  recent_scans: Scan[];
}

// ─── API calls ────────────────────────────────────────────────────────────────

export const apiClient = {
  // Dashboard
  getDashboard: () => api.get<DashboardStats>("/dashboard").then(r => r.data),

  // Targets
  getTargets: () => api.get<Target[]>("/targets").then(r => r.data),
  createTarget: (domain: string, description?: string) =>
    api.post<Target>("/targets", { domain, description }).then(r => r.data),
  deleteTarget: (id: string) => api.delete(`/targets/${id}`),

  // Scans
  getScans: (params?: Record<string, any>) =>
    api.get<Scan[]>("/scans", { params }).then(r => r.data),
  getScan: (id: string) => api.get<Scan>(`/scans/${id}`).then(r => r.data),
  createScan: (domain: string, options?: object) =>
    api.post<Scan>("/scans", { domain, options: options ?? {} }).then(r => r.data),
  cancelScan: (id: string) => api.delete(`/scans/${id}`),
  getScanLogs: (id: string) =>
    api.get<any[]>(`/scans/${id}/logs`).then(r => r.data),

  // Findings
  getFindings: (params?: Record<string, any>) =>
    api.get<Finding[]>("/findings", { params }).then(r => r.data),
  getFinding: (id: string) => api.get<Finding>(`/findings/${id}`).then(r => r.data),
  updateFinding: (id: string, data: Partial<Finding>) =>
    api.patch<Finding>(`/findings/${id}`, data).then(r => r.data),
  getValidationCommands: (id: string) =>
    api.get(`/findings/${id}/validate`).then(r => r.data),

  // Attack Paths
  getPaths: (params?: Record<string, any>) =>
    api.get<AttackPath[]>("/paths", { params }).then(r => r.data),

  // Assets
  getAssets: (params?: Record<string, any>) =>
    api.get<Asset[]>("/assets", { params }).then(r => r.data),

  // Reports
  getReport: (scanId: string, fmt: "json" | "markdown" | "html" = "json") =>
    api.get(`/reports/${scanId}?fmt=${fmt}`).then(r => r.data),
};
