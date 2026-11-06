export type ControlOverview = {
  window_hours: number;
  rules: { active_total: number; trusted_total: number; by_type: Record<string, number> };
  traffic: { requests: number; proxy_blocked: number; unique_ips: number };
  detections: { signals: number; suspicious_ips: number; brute_force: number; http_scans: number };
  auto_ban_mode: string;
  recent_actions: { target: string; type: string; action: string; reason: string; created_at: string }[];
};
export type Suspect = {
  ip: string;
  max_score: number;
  signals: number;
  country_code?: string;
  trusted: boolean;
  internal: boolean;
  block_rule: { type: string; value: string } | null;
};
