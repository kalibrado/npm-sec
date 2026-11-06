export type Threat = {
  id: number;
  ip: string;
  score: number;
  threat_type?: string;
  created_at?: string;
  host?: string;
  uri?: string;
  country_code?: string;
  reasons?: string[];
};
export type ThreatSummary = {
  by_type: { threat_type: string; count: number; max_score: number; avg_score: number }[];
  top_ips: { ip: string; count: number; max_score: number; last_seen: string }[];
};
