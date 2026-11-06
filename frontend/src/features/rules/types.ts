export type Rule = { id: number; type: string; value: string; host?: string; reason?: string; created_at?: string; expires_at?: string | null };
export type Trusted = { id: number; type: string; value: string; reason?: string };
export type RuleType = "ip" | "cidr" | "country";
