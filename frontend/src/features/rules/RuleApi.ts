import { getJson } from "../../services/api";
import type { Rule, Trusted } from "./types";

async function mutate(url: string, method: "POST" | "DELETE", payload?: unknown) {
  const response = await fetch(url, { method, credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: payload === undefined ? undefined : JSON.stringify(payload) });
  if (!response.ok) {
    const data: unknown = await response.json().catch(() => null);
    const detail = data && typeof data === "object" && "detail" in data ? JSON.stringify(data.detail) : response.statusText;
    throw new Error(`HTTP ${response.status}: ${detail}`);
  }
}
export const ruleApi = {
  load: async (signal: AbortSignal) => Promise.all([
    getJson<Rule[]>("/blocklist", signal), getJson<Trusted[]>("/trusted", signal),
  ]),
  addBlock: (type: string, value: string, reason: string) => mutate("/blocklist", "POST", { type, value, reason }),
  removeBlock: (id: number) => mutate(`/blocklist/${id}`, "DELETE"),
  addTrust: (type: string, value: string, reason: string) => mutate("/trusted", "POST", { type, value, reason }),
  removeTrust: (id: number) => mutate(`/trusted/${id}`, "DELETE"),
};
