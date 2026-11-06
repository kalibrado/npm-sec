export type Stats = {
  total: number;
  blocked: number;
  allowed: number;
  block_rate: number;
  top_countries: { country_code: string; count: number }[];
  top_attackers: { ip: string; count: number }[];
  top_uris: { uri: string; count: number }[];
};

export async function getJson<T>(path: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(path, { credentials: "same-origin", signal });
  if (!response.ok) throw new Error(response.status === 401 ? "Session expirée ou connexion requise" : `Erreur HTTP ${response.status}`);
  return response.json() as Promise<T>;
}
