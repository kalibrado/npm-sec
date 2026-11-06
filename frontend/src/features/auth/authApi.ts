export type User = { id: number; username: string; role: "admin" | "viewer" };
export type AuthResponse = { authenticated: boolean; user: User };

export async function login(username: string, password: string): Promise<User> {
  const response = await fetch("/auth/login", { method: "POST", credentials: "same-origin",
    headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username, password }) });
  if (!response.ok) throw new Error(response.status === 401 ? "Identifiants invalides." : `Connexion impossible (HTTP ${response.status}).`);
  const data: { user: User } = await response.json();
  return data.user;
}
export async function logout(): Promise<void> {
  const response = await fetch("/auth/logout", { method: "POST", credentials: "same-origin" });
  if (!response.ok) throw new Error(`Déconnexion impossible (HTTP ${response.status}).`);
}
