export type AccessLog = {
  id: number;
  timestamp?: string;
  ip?: string;
  host?: string;
  method?: string;
  uri?: string;
  status?: number;
  country_code?: string;
  blocked?: number | boolean;
};
export type HistoryResponse = {
  logs: AccessLog[];
  total: number;
  next_cursor: number | null;
};
