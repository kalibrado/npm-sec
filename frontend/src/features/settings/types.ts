export type FieldSchema = {
  type: "boolean" | "integer" | "choice" | "countries" | "cidrs" | "tokens";
  label: string;
  description?: string;
  min?: number;
  max?: number;
  choices?: string[];
};
export type SettingValue = boolean | number | string | string[];
export type Profile = {
  revision: number;
  settings: Record<string, SettingValue>;
  schema: Record<string, FieldSchema>;
  deployment: { state: string; message: string };
};
export type Preview = {
  changed_files: string[];
  diff: Record<string, string>;
  warning: string;
  validation: string;
};
