import type { FieldSchema, SettingValue } from "./types";

export function SettingField({ name, schema, value, onChange }: {
  name: string;
  schema: FieldSchema;
  value: SettingValue;
  onChange: (value: SettingValue) => void;
}) {
  const id = `setting-${name}`;
  const help = `${id}-help`;
  let control;
  if (schema.type === "boolean") {
    control = <input id={id} type="checkbox" checked={value === true} onChange={e => onChange(e.target.checked)} aria-describedby={help}/>;
  } else if (schema.type === "choice") {
    control = <select id={id} value={String(value)} onChange={e => onChange(e.target.value)} aria-describedby={help}>
      {(schema.choices ?? []).map(option => <option key={option} value={option}>{option}</option>)}
    </select>;
  } else if (schema.type === "integer") {
    control = <input id={id} type="number" min={schema.min} max={schema.max} required
      value={Number(value)} onChange={e => onChange(Number(e.target.value))} aria-describedby={help}/>;
  } else {
    control = <textarea id={id} rows={2} aria-describedby={help}
      value={Array.isArray(value) ? value.join(", ") : String(value ?? "")}
      onChange={e => onChange(e.target.value.split(",").map(item => item.trim()).filter(Boolean))}/>;
  }
  return <div className="setting-field"><label htmlFor={id}>{schema.label}</label>{control}
    {schema.description && <small id={help}>{schema.description}</small>}</div>;
}
