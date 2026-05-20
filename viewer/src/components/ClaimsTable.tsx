import type { ClaimView } from "../api";

export default function ClaimsTable({ claims }: { claims: ClaimView[] }) {
  if (claims.length === 0) {
    return <p className="text-zinc-500 text-sm">No findings yet.</p>;
  }
  return (
    <ul className="space-y-1.5">
      {claims.map((c, i) => (
        <li
          key={i}
          className="flex items-center gap-3 px-2 py-1.5 rounded border border-ink-700 bg-ink-800 text-sm"
        >
          <SeverityChip severity={c.severity} />
          <span className="font-mono text-xs text-accent shrink-0">{c.vuln_class}</span>
          <span className="font-mono text-xs text-zinc-400 truncate flex-1">{c.url}</span>
          <span className="text-[10px] text-zinc-500 shrink-0">{c.status}</span>
        </li>
      ))}
    </ul>
  );
}

function SeverityChip({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: "bg-red-500/20 text-red-300",
    high: "bg-orange-500/20 text-orange-300",
    medium: "bg-yellow-500/20 text-yellow-300",
    low: "bg-blue-500/20 text-blue-300",
    info: "bg-zinc-700 text-zinc-400",
  };
  const cls = map[severity.toLowerCase()] ?? "bg-zinc-700 text-zinc-400";
  return (
    <span className={`w-14 text-center px-1.5 py-0.5 rounded text-[10px] uppercase font-mono ${cls}`}>
      {severity}
    </span>
  );
}
