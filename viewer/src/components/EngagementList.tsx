import type { EngagementView } from "../api";

export default function EngagementList({ engagements }: { engagements: EngagementView[] }) {
  if (engagements.length === 0) {
    return (
      <p className="text-zinc-500 text-sm">
        No engagements yet. Start one with{" "}
        <code className="font-mono text-accent">mantis hack &lt;target&gt;</code>.
      </p>
    );
  }
  return (
    <ul className="space-y-2">
      {engagements.map((e) => (
        <li
          key={e.id}
          className="rounded border border-ink-600 bg-ink-800 px-3 py-2 hover:border-accent/40 transition-colors"
        >
          <div className="flex justify-between items-baseline gap-3">
            <span className="font-medium truncate">{e.name}</span>
            <span className="font-mono text-[10px] text-zinc-500 shrink-0">
              {e.events} evts
            </span>
          </div>
          <div className="mt-1 flex items-center gap-2 text-xs">
            <StateBadge state={e.state} />
            <span className="font-mono text-zinc-600 truncate">{e.id}</span>
          </div>
        </li>
      ))}
    </ul>
  );
}

function StateBadge({ state }: { state: string }) {
  const cls =
    state === "active"
      ? "bg-accent/15 text-accent"
      : state === "completed"
      ? "bg-zinc-700 text-zinc-300"
      : state === "paused"
      ? "bg-yellow-500/15 text-yellow-300"
      : "bg-ink-700 text-zinc-400";
  return (
    <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${cls}`}>{state}</span>
  );
}
