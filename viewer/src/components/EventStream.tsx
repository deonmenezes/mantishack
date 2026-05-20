import { useEffect, useRef } from "react";

export default function EventStream({ lines }: { lines: string[] }) {
  const ref = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom when new lines arrive, unless the user
  // has scrolled up — then leave the viewport alone.
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 100;
    if (nearBottom) el.scrollTop = el.scrollHeight;
  }, [lines]);

  return (
    <div
      ref={ref}
      className="flex-1 overflow-y-auto px-4 pb-4 font-mono text-xs leading-relaxed text-zinc-300"
    >
      {lines.length === 0 ? (
        <div className="text-zinc-600">Waiting for daemon activity…</div>
      ) : (
        lines.map((line, i) => (
          <div key={i} className="whitespace-pre-wrap break-all">
            <span className="text-zinc-600 mr-2 select-none">
              {String(i + 1).padStart(4, "0")}
            </span>
            {line}
          </div>
        ))
      )}
    </div>
  );
}
