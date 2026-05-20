# mantis-viewer

Modern web viewer for live `mantis-daemon` engagement state. Vite + React
+ TypeScript + Tailwind. Talks to the daemon-served web UI backend
(crate `mantis-web-ui`) on `127.0.0.1:50452`.

## Architecture

```
┌──────────────────┐       gRPC :50451       ┌─────────────────┐
│  mantis CLI      │ ──────────────────────▶ │ mantis-daemon   │
│  (or MCP / TUI)  │                         │                 │
└──────────────────┘                         │  · RocksDB      │
                                             │  · scope        │
┌──────────────────┐    HTTP/SSE :50452      │  · egress proxy │
│  mantis-viewer   │ ◀────────────────────── │  · mantis-web-ui│
│  (this app)      │                         └─────────────────┘
└──────────────────┘
```

Daemon-side endpoints exposed by `mantis-web-ui`:

| Path           | Returns                                            |
|----------------|----------------------------------------------------|
| `GET /`        | Embedded fallback HTML shell                       |
| `GET /api/state` | Current `WebState` JSON snapshot                 |
| `GET /api/events` | Server-Sent Events stream of `Event` records    |

## Run

In one terminal, start the daemon:

```sh
mantis daemon
# logs:
#   mantis web UI listening   bind=127.0.0.1:50452
#   mantis daemon listening   bind=127.0.0.1:50451
```

In another, run the Vite dev server:

```sh
cd viewer
npm install   # first time only
npm run dev
# Local: http://localhost:5173
```

The Vite dev server proxies `/api/*` to `127.0.0.1:50452`, so you can
develop without CORS dancing. The page connects to `/api/state` for the
initial snapshot, then subscribes to `/api/events` for live updates.

## Build (production)

```sh
npm run build
# → viewer/dist/
```

A future iteration will let the daemon serve `viewer/dist/` directly at
`http://127.0.0.1:50452/` (replacing the current embedded HTML). For
now, run the Vite dev server alongside the daemon.

## Status (Phase 1)

What works:
- Daemon connection indicator (live / connecting / down)
- Engagement list with state badges
- Findings table with severity chips
- Live event stream (auto-scroll)

Not yet:
- Per-engagement deep view (phase indicator, hunter waves)
- Surface graph (react-flow)
- HTTP request explorer
- Markdown report viewer
- Codegen of TS types from Rust (currently hand-maintained in `src/api.ts`)
