# `mantis model`

> **Authorized testing only.** See [Responsible Use](../responsible-use.md).

Pick the Claude model used by `mantis hack`. Persists to `~/.Mantis/model`; subsequent `mantis hack` runs auto-apply it.

## Interactive picker

```sh
mantis model
```

| Key | Action |
|---|---|
| **Tab** | Move selection down |
| **Shift+Tab** | Move selection up |
| **↑ / ↓ / j / k** | Move selection |
| **1–9** | Jump to that row |
| **Enter** | Confirm — save preference |
| **Esc / q / Ctrl+C** | Cancel — preference unchanged |

When stdout/stdin isn't a TTY (e.g. piped, SSH-less), the picker falls back to a numbered prompt.

## Non-interactive forms

```sh
mantis model show                          # print current preference
mantis model set claude-opus-4-7           # set to Opus 4.7
mantis model set claude-sonnet-4-6         # set to Sonnet 4.6
mantis model set claude-haiku-4-5-20251001 # set to Haiku 4.5
mantis model set auto                      # clear (revert to claude default)
mantis model clear                         # also clears
```

`mantis model set <id>` accepts any model id that `claude --model` accepts — not just the ones in the built-in picker list. Setting an unknown id prints a note but is otherwise honored.

## How it integrates with `mantis hack`

Before spawning `claude --print`, `mantis hack`:

1. Inspects the `-- <claude args>...` you forwarded.
2. If they already contain `--model`, `--model=…`, or `-m`, your override wins. The saved preference is **not** applied.
3. Otherwise, if `~/.Mantis/model` is set, prepends `--model <saved-id>` to the claude invocation. You'll see:

   ```
   [mantishack] model: claude-opus-4-7  (from `mantis model`; override via `-- --model …`)
   ```

4. If no preference is saved, claude's own default model applies.

## Built-in list

| Label | id | Family | When to use |
|---|---|---|---|
| Auto | _(unset)_ | default | Let claude pick its own default. |
| Opus 4.7 | `claude-opus-4-7` | Opus | Strongest reasoning — architecture, deep multi-step engagements. |
| Sonnet 4.6 | `claude-sonnet-4-6` | Sonnet | Balanced default for most hunts. |
| Haiku 4.5 | `claude-haiku-4-5-20251001` | Haiku | Fast + cheap — quick scans, dry runs. |

The file is a plain UTF-8 single line — you can edit it directly if you prefer:

```sh
echo claude-opus-4-7 > ~/.Mantis/model
```

## See also

- [`mantis hack`](./hack.md)
- [Quickstart](../quickstart.md)
