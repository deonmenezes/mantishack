# `mantis find-auth-bugs`

> **Authorized testing only.** See [Responsible Use](../responsible-use.md).

Legacy unauth-only / multi-profile auth-differential pipeline. No FSM, no LLM, no waves — just a fast linear pipeline that:

1. Signs up an attacker + victim (Supabase JSON path, when detected)
2. Enumerates endpoint candidates from the seed URL
3. Runs the auth-differential against every endpoint with all profiles
4. Aggregates findings into a per-target archive under `./reports/<host>/`

```sh
mantis find-auth-bugs \
    --target https://app.example.com/ \
    --supabase-signup https://....supabase.co/auth/v1/signup \
    --supabase-apikey "$ANON_KEY" \
    --extra-path "/rest/v1/users" \
    --i-have-authorization
```

Without `--supabase-signup`, runs unauth-only — useful as a fast public-table scan.

For the full LLM-orchestrated 7-phase pipeline, use [`mantis hack`](./hack.md) instead.
