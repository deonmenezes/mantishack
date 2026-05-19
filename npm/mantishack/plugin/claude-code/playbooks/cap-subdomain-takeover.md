# cap-subdomain-takeover

**Capability:** Confirm a subdomain points (via CNAME or A) to a
third-party service where the namespace is **claimable** — i.e., the
legitimate operator no longer owns the resource, and an attacker can
register the same name on that service to host arbitrary content
under the in-scope domain.

A vanilla "subdomain CNAMEs to <third-party>" finding is `info` on
its own. This pack turns it into `high`/`critical` when the
third-party returns the takeover fingerprint.

## Inputs

- The list of alive subdomains and their CNAME chains (from
  hunter 1's output).
- The apex domain under test.

## Procedure

For each `(subdomain, cname-target)` pair the subdomain-enum hunter
discovered:

1. **Match the CNAME against the takeover fingerprint table:**

   | CNAME suffix / pattern              | Service          | Takeover fingerprint in body / status |
   |-------------------------------------|------------------|---------------------------------------|
   | `.herokuapp.com`                    | Heroku           | `No such app` (404)                   |
   | `.github.io`                        | GitHub Pages     | `There isn't a GitHub Pages site here.` |
   | `.netlify.app`                      | Netlify          | `Not Found - Request ID:` (404)       |
   | `.vercel.app`                       | Vercel           | `DEPLOYMENT_NOT_FOUND` or 404         |
   | `.cloudfront.net`                   | CloudFront       | `Bad request` / `The request could not be satisfied` |
   | `.s3.amazonaws.com`                 | S3 bucket        | `NoSuchBucket` (404)                  |
   | `.azurewebsites.net`                | Azure App Svc    | `Error 404 - Web app not found.`      |
   | `.cloudapp.net`                     | Azure Classic    | Open registration                     |
   | `.fastly.net`                       | Fastly           | `Fastly error: unknown domain`        |
   | `.surge.sh`                         | Surge.sh         | `project not found`                   |
   | `.bitbucket.io`                     | Bitbucket Pages  | `Repository not found`                |
   | `.readme.io`                        | ReadMe.io        | `Project doesnt exist... yet!`        |
   | `.statuspage.io`                    | Statuspage       | `You are being redirected`            |
   | `.tumblr.com`                       | Tumblr           | `Whatever you were looking for...`    |
   | `.ghost.io`                         | Ghost            | `Domain error`                        |
   | `.framer.app`                       | Framer Sites     | `404` with no site-id matched         |
   | `.webflow.io`                       | Webflow          | `The page you are looking for...`     |
   | `.zendesk.com`                      | Zendesk          | `Help Center Closed`                  |

2. **Fetch the subdomain and look for the fingerprint:**

   ```sh
   curl -sS --max-time 10 -L "https://<sub>" -o /tmp/sub-<n>.html -w "%{http_code}\n"
   grep -F "<takeover-fingerprint>" /tmp/sub-<n>.html
   ```

   - Fingerprint match → **`critical`** "subdomain takeover via <service>".
   - 404 with no fingerprint match but service is on the table → **`high`** "subdomain dangling at <service>; manual verification required".
   - 200 with content → **`info`** ("subdomain alive on <service>; no takeover signal").

3. **For S3 specifically, also try:**

   ```sh
   curl -sS --max-time 10 "https://<sub>.s3.amazonaws.com/" | head -5
   ```

   `<Code>NoSuchBucket</Code>` → **`critical`** + try to claim:
   `aws s3api create-bucket --bucket <sub> --region us-east-1` (do NOT actually claim; just record the takeover surface).

4. **For Framer specifically (relevant to tenkara):**
   - Framer site IDs leak through `framerusercontent.com/sites/<site-id>/`.
   - If a subdomain CNAMEs to `sites.framer.app` AND the served page is the generic 404, the Framer site ID can be re-registered.
   - Probe `https://framer.com/projects/<framer-site-id>` and `https://framer.com/api/projects/<framer-site-id>` to check accessibility.

5. **Chain test.** If a takeover is confirmed:

   ```
   hypothesis: "subdomain takeover -> trusted-origin abuse -> auth-cookie theft / cookie-bombing / OAuth callback hijack"
   outcome: "confirmed"
   steps: [
     "<sub>.<apex> CNAMEs to <third-party>.",
     "<third-party> returns <fingerprint>; the namespace is claimable.",
     "Attacker claims <claimable-name>, serves attacker-controlled JS under <sub>.<apex>.",
     "Any auth cookie scoped to .<apex> is sent to attacker subdomain; any OAuth callback registered for <sub>.<apex> is hijacked."
   ]
   ```

## Severity guide

- Confirmed takeover with fingerprint match: **`critical`**.
- Dangling CNAME on a service that's on the takeover list but no fingerprint match: **`high`**.
- CNAME to legitimate third-party that responds normally: **`info`**.

## Coverage to record

`cname-vs-takeover-table`, `service-fingerprint-grep`,
`s3-no-such-bucket`, `framer-site-id-claim-check`,
`subdomain-takeover-chain-narrative`.
