# cap-dmarc-takeover

**Capability:** Confirm a DMARC `rua=` (or `ruf=`) address points to
a domain the legitimate operator no longer owns — which an attacker
can register to intercept aggregate authentication reports across
every legitimate sender of the in-scope domain.

A vanilla "DMARC rua mismatch" finding is `low` on its own. This
pack turns it into `critical` if the target apex is actually
registrable/expired.

## Inputs

- `engagement_id`, `wave_number`, `assignment_id`.
- The apex domain under test (e.g., `tenkara.ai`).
- Optional: previously-discovered `rua`/`ruf` domains (from
  hunter-3's DMARC probe).

## Procedure

1. **Re-pull DMARC** (don't trust prior runs):

   ```sh
   dig +short TXT _dmarc.<apex>
   ```

   Extract every `mailto:` target and parse the apex (RFC 5321):
   the part after `@`.

2. **For each unique mail-target apex** that is NOT the in-scope apex:

   a. **Whois lookup** (use a registry-aware whois client; many shells default to thin whois which only resolves the registry, not the registrar):

   ```sh
   whois <target-apex> 2>/dev/null | head -60 > /tmp/whois-<apex>.txt
   ```

   Look for:
   - `No match for "<apex>"`, `Domain not found`, `NOT FOUND`, `Status: free` → **`critical`** "DMARC rua target apex is unregistered; attacker can register and intercept DMARC reports".
   - `Registry Expiry Date: <date in the past>`, `Expiration Date: <past>`, `Status: redemptionPeriod` → **`critical`** "DMARC rua target apex is in redemption / expired".
   - `Status: pendingDelete` → **`critical`** "DMARC rua target apex is pending delete; will become registrable shortly".
   - `Status: clientHold` → **`high`** "DMARC rua target apex is on clientHold; mail likely not flowing".

   b. **DNS sanity check.** Does the rua target apex resolve at all?

   ```sh
   dig +short ANY <target-apex>
   ```

   If empty AND whois shows it's expired → **`critical`**.

   If non-empty AND apex is third-party-owned (e.g., a Google Workspace verification page) → **`medium`** "DMARC rua target is third-party-owned; verify intentional".

   c. **MX check.** Does the rua target accept mail at all?

   ```sh
   dig +short MX <target-apex>
   ```

   No MX records → **`high`** "DMARC rua target apex has no MX; aggregate reports cannot be delivered (broken DMARC)".

3. **Special case: tenkara.ai → trytenkara.com.** During the live
   tenkara engagement we found the rua at `trytenkara.com`. Run the
   above procedure on that apex specifically.

4. **Chain test.** If the rua target apex is registrable, call
   `mantis_record_chain_attempt`:

   ```
   hypothesis: "DMARC rua misconfiguration -> aggregate report interception -> spoofing intelligence"
   outcome: "confirmed"
   steps: [
     "DMARC TXT at _dmarc.<apex> has rua=mailto:postmaster@<target>.",
     "whois <target> reports <evidence of unregistered/expired>.",
     "Attacker registers <target>, sets up an MX, receives all DMARC aggregate reports including SPF/DKIM alignment data, attacker identities sending mail, etc."
   ]
   ```

## Severity guide

- rua target apex is registrable (no whois match, expired, pendingDelete): **`critical`**.
- rua target apex resolves but has no MX (reports cannot be delivered): **`high`**.
- rua target apex is owned by a different operator-controlled entity (sister domain, third-party mail vendor): **`low`** with note recommending verification.

## Coverage to record

`dmarc-record-fetch`, `dmarc-rua-target-whois`, `dmarc-rua-target-mx`,
`dmarc-rua-target-registrability-check`.
