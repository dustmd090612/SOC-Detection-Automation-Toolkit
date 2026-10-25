# PHP2Shell Threat Intelligence & Snort Detection Rules

Experimental Snort detection signatures and threat intelligence indicators related to **CVE-2026-109618** and **CVE-2026-109619**, collectively referred to as PHP2Shell.

This repository combines previously collected indicators with additional findings from the CYFIRMA threat advisory published on 23 October 2026.

## Overview

PHP2Shell refers to critical vulnerabilities in the PHP runtime that may enable unauthenticated remote code execution under vulnerable configurations.

CYFIRMA reported a suspected DPRK-linked campaign, tracked as **June 2026 Minjun**, preparing to target exposed PHP infrastructure worldwide.

The advisory identifies government, banking, manufacturing, logistics, shipping, **airports and aviation**, and online transaction platforms among the priority sectors.

**Attribution caveat:** CYFIRMA assesses campaign preparation with high confidence, but the link to the Lazarus ecosystem with moderate confidence. Attribution is not confirmed.

## Repository Contents

| File | Description | Count |
|---|---|---:|
| `snort/php2shell.rules` | Experimental Snort 2.x signatures | 13 |
| `ioc/previous_iocs.txt` | Previously collected PHP2Shell indicators | 11 |
| `ioc/cyfirma_campaign_staging.txt` | Suspected campaign infrastructure, including one possible typo | 16 |
| `ioc/cyfirma_suspected_sources.txt` | Suspected exploitation source IPs observed on 23 October 2026 | 17 |
| `ioc/cyfirma_payload_staging.txt` | Separately reported payload staging host | 1 |

**Total: 45 unique IP addresses across the supplied lists.**

## Detection Coverage

The Snort rules cover:

- Suspicious multipart/form-data requests
- Oversized multipart headers and filenames
- Repeated multipart controls and deeply nested field names
- `PHP_SESSION_UPLOAD_PROGRESS` with suspicious PHP syntax
- Suspicious PHP payloads embedded in multipart filenames
- `PHPSESSID` submitted as a multipart form field
- `php2shell`, `php2shell-scan`, and `JACKALPOC` tool indicators

### Rule Provenance

- SIDs `1000101–1000110`: experimental reconstructions based on previously supplied rule descriptions. **Not verified copies of production IPS signatures.**
- SID `1000111`: adapted from the previously supplied reference PDF, with a locally assigned SID.
- SIDs `1000112–1000113`: newly authored candidates using indicators described in the CYFIRMA advisory.

No rule is represented as an official CYFIRMA, PHP Security Team, or Snort vendor signature.

## Threat Hunting

Review web and endpoint telemetry from **17 October 2026 onward** for:

- Unusual multipart POST requests, including requests to non-upload endpoints
- `PHP_SESSION_UPLOAD_PROGRESS` in unexpected requests
- PHP worker crashes, OOM errors, SIGSEGV, or HTTP 500 responses following multipart POSTs
- PHP/web-server processes spawning shells, download utilities, or interpreters
- Newly created or modified PHP web shells
- Changes to `.user.ini`, `.htaccess`, cron jobs, or SSH authorized keys
- Unexpected outbound connections from PHP worker processes

A network signature match does not establish successful exploitation. Correlate network events with process, file, authentication, and application telemetry.

## IOC Handling

The IOC lists have different evidentiary strengths.

**Previously collected indicators:** Preserve original source attribution and revalidate current reputation.

**Campaign staging infrastructure:** CYFIRMA recommends monitoring and hunting. Some infrastructure may be shared or anonymizing services. One address is a possible transcription error.

**Suspected exploitation source IPs:** CYFIRMA recommends blocking or close monitoring after operational review. These addresses are not independently attributed to the suspected DPRK-linked campaign.

**Payload staging IP:** Listed separately because it is not established as one of the 16 campaign infrastructure addresses.

Do not treat every listed IP as a confirmed malicious host or permanently block it without validation.

## Remediation

Prioritize inventory and patching of internet-facing PHP services.

Fixed upstream release thresholds cited in the advisory:

- PHP 8.5.12 or later
- PHP 8.4.27 or later
- PHP 8.3.36 or later
- PHP 8.2.35 or later

For vendor-maintained distributions, verify applicable backported fixes. Restart PHP workers after updating and confirm the running runtime version.

Detection signatures and IP blocking are compensating controls, not substitutes for patching.

## Limitations

- Rules use Snort 2.x-style syntax and have not been independently compiled or regression-tested.
- Some signatures are broad heuristics and may generate false positives.
- Multipart parsing and HTTP body inspection limits affect detection.
- HTTPS inspection requires traffic visibility after decryption.
- Tool-specific user agents and markers are easily changed.
- The IOC lists represent historical observations, not real-time reputation data.

## References

- CYFIRMA, *Suspected DPRK Campaign staging PHP2Shell Targeting against Global PHP infrastructure*, 23 October 2026:
  https://www.cyfirma.com/research/cyfirma-threat-advisory-suspected-dprk-campaign-staging-php2shell-targeting-against-global-php-infrastructure/

- Lazarus.day report:
  https://lazarus.day/reports/suspected-dprk-campaign-staging-php2shell-targeting-against-global-php-infrastructure-VbQyF/

- PHP Security Team advisories:
  https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w

  https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp

## Disclaimer

This repository is for defensive security research and detection engineering. Indicators, signatures, and attribution assessments must be independently validated before operational enforcement.
