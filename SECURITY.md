# Security Policy

## Supported Versions

Only the latest release, or the default branch if there are no releases, receives security fixes.

## Reporting a Vulnerability

Please do not report security vulnerabilities through public issues, pull requests, or discussions.

Report them privately through GitHub's private vulnerability reporting:

1. Go to the repository's Security tab.
2. Click Report a vulnerability.

If that option is unavailable, please contact me using the email address on my GitHub profile.

Please include:

- A description of the issue and its potential impact
- Steps to reproduce, or a proof of concept
- Affected version, commit, or configuration

## What to Expect

This is a personal project maintained on a best-effort basis. I aim to acknowledge reports within 7 days and will keep you updated on progress. Once a fix is released, you will be credited in the advisory unless you prefer to remain anonymous.

## System and Scope

This repository contains a log analysis pipeline for a small set of Linux servers.
`logfilter.py` reads local and received journals through `journalctl` and writes condensed reports.
`analyze.py` sends those reports to an administrator-selected Ollama endpoint and writes analyses.
The supplied systemd services run as root. Neither script provides a listening network service.

Security review covers both scripts, the systemd units, and repository CI and dependency configuration.
Assets include sensitive log content, state and report integrity, pipeline availability, and the host's privileges.

## Threat Model and Trust Boundaries

Only trusted administrators control CLI arguments, configuration, known-issues files, state and report directories, and the Ollama endpoint.
These directories and their parent paths must not be writable by untrusted users.
Journal messages and application-provided fields may contain attacker-controlled text, even when stored in trusted files.
Systemd-generated metadata must be assessed according to what a log writer can actually influence.

Reports retain untrusted journal content. Model responses also require validation and must never become executable instructions.
The pipeline writes analysis text; it does not execute model suggestions or provide the model with tools.

## Security Invariants

- Journal content must not control commands, output paths, or network destinations.
- Journal-derived report fields must remain within their report lines, with control characters escaped and displayed text bounded.
- Reports, state, and analyses must be written atomically. State must advance only after the report is produced.
- Preview mode must not read the saved cursor or write state or reports.
- `logfilter.py` must not make network or LLM requests.
- Report and merge inputs must remain data, separated from model instructions with fresh markers absent from the input.
- Model replies must pass schema and completion checks before being accepted.
- An unreachable Ollama server must not cause reports to be marked analyzed or given up on.
- Sensitive logs and generated reports must not be exposed through repository content, test fixtures, or unintended output destinations.

## Reportable Findings and Severity Context

Reports should identify an input an attacker can control, a reachable path, and a concrete confidentiality, integrity, or availability impact.
Examples include privileged command execution, unintended file access, disclosure of log content, structural report forgery, and disproportionate resource exhaustion from attacker-controlled entries.
Account for root execution, actual deployment controls, and the privileges required to supply the input.
Do not assume every journal field is attacker-controlled or that every execution uses the supplied systemd sandbox.

## Out of Scope and Accepted Risk

Security monitoring, such as intrusion detection and login auditing, is outside the product's purpose.
This does not exclude vulnerabilities in the pipeline itself.

Path traversal, SSRF, or command argument injection claims based solely on trusted administrators choosing CLI arguments are not reportable.
This exclusion does not apply if journal content or another untrusted input can influence those values.

## Known Limitations and Compensating Controls

The supplied services configure a private state directory and filesystem restrictions; the analysis service also restricts network access to localhost.
These are deployment controls, not guarantees for manual execution or modified units.
Prompt instructions and random data markers reduce prompt-injection risk but do not guarantee faithful analysis. Schema validation does not establish factual accuracy or safe display of model text.
Displayed-field limits and request chunking do not bound total journal volume, pattern count, report size, or response size.
