# Security Policy

## Supported versions

ReviewBlind has not had a release yet. Once it does, security fixes will go to the latest
release.

## Reporting a vulnerability

Please report privately through GitHub: open the **Security** tab of this repository and choose
**Report a vulnerability**. Do not open a public issue.

Please **do not include real identities**, real reports, or files from a project under review.
Build the reproduction with the fictional persona in [CONTRIBUTING.md](CONTRIBUTING.md).

## What counts as a vulnerability

ReviewBlind inspects files that may be hostile, so these are security bugs:

- A scanned repository causing code to execute, including through Git configuration
- A file outside the scan root being read or written
- Any network connection during a scan
- A scanned file or Git data being modified
- A crafted file crashing or hanging the tool without a skipped entry being recorded
- Terminal or Markdown output being manipulated by repository content
- A passing verdict after an inspection silently failed

See [the threat model](docs/THREAT_MODEL.md).

## What does not count

- **A missed leak or a false positive.** These matter, but they are ordinary bugs. Please use the
  issue template.
- Risks listed as accepted in [the limitations](docs/LIMITATIONS.md).
- Vulnerabilities in a dependency with no path through ReviewBlind. Please report those upstream.
