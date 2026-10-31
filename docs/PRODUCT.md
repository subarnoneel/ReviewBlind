# ReviewBlind — Product Definition

> A deterministic, local-first CLI that preflights research repositories for
> accidental identity disclosure before double-anonymous peer review.

## The problem

Double-anonymous review asks authors to share code, notebooks, figures and
supplementary material without revealing who they are. Identity leaks into those
artifacts in places authors rarely look:

- a `pyproject.toml` author field or a `CITATION.cff` file
- a home path inside a notebook traceback, such as `/home/<username>/miniconda3/...`
- the `Author` metadata of a figure exported to PDF
- a `wandb.ai/<username>/` link in a config file
- Git history, when the repository or a `.git` directory is shared

Anonymization proxies such as [Anonymous GitHub](https://github.com/tdurieux/anonymous_github)
and [Hido](https://hido.fim.ai/) replace terms you list, so you must already know which terms to supply. Anonymous GitHub
also passes binary files through unchanged. ReviewBlind finds the terms and flags the places
a proxy may not reach.

## Primary user

A researcher preparing code, notebooks, figures or supplementary material for
anonymous review.

## Primary job

```text
Discover likely author identities
        ↓
Detect where those identities or associated metadata leak
        ↓
Explain exactly why each finding matters
        ↓
Help the author prepare the artifact for anonymous sharing
```

## Product principles

| Principle | What it means in practice |
|---|---|
| **Evidence, not scores** | Every finding names a rule, an exact location and the exact evidence. Severity and confidence stay separate. |
| **Honest about gaps** | "I found nothing" and "I could not inspect everything" are different results. The tool never says an artifact is anonymous. |
| **The author decides** | Identities are confirmed by a person. Derived guesses are never activated silently. |
| **Read-only** | ReviewBlind reports. It does not edit files, remove findings or rewrite history. |
| **Local and inert** | No network, no LLM, no execution of inspected code. |
| **Deterministic** | The same input, config and version produce the same report. |

## Non-goals

ReviewBlind does **not**:

- guarantee conference-policy compliance
- anonymize the public internet
- perform authorship or stylometric inference
- use facial recognition
- rewrite source code or Git history
- remove findings automatically
- upload research files
- use an LLM
- execute repository code
- replace Anonymous GitHub, Hido or similar anonymization proxies

## Commands

| Command | Purpose |
|---|---|
| `reviewblind init` | Normal starting point. Discover identities, let the user confirm them, write `.reviewblind.toml`. |
| `reviewblind discover` | Non-destructive identity discovery only. |
| `reviewblind scan` | Main command. Inspect the artifact and report findings. |
| `reviewblind export` | Turn a JSON scan report into a term list for an anonymization proxy. |
| `reviewblind rules` | Rule documentation from the CLI. |

Full interface: [CLI.md](CLI.md).

## Targets

The same finding matters differently depending on how the artifact will be shared.
`--target` selects that context.

| Target | Sharing scenario | Default |
|---|---|---|
| `mirror` | Served through an anonymizing proxy, assumed to hide the owner and Git history | Yes |
| `archive` | A supplementary ZIP or TAR | |
| `repository` | A public repository published under an anonymous account | |

## Workflow

```text
                    FIRST USE
                        │
                        ▼
              reviewblind init .
                        │
                        ▼
             Identity discovery
                        │
                        ▼
                 User confirms
                        │
                        ▼
             .reviewblind.toml
                        │
             ┌──────────┴──────────┐
             ▼                     ▼
     reviewblind scan .      edit identities
       --target mirror
             │
             ▼
       evidence findings
             │
             ▼
       fix repository
             │
             ▼
          re-scan
             │
             ▼
     no blockers/warnings
             │
             ▼
 reviewblind export report.json
   --format anonymous-github
             │
             ▼
     Anonymous GitHub / Hido
```

For a supplementary ZIP, use `reviewblind scan . --target archive`. For an anonymous
public repository, use `reviewblind scan . --target repository`.

## Scope of 0.1.0

**In scope:** the five commands; three target profiles; text, path, manifest, Git,
notebook, PDF, image and packaging scanners; stable fingerprints; terminal, JSON and
Markdown reports; an explicit incomplete-scan state.

**Out of scope:** `bundle`, `adjudicate`, baselines, SARIF, HTML reports, DOCX,
recursive archive inspection, hyperref internals, venue profiles, MCP, LLMs,
stylometry.

The release checklist is in [ROADMAP.md](ROADMAP.md).

## Planned for 1.1

Only after using 0.1.0 on real repositories:

- baseline and adjudication
- SARIF
- DOCX metadata
- safe ZIP and TAR inspection
- hyperref named-destination scanner

`reviewblind bundle` will be evaluated afterwards. It is not committed until scanning
itself works extremely well.
