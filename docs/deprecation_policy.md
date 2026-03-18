# Command Surface Deprecation Policy

This policy governs overlapping, advanced, legacy, deprecated, and removed Tideway command paths.

## Why This Exists

Tideway keeps one primary path for common API work:

1. `tideway new`
2. `tideway dev`
3. `tideway resource ...`
4. `tideway migrate`

Some older or more specialized commands still exist for compatibility and existing-project workflows.
This policy keeps those paths available without letting the public DX drift back into “many equally-valid starts”.

## Lifecycle Labels

### Primary

- Recommended for most users.
- Shown in onboarding docs and first-run help.
- Must have clear docs, tests, and a supported migration path from overlapping alternatives.

### Advanced

- Supported, but not part of the first-run story.
- Intended for existing projects, unusual architectures, or users who explicitly need manual control.
- Must be labeled `advanced` in CLI help and docs when referenced near onboarding material.

### Legacy

- Kept mainly for compatibility.
- Not promoted in onboarding or default examples.
- Should point users to the primary replacement whenever practical.

### Deprecated

- Still available, but scheduled to go away.
- Must have:
  - a documented replacement
  - migration notes
  - release-note visibility
  - an explicit removal target or removal condition

### Removed

- No longer part of the supported command surface.
- Docs, examples, tests, and release notes must stop teaching the removed path.

## Rules For Overlapping Command Paths

- One task gets one primary recommendation in onboarding docs.
- If two commands can accomplish the same common outcome, one of them must be primary and the other must be advanced, legacy, or deprecated.
- New top-level commands or flags that expand surface area must include:
  - a roadmap issue or equivalent rationale
  - migration notes if they overlap an existing path
  - updated docs/help that show where the new surface fits
- Do not add a new command just to provide another route to the same happy-path result.

## Deprecation Process

1. Stop promoting the old path.
2. Label it as `advanced` or `legacy` first when possible.
3. Publish the replacement path in `README.md`, `docs/getting_started.md`, and `docs/cli.md`.
4. Add release notes covering:
   - what changed
   - who is affected
   - what to run instead
5. Keep the deprecated path available for at least two minor Tideway releases unless there is a security or correctness reason to remove it faster.
6. Remove the path only after:
   - docs are updated
   - migration notes have shipped
   - tests and guardrails no longer depend on the old wording or behavior

## Maintainer Checklist

When a command path is introduced, relabeled, deprecated, or removed:

- update `docs/cli.md`
- update `README.md` and `docs/getting_started.md` if onboarding guidance changes
- update `.github/RELEASE_TEMPLATE.md`
- add or update mixed-command / messaging tests when the user-facing contract changes
- include the rationale and migration notes in release notes

## Current Default Interpretation

- `new`, `dev`, `resource`, `doctor`, and `migrate` are the primary command set.
- `add`, `backend`, `init`, `generate`, `setup`, and `templates` are advanced or compatibility-oriented surfaces and should stay out of the default onboarding path.
