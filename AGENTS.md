# AGENTS.md

Instructions for AI coding agents working in this repository. Read this file in full before changing anything.

## Repository layout

- `backend/`: Rust HTTP API. Rules: [`backend/AGENTS.md`](backend/AGENTS.md).
- `frontend/`: Flutter client. Rules: [`frontend/AGENTS.md`](frontend/AGENTS.md).

This file holds the rules for the whole repository. Before you change anything under `backend/` or `frontend/`, read that directory's `AGENTS.md` as well. Its rules add to the ones here and never relax them.

The rules are **requirements, not suggestions**. Most of them are enforced by compilers, linters or CI. Do not work around a check. If a rule blocks you, stop and ask the human (see [Exceptions](#exceptions)).

---

## 1. Do not turn the checks off

- Never weaken, disable or bypass a lint, type check, test, CI step or threshold. That includes editing lint or CI configuration, adding suppression comments or attributes, skipping or deleting tests, and lowering coverage or mutation thresholds.
- Never "fix" a failing check by weakening it. Fix the code.

## 2. Dependencies

- Prefer the standard library and existing dependencies.
- Ask the human before adding a new dependency. Say what it is for, whether it is actively maintained and why the existing ones are not enough.
- Once the human approves, add it yourself with the package manager (`cargo add`, `flutter pub add` and similar), following [2.1](#21-versions-and-pinning).
- Lockfiles are committed. They change only as a side effect of a dependency change.

### 2.1 Versions and pinning

- When you add a dependency, tool, action, container image or any other installed component for the first time, use its **latest stable release**. Look up the current version from the official registry or release page. Do not take it from memory, because your training data is out of date.
- Pin to an immutable reference whenever the ecosystem supports one:
  - **GitHub Actions:** pin the full 40-character commit SHA, with the human-readable version in a comment after it:

    ```yaml
    - uses: actions/checkout@<full-40-char-commit-sha> # v4.2.2
    ```

    Never use a tag (`@v4`) or a branch (`@main`). Resolve the SHA from the release tag itself, not from the default branch.
  - **Container images:** pin by tag and digest: `image: postgres:17.2@sha256:<digest>`. The digest is what gets pulled. The tag tells people and Renovate which version it is.
  - **Package managers** (Cargo, npm and similar): the committed lockfile pins exact versions and checksums. Keep it committed and do not hand-edit it.
- When you update a pinned reference, update the SHA and its version comment together, so the comment always matches the SHA.
- [Renovate](https://docs.renovatebot.com/) (`renovate.json`) opens pull requests that update dependencies, pinned SHAs, image digests and the pinned SDK versions. When you pin a version that Renovate does not detect on its own, such as a version in a workflow `env:` block, add a `# renovate: datasource=<datasource> depName=<name>` comment on the line above it.

## 3. Secrets

- Never commit secrets, `.env` files, credentials or tokens.
- Never log, print or return a secret in an error message or response.

## 4. Tests must actually test something

- Every behavior change needs tests that **fail without the change**. Test behavior through public interfaces, not implementation details.
- Do not write tests with no assertions, tests that only check that something "succeeded" without checking the result, or tests that mock the very thing under test.
- If mutation testing reports a surviving mutant, the tests are too weak. Fix it by writing a better test, never by deleting the code path or adding an exception.

## Exceptions

When a rule genuinely cannot be followed:

1. Stop. Do not work around it.
2. Use the smallest possible exception, in the form the directory's `AGENTS.md` prescribes, with a written reason that explains why the code is correct.
3. Point it out explicitly to the human in your summary or PR description, with the file and line.

## Before you finish

Run every check listed in the `AGENTS.md` of each directory you changed. All of them must pass. If any fails, the task is not done. Do not report success with failing checks.
