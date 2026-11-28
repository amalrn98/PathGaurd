# Continuous integration

## What runs

`.github/workflows/ci.yml` runs on every push to `main`, every pull request, and on demand.

| Job (check name) | What it verifies |
|---|---|
| `test (stable)` | Build all targets and run every test (unit, integration, property tests, deterministic fuzz smoke test, doc tests) on the latest stable Rust. |
| `test (1.88)` | The same on the **minimum supported Rust version**, 1.88. |
| `lint` | Actions are SHA-pinned, `cargo fmt --check`, `cargo clippy -D warnings`, `cargo doc` with warnings as errors. |
| `audit` | `cargo deny`: security advisories, banned and yanked crates, allowed sources and licenses. |
| `fuzz targets build` | The `cargo-fuzz` crate in `fuzz/` still compiles. |
| `ci-success` | Aggregates the jobs above. Fails if any of them did not succeed. |

`.github/workflows/fuzz.yml` runs the coverage-guided fuzz targets on nightly Rust every Monday and on demand (`Actions` tab, "Run workflow"). It needs nightly, so it is not part of the required checks. Crashing inputs are uploaded as artifacts.

### Supported Rust versions

* **stable**: always tested.
* **1.88**: the minimum, declared as `rust-version` in `Cargo.toml`. Raising it is a deliberate change: update `Cargo.toml`, the matrix in `ci.yml`, and this file together.

## Actions are pinned to commit SHAs

Every third-party action is referenced by its full 40-character commit SHA, with the release in a trailing comment. Mutable tags (`@v7`) and branches (`@master`) can be moved by whoever controls the action repository, so they are not used. `scripts/check-pinned-actions.sh` runs in the `lint` job and fails the build if an unpinned reference appears.

Toolchain selection uses the `toolchain:` input of `dtolnay/rust-toolchain` instead of a branch name.

**Updating.** Dependabot (`.github/dependabot.yml`, ecosystem `github-actions`) opens a weekly grouped pull request that bumps the SHA and its version comment together. To review one: open the compare link in the PR, read the diff between the two SHAs, and check the release notes. Do the same by hand when updating manually:

```bash
gh api repos/OWNER/REPO/git/ref/tags/vX.Y.Z --jq .object.sha     # lightweight tag
gh api repos/OWNER/REPO/git/tags/<sha-from-above> --jq .object.sha  # annotated tag: dereference to the commit
```

The SHAs currently in use were resolved from the official release tags of each action repository and recorded in the workflow comments. They have not had an independent source review, which is a reasonable thing for a maintainer to do once.

## Branch protection

Status when this was written: **`main` is not protected** (`GET /branches/main/protection` answers 404), so a failing CI run does not stop a merge or a direct push.

Recommended settings for `main` (Settings, Branches, Add rule, or a ruleset):

* Require a pull request before merging, with at least one approving review (this repository has a CODEOWNERS file).
* Require status checks to pass before merging, and require branches to be up to date. Required checks: `ci-success`. If you prefer them individually: `test (stable)`, `test (1.88)`, `lint`, `audit`, `fuzz targets build`.
* Dismiss stale approvals when new commits are pushed.
* Block force pushes and branch deletion.
* Optionally require signed commits and linear history.

The same with the GitHub CLI (review before running, because it changes repository settings and will block direct pushes to `main`):

```bash
gh api -X PUT repos/amalrn98/PathGuard/branches/main/protection --input - <<'JSON'
{
  "required_status_checks": { "strict": true, "contexts": ["ci-success"] },
  "enforce_admins": false,
  "required_pull_request_reviews": { "required_approving_review_count": 1, "dismiss_stale_reviews": true, "require_code_owner_reviews": true },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON
```

Note that with required reviews, a sole maintainer cannot approve their own pull requests. Either add a second reviewer, or set the required approvals to 0 and keep the required status checks, which is still a real gain.

**This was not applied automatically.** Repository settings were deliberately left unchanged because changing them was not requested explicitly and would alter how the maintainer can push.

## Verifying a commit

Every push triggers CI. To check a specific commit:

```bash
gh run list --commit <sha>            # runs for exactly that commit
gh api repos/amalrn98/PathGuard/commits/<sha>/check-runs --jq '.check_runs[] | [.name,.conclusion] | @tsv'
```
