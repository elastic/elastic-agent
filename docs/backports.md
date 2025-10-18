# Backports

## Overview

Elastic Agent relies on backporting PRs to incorporate changes into the appropriate release branches after merging
into `main`. Creating backport PRs is handled automatically using the appropriate [backport labels](https://github.com/elastic/elastic-agent/labels?q=backport).

To target specific release branch(es), add one or more labels `backport-<release branch name>` (e.g. `backport-9.2`). PRs can be labeled
before or after the PR is merged. If added before merging, the backports will be created after merging to `main`. Adding
a backport label to an already merged PR will create backports shortly after adding the label(s).

Mergify will automatically add a [reminder](https://github.com/elastic/elastic-agent/blob/main/.mergify.yml#L173) to any PR to `main` if missing at least one `backport-*` label. If your PR does _not_ need backporting, use the `backport-skip` label to avoid the automated comment.

There are also three additional `backport-*` labels to simplify which branches to target backports:

* `backport-active-all`: Backport to all currently active development branches (except `main`)
* `backport-active-8`: Backport only to 8.x branches
* `backport-active-9`: Backport only to 9.x branches


These labels use the [`backport-active` GitHub action](https://github.com/elastic/elastic-agent/blob/main/.github/workflows/backport-active.yml#L14) to automate targeting relevant branches. More detail can be found at
https://github.com/elastic/oblt-actions/blob/main/github/backport-active/README.md.

## Process

**For changes authored by an individual** - the original PR author is in charge of ensuring their original PR uses the
correct labels, the backport PRs are created, pass CI, and are merged.

**For changes authored by automation (GitHub actions, dependabot, etc.)** - these PRs should already be labeled with
`backport-active-all`. After the initial PR to `main` merges, the code reviewers (assigned based on teams defined in
`CODEOWNERS`) need to verify CI passes, approve, and merge the backport PRs.
