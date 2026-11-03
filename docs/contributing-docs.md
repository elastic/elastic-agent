# Contributing to the docs

The published Elastic Agent docs are the Markdown under `docs/reference/edot-collector/` and `docs/release-notes/`. `docs/docset.yml` defines the docset. Markdown files directly under `docs/` are repository documentation. The `exclude: "*.md"` entry keeps them out of the build, because `*.md` matches only the files in that directory. This page is one of them.

The `elastic-agent` entry in [docs-builder `assembler.yml`](https://github.com/elastic/docs-builder/blob/main/config/assembler.yml) sets no `current`, `next`, or `edge`. When those are unset they are `main`, so every environment publishes `main`. Read that entry. If it gains a `current` ref, production publishes that ref instead, and a docs change is on the live site only once it is on that ref. Open the pull request against `main`.

* `docs/reference/edot-collector/` is the collector reference.
* `docs/release-notes/` holds the breaking changes, deprecations, and known issues. Its top-level pages are maintained by hand. The release entries under `_snippets/` are generated from changelog fragments by `.github/workflows/release-notes.yml`.
* `docs/reference/edot-collector/_snippets/` holds text included by more than one page. Edit a snippet only when every page that includes it should change.

For wording, follow the [Elastic style guide](https://www.elastic.co/docs/contribute-docs/style-guide). Write what you can now do, see, or configure. Use "you", present tense, and sentence case headings. Put settings, field names, and file names in backticks.

Product names that have a substitution in `docs/docset.yml` are written as `{{agent}}`, `{{es}}`, `{{kib}}`, and the rest of that list. Match the page you are editing.

## Where to add something [where-to-add]

Add to the page that already covers the topic. Add a new page only when no existing page can carry it, and then add it to that section's `toc.yml`.

Look through `docs/` and the published docs before you add a page. Each fact belongs in one place. Link to it from the other pages instead of repeating it.

A page you move, rename, or delete needs an entry in `docs/redirects.yml`.

Link to a page in another Elastic docset with its docset link (`docs-content://...`, `integration-docs://...`), not with a URL on `elastic.co`.

## Cumulative docs [cumulative-docs]

One page stays valid across versions. Mark a version or deployment difference with `applies_to` on the page or on the section that differs, instead of copying the page. Read [Write cumulative documentation](https://www.elastic.co/docs/contribute-docs/how-to/cumulative-docs) and the [`applies_to` reference](https://www.elastic.co/docs/contribute-docs/how-to/cumulative-docs/reference).

When a GA or deprecated feature, field, or setting is removed from a versioned product, keep the content and mark it `removed <version>` with `applies_to`. Readers on versions that still have it need the page. Delete it only when it was only ever a preview or beta, or only ever existed in a product that has no versions.

## Generated sections [generated-sections]

Edit the Markdown directly, except inside a generated block between a `% start:<tag>` line and a matching `% end:<tag>` line. [docs/scripts/update-docs/README.md](scripts/update-docs/README.md) lists the tags, input data, and generation command.

For component blocks, edit the source data and regenerate. The gateway and sample-link blocks are built from released tags, so refresh them with the generator instead of editing them by hand. Any edit inside the markers is overwritten the next time the script runs. The component table is built from the latest released version, not from unreleased commits on `main`.

A docs-only change does not get a changelog fragment. Add the `skip-changelog` label. A user-visible behavior change still gets a fragment, as `AGENTS.md` describes, and the fragment stays out of the doc page.
