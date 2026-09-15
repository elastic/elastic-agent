"""Build the body for the automated update-docs pull request.

Reads review items (newly stamped components and documentation coverage gaps)
from the ``NEW_COMPONENTS_FILE`` JSON file when present, and writes the rendered
Markdown PR body to ``$RUNNER_TEMP/pr-body.md``.

This lives in its own module (rather than an inline heredoc in the workflow) so
that the workflow YAML stays valid and the rendering logic can be unit tested.

Environment variables:
  VERSION              Release version string (e.g. ``v9.5.3``). Required.
  NEW_COMPONENTS_FILE  Path to the JSON review-items file. Optional.
  RUNNER_TEMP          Directory to write ``pr-body.md`` into. Required.
"""

import json
import os
import pathlib


def build_new_components_section(names, version):
    """Return the 'new components detected' section, or None when empty."""
    if not names:
        return None
    bullets = "\n".join(f"- `{n}`" for n in names)
    return (
        "## ⚠️ New components detected\n\n"
        f"The following components appear in `{version}` for the first time.\n"
        "Please review each one and update `internal/edot/components.yml` as needed:\n\n"
        f"{bullets}\n\n"
        "For each new component, consider:\n"
        "- Should it be listed under `core_components`?\n"
        "- Does it need a `deprecated` entry?\n"
        "- Does it need an `annotations` comment (e.g., support caveats)?"
    )


def build_doc_coverage_section(coverage):
    """Return the 'documentation coverage gaps' section, or None when empty."""
    missing = coverage.get("missing_targets", [])
    orphaned = coverage.get("orphaned_pages", [])
    if not missing and not orphaned:
        return None

    lines = []
    if missing:
        lines.append("**Mappings pointing to missing files** in `component-docs.yml`:")
        lines += [f"- `{m['component']}` → `{m['doc_path']}`" for m in missing]
    if orphaned:
        if lines:
            lines.append("")
        lines.append(
            "**Component pages not linked from the components table** "
            "(add a mapping in `component-docs.yml`):"
        )
        lines += [f"- `{p}`" for p in orphaned]
    joined = "\n".join(lines)
    return f"## 📄 Documentation coverage gaps\n\n{joined}"


def build_body(data, version):
    """Render the full PR body from the review-items ``data`` dict."""
    sections = []
    new_components = build_new_components_section(data.get("newly_stamped", []), version)
    if new_components:
        sections.append(new_components)
    coverage = build_doc_coverage_section(data.get("doc_coverage", {}))
    if coverage:
        sections.append(coverage)

    extra = ("\n\n" + "\n\n".join(sections)) if sections else ""

    return (
        f"This PR updates the generated documentation based on the latest released version **{version}**.\n\n"
        "## Changes\n"
        "- Updates Elastic Agent component tables\n"
        "- Updates OpenTelemetry Collector Builder (OCB) configuration\n"
        f"- Uses data from the latest released version tag: `{version}`\n\n"
        "## References\n"
        f"- **Source go.mod**: https://github.com/elastic/elastic-agent/blob/{version}/internal/edot/go.mod\n"
        f"- **Source components.yml**: https://github.com/elastic/elastic-agent/blob/{version}/internal/edot/components.yml\n"
        f"- **Release tag**: https://github.com/elastic/elastic-agent/tree/{version}\n"
        f"{extra}\n\n"
        "cc @elastic/ski-docs\n\n"
        "This is an automated PR created by the documentation update workflow.\n"
    )


def load_review_items(path):
    """Load the review-items JSON file, returning {} when absent or unreadable."""
    if not path:
        return {}
    review_file = pathlib.Path(path)
    if not review_file.exists():
        return {}
    try:
        return json.loads(review_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        print(f"Warning: could not read review items file: {e}")
        return {}


def main():
    version = os.environ["VERSION"]
    data = load_review_items(os.environ.get("NEW_COMPONENTS_FILE"))
    body = build_body(data, version)
    out = pathlib.Path(os.environ["RUNNER_TEMP"]) / "pr-body.md"
    out.write_text(body, encoding="utf-8")
    print(f"PR body written to {out}")


if __name__ == "__main__":
    main()
