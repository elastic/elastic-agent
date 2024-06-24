<!-- Type of change
Please label this PR with one of the following labels, depending on the scope of your change:
- Bug
- Enhancement
- Breaking change
- Deprecation
- Cleanup
- Docs
-->

## What does this PR do?

<!-- Mandatory
Explain here the changes you made on the PR. Please explain the WHAT: patterns used, algorithms implemented, design architecture, message processing, etc.
-->

## Why is it important?

<!-- Mandatory
Explain here the WHY, or the rationale/motivation for the changes.
-->

## Checklist

<!-- Mandatory
Add a checklist of things that are required to be reviewed in order to have the PR approved

List here all the items you have verified BEFORE sending this PR. Please DO NOT remove any item, striking through those that do not apply. (Just in case, strikethrough uses two tildes. ~~Scratch this.~~)
-->

- [ ] My code follows the style guidelines of this project
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] I have made corresponding change to the default configuration files
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] I have added an entry in `./changelog/fragments` using the [changelog tool](https://github.com/elastic/elastic-agent#changelog)
- [ ] I have added an integration test or an E2E test

## Disruptive User Impact

<!--
Will the changes introduced by this PR cause disruption to users in any way? If so, please describe what changes users
could make on their end to nullify or minimize this disruption. Consider impacts in related systems, not just directly
when using Elastic Agent.
-->

## How to test this PR locally

<!-- Recommended
Explain here how this PR will be tested by the reviewer: commands, dependencies, steps, etc.
-->

## Related issues

<!-- Recommended
Link related issues below. Insert the issue link or reference after the word "Closes" if merging this should automatically close it.

- Closes #123
- Relates #123
- Requires #123
- Superseds #123
-->
-

## Questions to ask yourself

- How are we going to support this in production?
- How are we going to measure its adoption?
- How are we going to debug this?
- What are the metrics I should take care of?
- ...

<!-- CI Cheatsheet
Trigger comments:
/test             (Or `buildkite test this|it`) Triggers unit test pipeline
/test extended    (Or `buildkite test extended`) Triggers integration test pipeline

PR labels:
skip-ci           Skips unit and integration tests
skip-it           Skips integration tests
-->