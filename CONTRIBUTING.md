# Contributing to Elastic Agent

## Got Questions?

Have a problem you want Elastic Agent to solve for you?

* You can ask a question in the [forum](https://discuss.elastic.co/c/elastic-stack/elastic-agent).
* You are welcome to join Elastic Stack Community slack (https://elasticstack.slack.com) and ask for help on the #elastic-agent channel.

## Have an Idea or Feature Request?

* File an issue on [GitHub](https://github.com/elastic/elastic-agent/issues). Please remember that GitHub is used only for bugs and feature requests. If you have a general question, the [forum](https://discuss.elastic.co/c/elastic-stack/elastic-agent) or Elastic Stack Community slack (https://elasticstack.slack.com) is the best place to ask.

## Something Not Working? Found a Bug?

If you think you found a bug, it probably is a bug. Fill it in [GitHub](https://github.com/elastic/elastic-agent/issues)

## Found a Security Issue?

If you've found a security issue, before submitting anything via a PR, please
get in touch with our security team [here](https://www.elastic.co/community/security).

# Pull Request Guidelines

The following exists as a way to set expectations for yourself and for the review process. We *want* to merge fixes and features, so let's describe how we can achieve this:

## Goals

* To constantly make forward progress on PRs

* To have constructive discussions on PRs

## Overarching Guiding Principles

Keep these in mind as both authors and reviewers of PRs:

* Have empathy in both directions (reviewer <--> reviewee/author)
* Progress over perfection and personal preferences
* Authors and reviewers should proactively address questions of pacing in order to reach an acceptable balance between meeting the author's expected timeline for merging the PR and the reviewer's ability to keep up with revisions to the PR.

## As a reviewee (i.e. author) of a PR:

* I must put up atomic PRs. This helps the reviewer of the PR do a high quality review fast. "Atomic" here means two things:
  - The PR must contain related changes and leave out unrelated changes (e.g. refactorings, etc. that could be their own PR instead).
  - If the PR could be broken up into two or more PRs either "vertically" (by separating concerns logically) or horizontally (by sharding the PR into a series of PRs --- usually works well with mass refactoring or cleanup type PRs), it should. A set of such related PRs can be tracked and given context in a meta issue.

* The PR changeset should be rather small: 500 lines of code (excluding generated code or other changes that normally should not require close review by a human) is the soft limit that should be used to judge if a PR is "too big".

* I must strive to please the reviewer(s). In other words, bias towards taking the reviewers suggestions rather than getting into a protracted argument. This helps move the PR forward. A convenient "escape hatch" to use might be to file a new issue for a follow up discussion/PR. If you find yourself getting into a drawn out argument, ask yourself: is this a good use of our time?

## As a reviewer of a PR:

* I must first focus on whether the PR works functionally -- i.e. does it solve the problem (bug, feature, etc.) it sets out to solve.

* Then I should ask myself: can I understand what the code in this PR is doing and, more importantly, why it's doing whatever it's doing, within 1 or 2 passes over the PR?

  * If yes, approve the PR!

  * If no, ask for clarifications on the PR. This will usually lead to changes in the code such as renaming of variables/functions or extracting of functions or simply adding "why" inline comments. But first ask the author for clarifications before assuming any intent on their part.

* I must not focus on personal preferences or nitpicks. If I understand the code in the PR but simply would've implemented the same solution a different way that's great but it is not feedback that belongs in the PR. Such feedback only serves to slow down progress for little to no gain.*

* If I'm making a suggestion, I must provide a rationale for it.  It should be clear to the author of the PR why my suggestion is better than what is already in the PR.


