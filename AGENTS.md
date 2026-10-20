# Agent guidance for the Goodnotes Kratos fork

This repository is the Goodnotes fork of [Ory Kratos](https://github.com/ory/kratos).
The Goodnotes integration branch is `goodnotes`; target fork pull requests there
unless the task explicitly specifies another branch. The inherited
`CONTRIBUTING.md` describes upstream's `master` workflow.

## Check upstream before implementing

Before implementing a change or fix, check whether upstream Ory Kratos already
contains a suitable solution. This applies to application behavior, tests,
dependencies, build tooling, and CI. Prefer reusing upstream work over inventing
and maintaining a parallel implementation in this fork.

1. Identify the affected behavior and files in this fork.
2. Inspect the corresponding current upstream code and relevant commits, pull
   requests, issues, and release notes. Search by the symptom or error as well
   as the affected symbols or paths; checking only our fork or one keyword is
   not enough to conclude that upstream has no fix. Keep the investigation
   proportional to the change.
3. If a suitable upstream change exists, inspect its complete patch, tests,
   prerequisites, and any follow-up fixes. Check compatibility with our version
   and Goodnotes-specific behavior before adopting it.
   - Prefer `git cherry-pick -x <commit>` when the patch and its necessary
     prerequisites fit this fork.
   - Otherwise, port the smallest relevant change and its regression tests.
     Preserve upstream attribution and explain any adaptations.
   - Treat an unmerged upstream PR as a candidate to review, not as an accepted
     or released fix.
4. If no applicable upstream change exists, proceed with the normal local
   implementation and testing workflow. An upstream solution that cannot
   safely be ported also permits a local fix; document the incompatibility.

Use GitHub or a verified upstream Git remote for this investigation. Inspect
remote URLs rather than assuming that `origin` points to Ory. Do not merge all
of upstream or pull in unrelated changes merely to obtain one fix.

## Record evidence and validate the result

In the PR description, record the upstream repository and ref or commit checked,
the relevant search scope, and the outcome:

- For a cherry-pick or port, link the upstream PR and commit, describe adaptations
  and required prerequisites, and report the tests run against this fork.
- For a local implementation, summarize what was checked and why no upstream
  change applies. If upstream could not be inspected, state that limitation;
  do not present an unavailable check as evidence that no fix exists.

Upstream tests passing does not prove compatibility with this fork. Run focused
regression tests here, including coverage of affected Goodnotes-specific
behavior, and report validation gaps explicitly.
