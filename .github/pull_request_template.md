<!--
  INSTRUCTIONS — for whoever or whatever fills this in, human or agent.

  These sections are ENFORCED by the `ci / passed` check, not suggested. A
  missing or empty section fails the pull request.

  Everything inside an HTML comment is stripped before the emptiness test, so
  guidance never counts as an answer. Write outside the comments. You may delete
  the comments; you may not delete the headings.

  RULES THE CHECK APPLIES, exactly:
    1. All five `##` headings must be present: What, Why, Changelog,
       Verification, Risk.
    2. Each must contain at least one non-comment, non-blank line.
    3. EVERY line under `## Changelog` must be a Conventional Commits bullet:
         - <type>[optional (scope)][optional !]: <description>
       Types: build, chore, ci, docs, feat, fix, perf, refactor, revert, style,
       test. Nothing else parses. Prose, blank-line-separated paragraphs, or a
       bullet without a type will fail.

  WHY THE CHANGELOG FORMAT IS STRICT: this repository squash-merges with the
  pull request body as the commit message, so these bullets become the
  repository's permanent history, and the version bump is derived from them. A
  bullet nobody can parse is a release nobody can version.

  BE SPECIFIC IN THE DESCRIPTION. "fix: bug" is parseable and useless. Name what
  was wrong and where: "fix: a metadata leak in the audit relay that logged full
  request bodies".

  ONE BULLET PER USER-VISIBLE CHANGE. Refactors nobody can observe do not need
  one; use `chore:` or `refactor:` if you want them recorded.
-->

## What

<!-- What changed, in a sentence or two. Not a restatement of the diff. -->

## Why

<!--
  The reason, not the mechanism. If this follows from a decision or an open
  question in the record, name it (D42, O19) — that is what makes the record
  worth keeping.
-->

## Changelog

<!--
  Conventional Commits bullets, one per user-visible change. Examples:

    - fix: a metadata leak in the audit relay that logged full request bodies
    - feat(recall): return partial results when one provider is unhealthy
    - feat!: drop the by-name arm of GetWikiPage

  `!` marks a breaking change and implies a major bump. `feat:` implies minor,
  everything else patch. The highest bullet wins.
-->

## Verification

<!--
  How you know it works. "CI is green" counts only where CI covers it; say so if
  it does not, and say what you ran instead.
-->

## Risk

<!--
  What breaks if this is wrong, and how it is undone. "None" is a valid answer
  and worth writing rather than leaving blank.
-->
