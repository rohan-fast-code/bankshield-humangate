# Releases: How To Judge A Release Safely

This repo uses source only releases. No binary, no installer, and no secret is ever attached to a release. If you see a binary claiming to be BankShield HumanGate from another account, from a fork, or from a download site, treat it as untrusted until you verify it yourself.

## Release types in this repo

1. Major release, for example v2.0.0: gate decision logic changes, or a breaking change to an adapter or a test contract.
2. Minor release, for example v1.1.0: a new adapter, a new attack type with a test, or a new feature that does not break existing tests.
3. Patch release, for example v1.0.1: a bug fix, a docs fix, or a security fix with no new feature.
4. Pre release, for example v1.1.0-rc.1: a test version for review only, not for production use, and clearly marked as pre release on GitHub.
5. Security release: a fix for a vulnerability, with a clear note on what changed, what versions are affected, and what to update, and no exploit details in the public notes.

## How anyone can judge a release safely, in order

1. Check the source account and repo: rohan-fast-code/bankshield-humangate only. A fork, a similar name, or a reupload is not an official release.
2. Check the tag and the commit: the release tag must point to a commit on main in this repo, with author rohan-fast-code, and with the test commits visible in history. If the tag points to a commit you cannot find in this repo, do not trust it.
3. Check the release notes: every release must list what changed, what tests passed, and what is still a demo limit. A release with no notes, or with vague claims, is not safe to judge, so do not use it.
4. Run the tests yourself, from the release source, with Python 3 only, no extra dependencies, using the commands in README. Do not trust a test badge alone.
5. Check for secrets: run a search for keys, tokens, and passwords in the release source. This repo must contain demo values only. If you find a real secret, stop, and report it under SECURITY.md, and do not share it publicly.
6. Check the scope: this is a demo and research codebase, not a certified banking product. A release does not mean a bank can use it in production without its own threat modelling, penetration testing with permission, code review, and compliance review.
7. Check the checksum, if one is published in the release notes: download the source zip from GitHub only, compute its checksum yourself, and compare it to the checksum in the release notes. If they do not match, do not use that download.

## What a release must never contain

1. No real bank code, no real customer data, no real secret, no real key, and no real token.
2. No working exploit against a real bank, a real app, or a real website.
3. No binary that hides code you cannot read. If a future release ever adds a built artifact, it must be built by GitHub Actions from the same tagged source, with the build log public, and with a checksum published in the release notes.

## How a release is made in this repo

1. All tests pass locally, and the 120 attack test shows 120 blocked and 0 allowed.
2. Release notes are written in docs/RELEASE_NOTES_v1.0.0.md style, with changes, tests, limits, and safety notes.
3. Maintainer creates a tag, for example v1.0.0, on main, and creates a GitHub release from that tag, with the same notes, and with the tag commit visible.
4. After publishing, maintainer verifies the release page, the tag, and the source zip link, and records the release link in this file.

## Current releases

1. v1.0.0: first public release, planned, see docs/RELEASE_NOTES_v1.0.0.md. Status at the time of writing this file: notes ready in repo, GitHub release not yet published, because release creation needs the GitHub web UI, and is being done as a separate step.
