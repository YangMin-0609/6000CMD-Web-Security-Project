# Project coordinator contribution record

This is a factual working log for the repository owner/project coordinator.
Replace the role label with the member's preferred name before using it in the
final report. Add commit links and dates as the work is merged; do not claim
unfinished work as completed.

## Work already performed

1. Obtained permission to use the open-source django-helpdesk project for the
   group assignment (reported by the coordinator).
2. Created the group's GitHub repository and set up a local django-helpdesk
   v2.3.3 demo for testing.
3. Participated in and documented the scoped local baseline assessment that
   identified SEC-01 through SEC-06. This does **not** mean all possible
   weaknesses in the system have been found.
4. Tested the preliminary SEC-01 queue-access change locally: an unauthorised
   SP-2 ticket returned 403, an authorised DH-3 ticket remained accessible,
   and the ticket list/Queue filter no longer exposed Some Product to the
   test staff account. The preliminary code change was **AI-assisted** and
   remains subject to member review and separate contribution attribution.
5. Organised the four-member task allocation and prepared onboarding and
   evidence-handoff materials with AI assistance.
6. Prepared the upstream v2.3.3 import into the group repository while
   preserving the upstream history and separating the baseline from fixes.

## Not claimed as completed by the coordinator

- Independent authorship of the existing preliminary SEC-01 code.
- Fixes or retests for SEC-02 through SEC-06.
- A complete production security audit or proof that no other issues exist.

## Evidence and follow-up

The coordinator's local evidence pack contains SEC-01 before/after screenshots,
code screenshots, and selected baseline screenshots for other findings. Review
and redact screenshots before publishing them. Add links to the group commits,
Pull Requests, and the final Chapter 4 retest results when they exist.
