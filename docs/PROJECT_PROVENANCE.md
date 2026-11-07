# Project provenance and baseline

| Item | Record |
| --- | --- |
| Upstream source | https://github.com/django-helpdesk/django-helpdesk |
| Assessed version | `v2.3.3` |
| Upstream tag commit | `360bace463c78314adb07d6b8bffc4676b73be29` |
| Licence | BSD 3-Clause; retain `LICENSE` and third-party notices |
| Tag verification | The commit above matched the official upstream `refs/tags/v2.3.3` on 7 November 2026. |
| Original local clone date | Not independently verified; do not infer it from file timestamps. |

The group's initial repository contained its own `README.md` and `.gitignore`.
The upstream Git history was merged into the group repository, rather than
copying an untracked folder or replacing the group's initial commit. The
`.gitignore` combines the group's original rules with upstream's rules and
explicitly excludes locally uploaded demo attachments. Group onboarding files
are separate from the assessed upstream source.

This baseline is the version used for the group's local security assessment.
It is **not** a claim that v2.3.3 is the newest release or that it is free of
security issues. SEC-01's preliminary local repair is intentionally not part
of the baseline import; it needs separate review and attribution.

Do not commit local virtual environments, SQLite databases, test attachments,
credentials, or ticket-access links. Each team member should create their own
local test environment using `team-setup/README.md`.
