# INT6000CMD Web Security Project

This group project assesses and improves the security of
[django-helpdesk](https://github.com/django-helpdesk/django-helpdesk). The shared
starting point is upstream **v2.3.3** at commit
`360bace463c78314adb07d6b8bffc4676b73be29`. The upstream licence is
BSD 3-Clause; see [LICENSE](LICENSE).

The initial import intentionally contains the upstream baseline, **not** the
group's security fixes. The preliminary local SEC-01 change is being kept
separate for member review and an accurately attributed follow-up commit.

New teammates: follow the [Windows and VS Code setup guide](team-setup/README.md).
The [Chinese version](team-setup/README_ZH.md) is also available.

See [project provenance](docs/PROJECT_PROVENANCE.md) and the
[coordinator contribution log](docs/COORDINATOR_CONTRIBUTIONS.md). Each member
should work in a separate feature branch and provide before/after test
evidence for their assigned security findings.
