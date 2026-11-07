# Contributing to SessionArmor

Issues and pull requests are welcome. For a vulnerability, use the private
reporting route in [SECURITY.md](SECURITY.md) instead of a public issue.

Fork the repository and make your change on a branch of your fork. Keep it
focused, explain its behavior and compatibility impact, update the relevant
docs, and include appropriate test evidence. Commit under your own name and
email. Never submit credentials, customer data, or production examples.
Contributions are provided under the repository's [MIT license](LICENSE);
preserve copyright and third-party license notices.

The owner (`@bezu-1`) reviews and approves external changes before merge.
New commits invalidate previous approval. Workflow, release, and agent
configuration (`.github/`, `.claude/`, `AGENTS.md`, `CLAUDE.md`) receive the
same owner review as application code.

Issues, pull requests, comments, and mentions never start workflows or
maintainer automation, and never grant access to release credentials. CI does
not run automatically on pull requests: only the owner starts the manual
workflows, so include the commands you ran locally and their results. Do not
ask an automated agent to approve or merge its own work.

See [VERSIONING.md](VERSIONING.md) for the common versioning and release policy
and the README's development instructions for this package's local checks.
