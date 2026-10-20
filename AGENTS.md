# Repository workflow

- Make all new changes directly on `main`.
- Do not create or switch to feature branches, task branches, or additional Git worktrees.
- Before editing, verify that the current branch is `main`. If it is not, return to `main` without discarding or overwriting uncommitted work. Ask the user before proceeding if switching safely is not possible.
- Do not commit or push changes unless the user explicitly asks.
- Author every commit and merge as `Alex <bezman.alexc@gmail.com>` (`git config user.name "Alex"`,
  `git config user.email "bezman.alexc@gmail.com"`), and do not add `Co-Authored-By: Claude` or
  `Claude-Session` trailers to commit messages.
