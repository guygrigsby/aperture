# CLAUDE.md

Steering file for coding agents working in this repo.

## On this file (read first)

The **Engineering discipline** and **Writing style** sections below are excerpted
from my personal `~/.claude/CLAUDE.md`, the global instruction file that governs
every agent session I run, across every project. They are reproduced here on
purpose. The take-home asks how I wrap coding agents in review, testing and
security practice; this is the literal answer. These are the standing guardrails
I work under, not rules invented for this exercise. The provenance is the point:
you are seeing my actual flow.

The **Project invariants** section is specific to this repo and was written for
it.

## Project invariants (this repo)

- **Identity is ambient.** The caller's identity is resolved from Tailscale
  `WhoIs` on the connection, never from a tool argument, header, or any
  client-supplied value. No tool takes an `identity`/`user`/`role` parameter. See
  `docs/adr/0001-identity-is-ambient.md`.
- **Fail closed.** Any error resolving identity or capabilities yields a deny
  plus an audit line. Never fail open, never panic on the authz path.
- **DDD dependency rule.** `internal/authz` is the domain and imports nothing
  from `tailscale.com`. Vendor types stop at the `internal/tailnet`
  anti-corruption layer. Verifiable with one grep; keep it true.
- **Tailnet is the perimeter.** Bind only to the `tsnet` listener, never
  `0.0.0.0`. No Funnel. `TS_AUTHKEY` from env; tsnet state and key material stay
  gitignored.
- **Anti-slop.** No speculative abstractions, no interface with one
  implementation, no config for a value that never changes. Smallest thing that
  works. Pin the official MCP SDK and let CI compile it so a hallucinated API
  can't survive.

## Engineering discipline (excerpted from my global CLAUDE.md)

- **Prove every bug with a failing test first.** Reproduce in a test, watch it
  fail, fix to green. The security boundary here gets its deny-path test written
  before the code that satisfies it.
- **Test through the real path before claiming done.** Before any
  fixed/working claim: what exactly does the user do, and did I do that and watch
  it succeed? State what was verified and what couldn't be.
- **Commit autonomously, in discrete logical units.** Each self-contained unit
  (a feature, a fix, a test+impl pair) gets its own commit with a clear message
  the moment it's coherent and green. The git history should narrate the work.
- **Self-review every diff for duplicated code and misplaced functionality.**
  The two failure modes of AI-written code: near-identical functions or repeated
  literals that should be factored, and logic put in the wrong layer or
  reimplementing something that exists. Dedup and re-home before committing.
- **Security-review every diff that touches an auth, identity, secret, or trust
  boundary before merge.** A fresh-context adversarial pass (a separate
  subagent, not the author) hunting fail-open paths, identity spoofing, value or
  secret leakage, and info disclosure. Verify each finding rather than trust it:
  agent reviewers carry their own false positives, the build is the arbiter. For
  agent-generated security code this is mandatory, it is how the production bar
  holds. This repo's authz core got exactly that pass, and its findings are in
  the PR threads.
- **Check for existing libraries before building from scratch.** Order: deps
  already in the project, stdlib, then a maintained registry package. State the
  chosen library or why none fit.
- **Use DDD for large changes.** Name the bounded contexts, ubiquitous language,
  aggregates/invariants and the anti-corruption layer at vendor boundaries before
  implementation.
- **Record architectural decisions as ADRs** (`docs/adr/NNNN-kebab-title.md`,
  with Status and Context/Decision/Consequences). Append-only; supersede, never
  rewrite.

## Writing style (excerpted from my global CLAUDE.md)

No em or en dashes, ever. Lead with the answer, verb-first, no preamble. Terse;
no editorializing affirmations. No document scaffolding (`## Summary`, test-plan
tables, quantified-everything). Backticks only for real symbols. Specifics over
ornament. Applies to commits, comments, docs and PR text in this repo.

## No agent attribution in git

Commits and PRs carry no `Co-Authored-By` trailers and no "Generated with" or
tool-attribution footers. (The README's "Built with agents" section is a
deliberate, separate POV write-up, not boilerplate attribution.)

## Tooling (the plugins behind this)

Built with Claude Code, disciplined by these public plugins. Two of them I wrote:

- [ddd](https://github.com/guygrigsby/claude-plugins) (mine): domain-driven
  design for large changes. The bounded contexts, ubiquitous language and
  anti-corruption layer in this repo come from it.
- [my-voice](https://github.com/guygrigsby/claude-plugins) (mine): builds a
  writing-voice corpus from real email/PR/blog history; the docs and PR prose
  are drafted through it.
- [superpowers](https://github.com/anthropics/claude-plugins-official):
  brainstorming, written plans, TDD, and subagent-driven execution with review
  checkpoints.
- [ponytail](https://github.com/DietrichGebert/ponytail): lazy-senior-dev
  discipline. Stdlib and native before dependencies, shortest working diff, no
  speculative abstractions.
