# Stage-4 gate harness

Prepare a Curator-installed memory skill, let the orchestrator run two agents,
then verify A's source-linked decision observation recalled by B. These scripts
never start an agent. `self-test` substitutes direct CLI calls for the agents;
a passing self-test is harness evidence, not a completed agent gate.

Requirements: POSIX, Python 3.10+, Git with SSH commit signing, `ssh-keygen`,
Go 1.25+, and an already installed Curator supporting Skillfile schema 2 and
skill schema 8 (tested with 0.15.0-rc.7). No dependencies are installed.

## Prepare

From the source checkout:

```sh
.scripts/stage4-gate/prepare /absolute/fresh/scratch /absolute/source/checkout
```

The scratch directory must not exist. Keep it outside Git repositories and
native manager/agent homes, in the orchestrator's authorized writable area. All
fixture data, ephemeral keys, Curator state, project output and logs stay below
scratch. Preserve this directory at the same path until verification finishes.
Existing directories are refused; there is no reset or cleanup command.

Optional `--curator /absolute/path/to/curator` and `--go /absolute/path/to/go`
select trusted installed tools. Otherwise Curator is discovered on the caller's
PATH and Go on the fixed system tool path. Go version managers' shims are not
used. Tool paths are resolved before invoking tools with an empty-environment
allowlist. Nothing else from the caller's environment is passed to Curator,
memory, Git, or either agent environment.

`prepare` copies the package inputs (`SKILL.md`, `agent-skill.json`, `go/`) into
scratch, then runs `skill check`, scratch `bootstrap`, `project resolve`, and
project-local `install`. It never calls `profile` or `use`, or examines a native
Curator/agent home. HOME, XDG paths, TMPDIR and Go caches are scratch paths;
`CURATOR_*`, `CODEX_HOME`, `CLAUDE_CONFIG_DIR`, caller Git configuration, metadata,
keys and sockets are absent. Git allows only local file transport; SSH transport
is disabled. Fixture SSH keys sign fixture commits only. They are independent
of the memory record keys and of any host signing identity.

Each memory clone is pre-created with its own external `git-store` metadata.
The env files set **new fixture-specific** `GIT_DIR` and `GIT_WORK_TREE`; they do
not preserve the caller's values. Normal CLI `spaces init/add` adopts these
existing worktrees, then verifies/syncs them normally. No `.git` entry is created.
All Git commands in an agent environment target that agent's memory clone;
do not use the environment to operate on an unrelated repository.

The JSON printed to stdout is also saved as `scratch/summary.json`. It includes:

- `project`: working directory to use for both agent runs;
- `installed`: Curator shim, artifact, receipt, skill and Codex adapter paths and
  SHA-256 digests, verified against the install marker;
- `space`, `genesis_digest`, `genesis_commit`, `prepared_head`, local bare remote;
- owner/A/B public memory identities and keys, memory homes, and A/B clone paths;
- `agent-A.env`, `agent-B.env`: sourceable environment files containing paths,
  synthetic Git identities and explicit Git signing configuration; no key bytes.

`owner.env` and the JSON environment files support the harness. Keep the entire
scratch private: it contains **ephemeral private keys**. Do not attach scratch
archives, key files or environment dumps to a public issue. Evidence JSON logs
contain synthetic fixture inputs, commands, public keys and results.

## Project discovery and installation evidence

Curator's [manager profile §3 and §5](https://github.com/relux-works/curator-spec/blob/e41f96387287f5e76604627f9e63662f7d6d86d4/profiles/manager.md)
specifies `.agents/skills/<name>`, `.agents/bin`, and the `.codex/skills` adapter.
The [source extension](https://github.com/relux-works/curator-spec/blob/e41f96387287f5e76604627f9e63662f7d6d86d4/protocol/skillfile-sources.md)
defines project-local Skillfile schema-2 installs. The harness checks that the
Curator-created Codex adapter exposes the same `SKILL.md` as the installed skill.
[Codex's local skill discovery documentation](https://learn.chatgpt.com/docs/build-skills#where-codex-loads-local-skills)
also specifies `.agents/skills` at the working directory and its repository
ancestors. Starting in `scratch/project` therefore exposes the installed skill
directly, including on versions using the Curator-created compatibility adapter.
No shell activation or global installation is required. This verifies the
filesystem surfaces; it does not claim an agent discovery probe was run.

The original Curator shim is first on PATH. It targets the marker/receipt-bound
compiled artifact; neither the shim nor the binary is wrapped or replaced.
Prepare and verify record and recheck their digests, and verifier commands invoke
that absolute shim path. This proves which executable the harness invoked.
**State cannot attest which executable a past agent invoked.** For the actual
agent gate, the orchestrator must retain its launcher/tool transcript showing
`command -v memory` and the absolute shim invocation. The verifier's JSON states
this limit explicitly; a passing verdict alone is not agent execution attestation.

## Launch recipe (orchestrator only)

Choose a fresh fixture, not a self-test fixture. Set the following shell variables
in the orchestrator shell; these are examples, not values embedded in env files:

```sh
scratch=/absolute/fresh/scratch
codex_bin=/absolute/path/to/codex
```

Create two non-sensitive prompt files in scratch. A's prompt should explicitly
invoke `$memory`, resolve `command -v memory`, and call the resulting absolute
Curator shim. Ask A to sync, record exactly one documentary decision observation
whose content includes both a unique topic and the expected decision text, and
attach a real runtime/session/message locator and a short safe session excerpt
using `--source-session` and `--source-text`. B's prompt should invoke `$memory`,
resolve and call the same absolute shim, sync, recall the topic with `--json`,
and report the returned decision and source refs. B must not write any records.
Both identities have writer and reader grants so B's restraint is observable.

The current CLI cannot admit a receipt-backed authoritative `decision_record`.
Use `add assertion --content 'Decision: TOPIC ...'` with session source flags,
as in the stage-3 gate. This is a documentary observation with `statement_kind:
fact`, not authority to act. Reader source evidence is exact `id@version` refs;
the CLI does not disclose session excerpts/locators to readers. See the
[CLI limitations](../../docs/cli.md#limitations) and the
[existing scenario](../../go/e2e/phase_b_test.go).

Launch A, wait for completion, then B. The following command is a complete
isolated environment/cwd recipe; only the orchestrator executes it:

```sh
/usr/bin/env -i /bin/sh -c '
  . "$1"
  cd "$2/project" || exit
  exec "$3" exec --skip-git-repo-check --sandbox workspace-write --add-dir "$2" -
' sh "$scratch/agent-A.env" "$scratch" "$codex_bin" \
  < "$scratch/agent-A.prompt.md" > "$scratch/evidence/agent-A.transcript" 2>&1

/usr/bin/env -i /bin/sh -c '
  . "$1"
  cd "$2/project" || exit
  exec "$3" exec --skip-git-repo-check --sandbox workspace-write --add-dir "$2" -
' sh "$scratch/agent-B.env" "$scratch" "$codex_bin" \
  < "$scratch/agent-B.prompt.md" > "$scratch/evidence/agent-B.transcript" 2>&1
```

Do not source these files into an already populated shell: use `env -i` as
shown. The project deliberately has no `.git`; Codex's repository guard needs
`--skip-git-repo-check`. `--add-dir` permits the runtime's workspace sandbox to
access fixture memory homes beside the project. Other runtime restrictions
still apply. The harness provisions **no agent authentication** and does not
copy/link native credentials. The orchestrator must supply its already authorized
authenticated runtime through its established launch channel; if that channel
requires extra authentication setup, resolve it there before running the agent.
Do not export credentials from a native home to make this example work.

Retain each agent's transcript, exit code, resolved command path and read result.
An agent's exit 0 is not the verifier verdict. The harness does not parse or
trust agent prose as instructions.

## Verify

After both runs, invoke from any directory:

```sh
/absolute/source/checkout/.scripts/stage4-gate/verify \
  "$scratch" 'unique-topic' 'expected decision text'
```

Exit 0 and JSON `verdict: pass` require:

- unchanged Curator context, adapter, marker, receipt, shim and artifact;
- clean checks for A and B at the current remote head;
- B's topic recall with `--require-current` returning exactly one current item,
  issued/submitted by A, containing the case-sensitive expected text and valid
  nonempty source refs;
- a corresponding record signed by A's registered memory key, with source refs
  resolving to A-signed source records, and every history commit signed;
- no B-key, B-issuer or B-submitter record anywhere in the space history.

The commands use the installed shim and the saved fixture environments; ambient
Git/Curator/agent variables are ignored. Reads/checks synchronize local verified
state, but the verifier does not create records or push. JSON includes recall,
check, history and installation evidence. Normal verification failures return
exit 1 with a specific `reason`; setup/command failures return a failed verdict,
not a skipped check. CLI outputs and exit codes are in `scratch/evidence/`.
The fixture summary and saved env/installation metadata are trusted verifier
inputs, not an adversarial attestation service.

## Self-test and negative controls

```sh
.scripts/stage4-gate/self-test /absolute/another-fresh/scratch /absolute/source/checkout
```

This invokes `prepare`, uses its installed binary to let A add a source-linked
decision and B sync/recall, then runs `verify`. It requires these exact results:

| Control | Exit | Reason |
| --- | ---: | --- |
| A writes, B reads | 0 | pass |
| Wrong expected decision text | 1 | `decision_text_mismatch` |
| Changed Curator shim | 1 | `installation_changed` |
| Restored original shim | 0 | pass |
| B writes an unrelated valid record | 1 | `b_wrote_record` |

It also plants ambient Curator/agent/Git settings and checks their exclusion,
and checks the sourceable env files against the JSON environments used by the
harness. It checks that the fixture contains no `.git` entry. It writes
`evidence/self-test.json` and per-control verifier results.
The final fixture deliberately contains B's negative-control write. Prepare a
new fixture for real agents. No agent runs, network remote, server, global
configuration changes or host signing keys are involved in the self-test.
