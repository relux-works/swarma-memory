# Write scanner locator rules

The offline write scanner checks both proposed records and persisted intake
metadata (including context and idempotency keys), before signing. It also checks
object keys. A finding is a heuristic refusal, not a provider-validity check;
passing does not prove that data contains no secrets. See the
[scanner overview](../README.md#write-scan) for thresholds, limits and redaction.

## Artifact-source locator roles

The additional entropy exemptions below apply only to string values at exactly
`/body/object`, `/body/revision` and `/body/origin` of a root record whose
`envelope.kind` is `source` and `body.source_kind` is `artifact`. They do not apply
to arbitrary fields with those names, object keys, excerpts or an entire body.
The scanner does not require a fully valid record to inspect it; the kernel and
adapter still validate record shape and authority independently.

Each of these three fields may contain exactly one of these locator atoms:

| Kind | Closed shape |
| --- | --- |
| Matrix event | `$` followed by exactly 43 ASCII base64url characters (`A-Z`, `a-z`, `0-9`, `_`, `-`), without padding |
| Matrix room | `!` followed by a nonempty base64url localpart, `:`, and a server; at most 255 bytes overall |
| Commit | Exactly 40 or 64 lowercase hexadecimal characters |
| SHA-256 digest | Exactly `sha256:` followed by 64 lowercase hexadecimal characters |
| Session/message UUID | Exactly `8-4-4-4-12` hexadecimal characters, case insensitive |

A room server is an ASCII hostname (nonempty labels of at most 63 alphanumeric
or hyphen characters, without leading/trailing hyphens; total at most 253 bytes),
or a bracketed IPv6 address, optionally followed by `:` and a decimal port from
1 through 65535 with at most five digits. Dotted IPv4 addresses fit the hostname
shape. Trailing dots, paths, IPv6 zone IDs and unbracketed IPv6 are outside this
conservative subset. This is an exemption grammar, not a complete Matrix ID
validator; other forms, including domainless room IDs, receive ordinary scanning.

`/body/revision` may also be exactly `message:` plus one locator atom, or `index:`
plus an unsigned decimal integer representable in 64 bits (at most 20 digits).
There is no substring exemption and no trimming of whitespace or suffixes.

## CLI session origins

`--source-session` builds a source with `owner: runtime:<runtime>`,
`object: session:<session>`, a message/index revision, and an `origin` string
containing canonical JSON with exactly three string keys: `runtime`, `session`
and `message`. Add, assess and enabled attributed replace/correct share this
session-input and source-scanning path. This structured origin and its `session:`
object receive an entropy exemption only when all components match one of these forms:

- `matrix:<room>:<event>` with the exact room/event grammars above. The final
  `:$` separates the event; a room server and port remain part of the session.
- `codex:<uuid>:<message>` or `claude-code:<uuid>:<message>`. The message is a UUID,
  `message:<uuid>`, unsigned decimal index, or `index:<unsigned decimal index>`.
  UUID and index grammars are as above.

The origin must be byte-for-byte canonical JSON, without duplicate or additional
keys. Its owner, object and revision must agree with its components. Explicit
`message:`/`index:` prefixes survive; a bare decimal becomes `index:<n>` and a
bare UUID or Matrix event becomes `message:<id>`. A wrong role, inconsistent
component, malformed JSON or noncanonical representation receives ordinary
scanning. An unsupported CLI locator retains the legacy first-two-colons split
and ordinary scanner behavior, rather than gaining an exemption.

This changes neither the record format nor the meaning of provenance. Session
sources remain reported, unavailable documentary references with exact retained
excerpt bytes and a `sha256-bytes-v1` digest; they are not live-resolved sources.
Other CLI locator flags are unchanged: `--sources` names signed record refs,
assessment `--origin` is free-form text, and promotion target origins retain
their existing record-reference shape.

## Checks that remain active

These are **entropy-only** exemptions. Every known-format detector and every size
limit still runs. In an entropy-exempt string, known-token patterns also match
without identifier boundaries: prefixing/suffixing a token inside a valid room
localpart cannot hide it. JWT checks also search bounded DNS-label header starts
and retain a valid signature prefix when an adjoining character invalidates its
base64 length; the room grammar bounds each label to 63 bytes. Nonmatching values receive the original scanning rules;
malformed syntax alone does not guarantee a secret finding.

`--content` and `--source-text` gain no Matrix, commit or digest atom exemption.
Full high-entropy IDs there can still be refused, even beside a valid locator.
Keep exact coordinates in locator fields and retain only non-sensitive excerpts.
For these locator kinds we choose strict free text: syntax cannot distinguish an
arbitrary 40-hex or 43-base64url secret from an identifier, so a general
delimited-token exception would create a secret channel. A locator exemption
likewise recognizes a declared role and syntax, not the absence of a secret;
never use it to store credentials.

## Task-ID boundaries in engineering text

Entropy candidates normally join ASCII words containing `/`, `-` and `_`.
A compound of short engineering words and identifiers can therefore reach the
32-byte minimum and 4.5-bit threshold even when each component is short. A Go
pseudoversion such as `v0.0.0-20260102030405-123456abcdef` is not such a trigger
on its own: its dots split it, leaving a longest candidate of 29 bytes. Short
7–12-hex SHAs, PR numbers and eight-character event prefixes are likewise below
the minimum when separated normally.

In string **values**, a whole slash-delimited segment matching exactly
`TASK-[0-9]{6}-[a-z0-9]{6}` is an entropy token boundary. This closed 18-byte
syntax recognizes no authority and consults no board. After removing only those
segments from the candidate, every remaining contiguous slash-joined run is
checked, as is each individual non-task segment. If any remaining run reaches
32 bytes, the **original combined candidate is checked too**, so removing the
ID cannot lower a long possible secret's entropy below the threshold. Only when
all remaining runs are shorter than 32 can the original combined candidate be
discarded. No whitespace, prefix, suffix, case or alphabet near miss qualifies.
Keys retain their original tokenization, and named-token/size checks always see
the complete original value. This applies equally to content, excerpts and
metadata values.

For example, `scan_refused3/TASK-123456-ghijkl` passes without granting an
exception to arbitrary hex or base64 tokens. A 32-byte base64url token cannot
cross a slash; a canonical standard-base64 token cannot cross the hyphens in a
task-ID segment. Any such long token is therefore in a remaining run of at least
32 bytes, retaining the original checks as well as the residual checks. A long
secret alone, joined to an ordinary word, or beside a valid task ID still
refuses when it meets the detector thresholds. Slashes inside other base64
candidates are preserved, not generally split. Other long prose compounds can
still trigger the original heuristic; there is no general path or word exemption.

Complete UUID candidates already bypassed entropy checks before this change,
including in idempotency metadata. UUID keys therefore need no additional
exception. Composite session/message keys are still scanned as ordinary text;
a short readable retry key is convenient. Existing exact digest/handle exemptions
remain unchanged, including support for scanning standalone digest bodies.

Run `go -C go test -count=1 ./scan` for exact forms, near misses, named-token
lookalikes, role/coherence, free-text and size controls. Run
`go -C go test -count=1 -timeout=30m ./cmd/memory -run 'TestWrite(MatrixSessionLocator|LocatorRefusals)$'`
for actual signed CLI intake, unchanged refusal state and separate-reader replay.
Fixtures use synthetic identifiers and secrets only.
