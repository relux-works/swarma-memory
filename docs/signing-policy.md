# Signing and space policy

The signing and policy-verification primitives operate on full in-memory records
and adapter-supplied `io/fs` filesystems. The separate [git adapter](git-spaces.md)
provides transport and history integration; these primitives discover no host
agent, CLI configuration or key holder.
`go/sign/localkey` generates temporary Ed25519 identity keys and provides explicit
private-file persistence. Tests generate their own ephemeral keys only.

## Record signatures

`sign.Signer.Sign(sign.CanonicalRecord)` receives the entire validated record.
`sign.NewCanonicalRecord(value, schemas, domains)` checks the closed stored-record
schema, positive versions and exact assertion domain content through the kernel.
The immutable result returns detached bytes/values; its zero value cannot be
signed. Both signing backends refuse a submitter different from its own identity with
`submitter_mismatch`. Issuer and subject remain distinct roles and confer no
signing identity. The signature includes every stored envelope field, including
submitter, admission class and recorded position. Admission/stamping happens
before this stored representation is signed; signing grants no admission right.

The wire envelope is exactly:

```json
{"record": {}, "signature": {"purpose": "swarma-memory-record/1", "key": "<key-id>", "alg": "ed25519", "value": "<base64>"}}
```

`record` here stands for a complete kernel record, not an empty object.
The closed schema is [signed-record.schema.json](../go/sign/schema/signed-record.schema.json);
its five record branches reference the existing kernel schema URIs. Base64
length/canonical spelling and cryptographic checks are enforced by verification.
`sign.ParseRecord` uses strict kernel JSON parsing: duplicate/unknown fields,
non-integral numbers, invalid Unicode and malformed shapes are rejected.

All six signature purposes use the same explicit framing:

```text
UTF-8(purpose) || 0x00 || kernel.CanonicalJSON(payload)
```

The tags are `swarma-memory-record/1`, `swarma-memory-policy/1` and
`swarma-memory-key-registration/1`, plus `swarma-memory-write/1` for the
[git adapter's authenticated transaction metadata](git-spaces.md#authenticated-admission-metadata),
and `swarma-memory-space-advertisement/1` and `swarma-memory-directory/1` for
[target advertisements and platform publications](git-spaces.md#platform-directory).
`signature` itself is outside its signed payload. Changing or retagging a signature cannot cross these domains. Values
are Ed25519 signatures encoded in canonical padded standard base64. Key IDs are
`ed25519:sha256:` followed by lowercase hex SHA-256 of the raw 32-byte public key
(no JSON, purpose prefix or base64 in that digest). Public keys are also encoded
in canonical padded standard base64.

A typical record round trip is:

```go
record, err := sign.NewCanonicalRecord(value, schemas, domains)
// Handle err before continuing.
signature, err := identityKey.Sign(record)
wire, err := json.Marshal(sign.SignedRecord{Record: record, Signature: signature})
parsed, err := sign.ParseRecord(wire, schemas, domains)
verified, err := historicalPolicy.VerifyRecord(parsed, schemas, domains)
// verified.Bytes() equals record.Bytes() on success.
```

Every error must be handled; the sketch omits repeated handling for readability.
Inputs to the value APIs use the kernel's acyclic decoded JSON tree types.

## Signed space.json

`space.SignedPolicy` serializes as `{"policy": <Policy>, "signature": <Signature>}`.
The policy signature covers only the full canonical `policy` object under the
policy purpose. The payload retains all architecture §5.3 fields:

| Field | Representation |
| --- | --- |
| `space_id`, `kind` | Nonempty identity; `agent`, `project` or `platform` |
| `owners` | Nonempty unique identity list |
| `writers` | Grants with `identity`, `admission_classes`, `schemas`, `kinds` |
| `readers` | Entries with `identity` and `spaces`; identity `public` denotes open access in unqualified legacy policies |
| `keys` | Owner-signed registration envelopes described below |
| `schemas` | Exact domain `{id, version}` references |
| `ceiling` | Exactly `non-sensitive` for git spaces |
| `limits` | Positive `max_record_bytes`, `max_field_bytes` |
| `resolvers` | V2 entries with unique `area`, closed `match:{schemas,subjects}` and sorted nonempty unique `identities`; see [routing rules](cli.md#exact-conflict-checks-and-resolver-policy) |
| `retention` | `on_owner_retire`, `on_owner_revoke`, each `retain` or `deny` |

Current payloads include `format: "swarma-memory-policy/2"`; the signature
purpose remains `swarma-memory-policy/1`. Legacy payloads omit the discriminator
and resolver match fields; their canonical signature bytes remain unchanged.
New owner transitions upgrade legacy entries to one catch-all union. V2 validates
exact-match overlap and registered reader/writer resolver qualification at both
signing and verification.

The payload additionally has `version` (positive integer), `previous` (prior
policy digest or null) and `author` (the signing owner identity). Empty arrays
are encoded as `[]`, not null. All custom schemas are closed and live under
[space/schema](../go/space/schema), outside `spec/`.

Writer grants have no wildcards. A record must match identity, admission class,
schema and kind within one complete grant. A schema selector of `null` explicitly
covers non-assertion records, whose kernel schema field is null. A grant's exact
non-null refs must also appear in `schemas`. Lists cannot mix different grants'
selectors to assemble authority. Record space must equal policy space.

A `keys` entry is `{"registration": <Registration>, "signature": <Signature>}`.
The registration payload binds `space_id`, `policy_version`, `author`, `identity`,
`key`, `alg` and `public_key`. Its distinct-purpose signature is required even
when the policy itself has a valid signature. Keys must match their derived IDs;
duplicate IDs, including use across identities, are rejected. Each policy owner
must have a registered key. Writers without a registered key cannot verify.
`NewCanonicalRegistration` and `NewCanonicalPolicy` create immutable full signing
requests; `space.PolicySigner` exposes the typed methods implemented by both backends.
These methods also require the signing identity to equal the payload's author.

## Policy history and trust anchor

`space.VerifyChain(chain, trustedGenesisDigest)` returns no partial chain on any
failure. The caller must obtain the genesis digest through a trusted external
channel; self-signing by an arbitrary key is insufficient to identify a space.
The digest is `sha256:` plus lowercase hex SHA-256 of the framed canonical policy
payload, using the policy purpose above. It excludes the outer signature.

Genesis is version 1 with null `previous`, signed by one of its own listed
owners. Its key registrations must be signed by listed owners using keys in
that pinned genesis payload. One owner signature suffices; no threshold scheme
is inferred. Each subsequent version must:

- increment the version by exactly one, preserve space ID and kind, and name the
  exact previous verified policy digest;
- be signed by an owner, with a key registered in that **previous** policy;
- have every key registration bound to the new space/version and endorsed by
  an owner/key from the previous policy.

Thus registrations are re-endorsed for every policy version. The previous owner
can register a new owner's key while transferring ownership; that new owner can
sign the following transition. Merely declaring oneself an owner in a proposed
policy cannot authorize it. Earlier records continue to verify against their
historical keys after rotation, rather than the latest registry.

`VerifiedPolicy` stores detached policy/key data and exposes copies. A record's
in-force policy is an explicit trusted input from its admission/history position.
It is never selected by the untrusted record's timestamp or latest-policy guess.
The exact record/signature envelope has no policy-version extension. The
[git adapter](git-spaces.md) now derives authentic history positioning from
first-parent replay and maintains external anti-rollback cursors.

## Verification and kernel integration

`VerifiedPolicy.VerifyRecord` implements architecture §6.3 rules 1–3:

1. Require the record purpose and a registered key for the exact submitter;
   verify the signature over the complete immutable canonical record.
2. Require the correct space, an accepted exact assertion schema, and kernel
   closed-schema/domain-content validation using the supplied trusted registry.
3. Require one complete submitter writer grant for class/schema/kind.

It also checks configured byte limits and rejects explicit or populated
domain-declared sensitive fields. Record size counts canonical record bytes;
field size counts canonical body string leaves and complete `content[].value`
values, including arrays. These checks do not scan for undeclared secrets.
The git adapter enforces readers in addition to kernel grants. Resolver metadata
routes read-only escalation packets and grants no authority; owner
retirement/revocation actions remain metadata for later integration.

`space.NewSnapshot(template, []space.RecordAtPolicy, schemas, mint)` verifies every
record under its explicitly bound verified policy, then calls `kernel.NewState`.
The caller supplies an empty records array and trusted complete kernel intake,
registry, policy and runtime metadata in the template. Unsigned template records,
invalid signatures and invalid complete snapshots return no state. It never
invents lineage facts, reviews, grants or transaction positions. The caller must
supply authentic domain definitions, not only matching schema IDs.

This is a stored-snapshot trust adapter, not an admission replay or a git write
path. Rules 4 and 5 (revision authority and expected version), retention and all
other semantic admission checks remain with `State.Write`. Signatures cannot
make unadmitted records admitted. The git history adapter reconstructs accepted
transactions using an independently trusted template. Individual verification
errors can be collected by that reader; the snapshot adapter fails the whole batch
rather than publishing a partial state with broken references.

## Diagnostics and key files

Trust failures are `*sign.Diagnostic` with a typed `Code` and public `Field`;
callers can use `errors.As`. They are distinct from kernel refusal values.
Important codes include `invalid_signature`, `purpose_mismatch`, `wrong_key`
(registered for a different identity or inconsistent public-key ID),
`unregistered_key`, `unsigned_registration`, `unauthorized_owner`,
`policy_sequence`, `policy_anchor`, `grant_mismatch`, `schema_not_accepted`,
`sensitivity_ceiling` and `invalid_snapshot`. Rejected payloads and private key
material are never included in diagnostics. A valid signature under an unknown
key still fails registry membership.

`localkey.Generate(identity)` uses `crypto/rand` and stdlib Ed25519.
`key.Save(path)` creates a new regular file exclusively with mode 0600, refuses
existing files/symlinks, syncs it, and removes its own incomplete file on failure.
The file holds only `identity`, `alg: "ed25519"` and a base64 32-byte private seed.
`localkey.Load(fs, name)` reads that explicit file only, checks regular-file type
and exact mode 0600, bounds reading to 4097 bytes and rejects malformed or
oversized input. It never discovers ambient keys. Key formatting redacts secrets.

The caller must provide private trusted parent directories and filesystem
behavior; the `io/fs` adapter is not a hostile-filesystem sandbox or a key holder.
Temporary keys still have the architecture's prompt-injection/home-loss risks.
No test reads host keys, SSH agents or credentials.

## SSH-agent backend and key rotation

`go/sign/sshagent` implements the same six typed signer interfaces as localkey;
they share canonical author/purpose checks. It holds only public configuration
and signs the complete `sign.Frame(purpose, canonical)` through an explicit Unix
socket. The [RFC 9987 agent protocol](https://www.rfc-editor.org/rfc/rfc9987.html)
uses messages 11/12 (identities), 13/14 (signing, flags 0) and 5 (FAILURE).
Frames (including the four-byte length header) are bounded to 256 KiB before allocation; parsers require complete SSH
strings and consume the exact payload, including nested signature blobs.
The [RFC 8709 Ed25519 encoding](https://www.rfc-editor.org/rfc/rfc8709.html)
contains the algorithm string and the 64 raw signature bytes. The backend
performs `ed25519.Verify` against the configured raw public key before returning
any signature. The stored signature, key ID, purposes and verifier are unchanged.
No private material passes into memory, and normal key formatting is redacted.
See [CLI configuration and errors](cli.md#explicit-ssh-agent).

**Use a dedicated memory identity key**, separate from SSH login and Git signing.
Domain separation prevents a memory signature being retagged as another memory
purpose. It does not stop a compromised client of an unrestricted SSH agent from
asking for arbitrary other bytes. Agent approval/access policy and key separation
remain necessary; an explicit endpoint and local self-check do not authenticate
the agent process or constrain other clients of that process. Neither tests nor
runtime discover or read host keys or ambient sockets.

To rotate an existing space without changing its trust anchor:

1. Initialize a separate agent home with the **same owner identity** and the new
   dedicated public key using `keys init --ssh-agent ... --public-key ...`.
2. Read its raw `public_key` from `keys show`. From the current file-key owner
   home, run `keys register --space SPACE --identity OWNER --public-key BASE64`.
   This commits an endorsement of the agent key by the preceding owner key.
3. From the agent home, run `spaces add SPACE --remote URL --genesis ORIGINAL_PIN`
   with the original genesis digest. Verify before making changes.
4. Make the next policy change from that home, for example `policy grant`.
   The new key signs the next version; existing readers retain the same genesis
   and verify historical file-key and subsequent agent-key signatures.

There is **no key removal command** yet: the previous key remains registered.
Rotation adds a key; it does not revoke the old key or retire an owner. P-256 and
key removal are separate open tasks. Do not edit signed history to simulate them.
Tests include a Unix fake agent and a bounded foreground `ssh-agent -D` with
an ephemeral key. Cleanup reaps its exact PID and closes every owned listener;
no test uses the user's `SSH_AUTH_SOCK`, `~/.ssh` or host signing agent.

## Architecture choices and validation

Architecture §5.3 leaves grant, chain metadata, endorsement encoding and retention
values open. This implementation makes the choices above explicit, including
per-version endorsement by the authorizing previous owners. Architecture §6.1
leaves framing open; the NUL separator is fixed here. Sections §5.3/§6.3 do not
specify genesis authentication or policy-position transport; an explicit pinned
genesis digest and trusted historical binding are mandatory inputs here.
Threshold approval and operational retirement/revocation behavior remain design
questions for their owning tasks; this layer does not silently choose actions.

`go -C go test ./...` covers all required forgery, replay, registry, owner-chain, grant,
submitter and canonical round-trip cases with real ephemeral keys and valid
controls. It also covers key persistence/permissions, owner transfer/key rotation,
non-assertion grants, closed-schema violation controls, immutable results and
fail-closed snapshot integration. Independent stdlib signing checks the framing.
Use `go -C go test -race ./...`, `go -C go vet ./...`, `python3 -B spec/checks/validate.py` and
`go -C go run ./cmd/memory conformance` for the full gates. Optional logs belong in
ignored `.temp/`; no key material belongs in documentation or outcome resources.

## Directory signatures and owner namespaces

`SignedAdvertisement` is `{advertisement, signature}` and `SignedDirectory` is
`{entry, signature}`. Their closed adapter schemas live in `go/space/schema`.
`NewCanonicalAdvertisement` and `NewCanonicalDirectory` make detached typed
requests; `localkey.SignAdvertisement`/`SignDirectory` require their own author's
identity and reject zero requests. Neither method signs arbitrary hashes.
Directory payload digests use SHA-256 of the directory-purpose framed canonical
entry, including its nested signed advertisement; `previous` points to that
payload digest, not to Git or the outer signature.

Replay verifies the publication with the platform owners/registered keys in
force on the accepted first-parent line. Merely being a platform writer is
insufficient (`directory_unauthorized`). Purposes are checked before schema or
cryptography, including the nested advertisement (`purpose_mismatch`). Its
cryptographic signature is checked on use against the target's verified policy
at the exact observed version/digest. A current publisher must still be a current
owner; removal makes new discovery stale, without retroactively invalidating the
historical publication or independently pinned target access.

Genesis owners establish the immutable owner namespace (`<owner>/<id>`). Owners
cannot span namespaces (`mixed_owner_namespace`). Registrations and grants in a
qualified space must be qualified (`identity_owner_mismatch`); foreign qualified
readers and registrations are allowed, foreign writers are not
(`cross_owner_writer`). A raw public key asserts no provenance. Only the local
owner's signed registration attests its identity; v1 cannot identify falsely
attributed key bytes. Wholly unqualified single-owner legacy policies stay
unqualified; qualified and legacy identities cannot be mixed. Cross-owner
promotion refuses `cross_owner_promotion`; no forward-right mechanism exists yet.
