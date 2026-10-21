package e2e_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const stage5AlphaID = "record:stage5-decision"
const stage5BetaID = "record:stage5-assumption"
const stage5Decision = "Decision: retain the original source when sharing memory"
const stage5Assumption = "Assumption: reciprocal sharing remains read-only"
const stage5Excerpt = "Keep the original decision locator: café, Հայերեն.\nThe second owner must see this exact excerpt.\n"

// Stage 5: two owner namespaces share populated projects through their own
// pinned platforms. Discovery supplies no read/write authority, preserves source
// attribution, and recovers each own-project pin after identity-key replacement.
// File remotes cannot prove a hosting ACL; the README records that boundary.
func TestStage5TwoOwners(t *testing.T) {
	t.Parallel()
	s := newStage5(t)
	// Each agent starts with only its own platform pin. Even its own project
	// genesis is learned through the directory, never manually supplied.
	s.discover(s.a, s.alpha, s.platform1)
	s.discover(s.b, s.beta, s.platform2)
	writeResult(t, s.a.start(stage5Excerpt, "add", "assertion", "--space", s.alpha.id, "--id", stage5AlphaID, "--content", stage5Decision, "--source-session", "runtime:stage5:message:decision", "--source-text", "-", "--idempotency-key", "stage5:decision", "--at", intakeTime).finish(0), stage5AlphaID, 1, 3)
	writeResult(t, add(s.b, s.beta, stage5BetaID, stage5Assumption), stage5BetaID, 1, 1)
	s.discover(s.b, s.alpha, s.platform2)
	s.discover(s.a, s.beta, s.platform1)
	// These stable, populated records also detect a reader instrument that
	// returns an empty success instead of enforcing the target policy.
	s.step(t, "listed-but-ungranted", func(t *testing.T) {
		// Both foreign keys are registered and advertisements valid, but neither
		// foreign reader grant exists. Listing must not expose items or sources.
		s.noRead(s.b, s.alpha, "listed-but-ungranted")
		s.noRead(s.a, s.beta, "listed-but-ungranted")
		s.assertProject(s.a, s.alpha, stage5AlphaID, stage5Decision, s.a.identity, true)
		s.assertProject(s.b, s.beta, stage5BetaID, stage5Assumption, s.b.identity, false)
	})
	for _, row := range []struct {
		owner, reader *agent
		p             project
	}{{s.owner, s.b, s.alpha}, {s.other, s.a, s.beta}} {
		row.owner.run(0, "policy", "grant", "--space", row.p.id, "--identity", row.reader.identity, "--role", "reader")
	}
	s.step(t, "reciprocal-source-reads", func(t *testing.T) {
		// The foreign reads retain exact content, issuer, source locator/digest,
		// multiline excerpt and unavailable state in recall and explain.
		s.assertProject(s.b, s.alpha, stage5AlphaID, stage5Decision, s.a.identity, true)
		s.assertProject(s.a, s.beta, stage5BetaID, stage5Assumption, s.b.identity, false)
	})
	s.step(t, "revoke-and-regrant", func(t *testing.T) {
		// Revocation with an active listing returns no data while the own reader
		// retains the populated decision; a signed regrant restores all sources.
		s.owner.run(0, "policy", "revoke", "--space", s.alpha.id, "--identity", s.b.identity, "--role", "reader")
		listing := object(t, s.b.run(0, "directory", "show", "--space", s.platform2.id, "--space-id", s.alpha.id).Data, "entry", "diagnostics")
		listed := object(t, listing["entry"], "entry", "signature", "state", "digest")
		entry := object(t, listed["entry"], "format", "directory_space", "space_id", "version", "previous", "status", "advertisement", "author")
		if text(t, entry["status"]) != "active" || text(t, entry["space_id"]) != s.alpha.id {
			t.Fatal("revocation changed the active directory listing")
		}
		s.noRead(s.b, s.alpha, "revoked-reader")
		s.assertProject(s.a, s.alpha, stage5AlphaID, stage5Decision, s.a.identity, true)
		s.owner.run(0, "policy", "grant", "--space", s.alpha.id, "--identity", s.b.identity, "--role", "reader")
		s.assertProject(s.b, s.alpha, stage5AlphaID, stage5Decision, s.a.identity, true)
	})
	s.step(t, "cross-owner-writes-and-promotion", func(t *testing.T) {
		// A foreign reader cannot acquire a writer grant, directly write, or
		// promote into its own project. Config and publication state stay fixed.
		s.owner.run(0, "sync", "--space", s.alpha.id)
		before, config := s.state(s.owner, s.alpha), s.configBytes(s.owner)
		refused(t, s.owner.run(3, "policy", "grant", "--space", s.alpha.id, "--identity", s.b.identity, "--role", "writer"), "cross_owner_writer")
		s.sameState(s.owner, s.alpha, before)
		s.sameConfig(s.owner, config)
		s.b.run(0, "sync", "--space", s.alpha.id)
		before, config = s.state(s.b, s.alpha), s.configBytes(s.b)
		refused(t, s.b.run(3, "add", "assertion", "--space", s.alpha.id, "--id", "record:foreign-write", "--content", "Forbidden guest write", "--idempotency-key", "deny:foreign-write", "--at", intakeTime), "not_authorized")
		s.sameState(s.b, s.alpha, before)
		s.sameConfig(s.b, config)
		s.b.run(0, "sync", "--space", s.beta.id)
		before, config = s.state(s.b, s.beta), s.configBytes(s.b)
		refused(t, s.b.run(3, "promote", stage5AlphaID, "--space", s.alpha.id, "--to", s.beta.id, "--id", "record:foreign-promotion", "--idempotency-key", "deny:foreign-promotion", "--at", intakeTime), "cross_owner_promotion")
		s.sameState(s.b, s.beta, before)
		s.sameConfig(s.b, config)
		s.assertProject(s.b, s.beta, stage5BetaID, stage5Assumption, s.b.identity, false)
		s.assertProject(s.b, s.alpha, stage5AlphaID, stage5Decision, s.a.identity, true)
	})
	c := s.newPrincipal("third-agent", "o2/agent:c1")
	s.register(s.other, c, s.platform2)
	s.other.run(0, "policy", "grant", "--space", s.platform2.id, "--identity", c.identity, "--role", "reader")
	s.pin(c, s.platform2, "platform")
	s.step(t, "tampered-advertisement-and-third-identity", func(t *testing.T) {
		// A wrong genesis cannot configure any target clone/cache. Restoring the
		// adjacent valid ad permits discovery, but c1 still lacks a reader grant.
		ad, err := os.ReadFile(s.alphaAd)
		if err != nil {
			t.Fatal(err)
		}
		var value map[string]any
		if err := json.Unmarshal(ad, &value); err != nil {
			t.Fatal(err)
		}
		value["advertisement"].(map[string]any)["genesis_digest"] = "sha256:" + string(bytes.Repeat([]byte("0"), 64))
		file := filepath.Join(s.root, "tampered-advertisement.json")
		if err := os.WriteFile(file, mustStage5JSON(t, value), 0600); err != nil {
			t.Fatal(err)
		}
		s.publish(s.other, s.platform2, file)
		before := s.configBytes(c)
		refused(t, c.run(3, "spaces", "add", s.alpha.id, "--from-directory", s.platform2.id), "directory_mismatch")
		s.sameConfig(c, before)
		s.onlyConfigured(c, s.platform2.id)
		s.noTargetState(c, s.alpha)
		s.publish(s.other, s.platform2, s.alphaAd)
		s.discover(c, s.alpha, s.platform2)
		s.noRead(c, s.alpha, "third-identity")
		s.assertProject(s.b, s.alpha, stage5AlphaID, stage5Decision, s.a.identity, true)
	})
	s.step(t, "other-owner-directory-without-pin", func(t *testing.T) {
		// Knowing the other platform's name does not supply its trust pin.
		before := s.configBytes(s.b)
		refused(t, s.b.run(2, "spaces", "add", s.alpha.id, "--from-directory", s.platform1.id), "unknown_space")
		s.sameConfig(s.b, before)
		s.b.run(0, "directory", "show", "--space", s.platform2.id, "--space-id", s.alpha.id)
	})
	// All four spaces have nonempty projected views before the invariance check.
	for _, row := range []struct {
		owner *agent
		p     project
	}{{s.owner, s.platform1}, {s.other, s.platform2}} {
		writeResult(t, add(row.owner, row.p, "record:platform-marker", "Platform marker remains unchanged"), "record:platform-marker", 1, 1)
	}
	s.step(t, "directory-is-not-a-kernel-write", func(t *testing.T) {
		// Republish in both directories: all four populated semantic views stay
		// byte-identical after cursor normalization; project heads do not move.
		rows := []struct {
			owner *agent
			p     project
		}{{s.owner, s.platform1}, {s.other, s.platform2}, {s.owner, s.alpha}, {s.other, s.beta}}
		before := make([][]byte, len(rows))
		for i, row := range rows {
			before[i] = s.semanticView(row.owner, row.p)
		}
		alphaHead := s.owner.git(s.alpha.remote, "rev-parse", "main")
		betaHead := s.other.git(s.beta.remote, "rev-parse", "main")
		s.publish(s.owner, s.platform1, s.betaAd)
		s.publish(s.other, s.platform2, s.alphaAd)
		for i, row := range rows {
			if !bytes.Equal(before[i], s.semanticView(row.owner, row.p)) {
				t.Fatal("directory publication changed a populated kernel view", row.p.id)
			}
		}
		if s.owner.git(s.alpha.remote, "rev-parse", "main") != alphaHead || s.other.git(s.beta.remote, "rev-parse", "main") != betaHead {
			t.Fatal("directory publication changed target history")
		}
	})
	s.step(t, "manual-pin-without-entry", func(t *testing.T) {
		// Neither directory lists either platform. A fresh same-identity home
		// with a target grant reads a populated platform using only a manual pin.
		manual := s.newPrincipal("manual-reader", s.b.identity)
		s.register(s.owner, manual, s.platform1)
		s.owner.run(0, "policy", "grant", "--space", s.platform1.id, "--identity", manual.identity, "--role", "reader")
		for _, row := range []struct {
			owner *agent
			p     project
		}{{s.owner, s.platform1}, {s.other, s.platform2}} {
			refused(t, row.owner.run(3, "directory", "show", "--space", row.p.id, "--space-id", s.platform1.id), "directory_missing")
		}
		s.pin(manual, s.platform1, "platform")
		onlyRecord(t, readItems(t, readAt(manual, "recall", "*", s.platform1.id), s.platform1.id), "record:platform-marker", "Platform marker remains unchanged", s.owner.identity)
		before := s.configBytes(manual)
		refused(t, manual.run(3, "spaces", "add", s.alpha.id, "--from-directory", s.platform1.id), "identity_owner_mismatch")
		s.sameConfig(manual, before)
	})
	s.step(t, "both-home-recoveries", func(t *testing.T) {
		// Wipe each memory home, replace its record-signing key and register the
		// public replacement in its own owner's spaces. Only the platform is
		// manually pinned; the own project and all old content are rediscovered.
		for _, row := range []struct {
			owner, reader *agent
			platform, p   project
			id, value     string
			source        bool
		}{{s.owner, s.a, s.platform1, s.alpha, stage5AlphaID, stage5Decision, true}, {s.other, s.b, s.platform2, s.beta, stage5BetaID, stage5Assumption, false}} {
			oldKey := row.reader.keyID
			if err := os.RemoveAll(row.reader.home); err != nil {
				t.Fatal(err)
			}
			key := object(t, row.reader.run(0, "keys", "init", "--identity", row.reader.identity).Data, "identity", "key_id", "algorithm", "public_key")
			row.reader.keyID, row.reader.publicKey = text(t, key["key_id"]), text(t, key["public_key"])
			if row.reader.keyID == oldKey {
				t.Fatal("recovery reused a lost identity key")
			}
			s.register(row.owner, row.reader, row.platform)
			s.register(row.owner, row.reader, row.p)
			s.pin(row.reader, row.platform, "platform")
			s.onlyConfigured(row.reader, row.platform.id)
			s.discover(row.reader, row.p, row.platform)
			s.onlyConfigured(row.reader, row.platform.id, row.p.id)
			s.assertProject(row.reader, row.p, row.id, row.value, row.reader.identity, row.source)
		}
	})
	s.step(t, "writer-signed-directory-entry", func(t *testing.T) {
		// The legitimate CLI refuses an agent writer's publication without any
		// effects. A raw, cryptographically valid writer-signed entry also fails
		// replay with directory_unauthorized, while the valid project remains usable.
		s.a.run(0, "sync", "--space", s.platform1.id)
		before, config := s.state(s.a, s.platform1), s.configBytes(s.a)
		refused(t, s.a.run(3, "directory", "publish", "--space", s.platform1.id, "--entry", s.alphaAd), "directory_unauthorized")
		s.sameState(s.a, s.platform1, before)
		s.sameConfig(s.a, config)
		s.forgeWriterEntry()
		listed := object(t, s.a.run(0, "directory", "list", "--space", s.platform1.id).Data, "entries", "diagnostics")
		entries := array(t, listed["entries"])
		if len(entries) != 2 {
			t.Fatal("writer entry entered discovery or hid a valid neighbour")
		}
		diagnostics := array(t, listed["diagnostics"])
		if len(diagnostics) != 1 || text(t, object(t, diagnostics[0], "commit", "path", "code")["code"]) != "directory_unauthorized" {
			t.Fatal("writer entry missed the publisher-authority check", string(listed["diagnostics"]))
		}
		refused(t, s.a.run(3, "directory", "show", "--space", s.platform1.id, "--space-id", s.platform1.id), "directory_missing")
		s.sameConfig(s.a, config)
		s.a.run(0, "directory", "show", "--space", s.platform1.id, "--space-id", s.alpha.id)
		s.assertProject(s.a, s.alpha, stage5AlphaID, stage5Decision, s.a.identity, true)
	})
	for _, p := range []project{s.platform1, s.platform2, s.alpha, s.beta} {
		s.verifyCommits(p)
	}
}
