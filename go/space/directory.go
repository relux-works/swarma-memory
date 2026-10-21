package space

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"time"

	"github.com/relux-works/swarma-memory/go/kernel"
	"github.com/relux-works/swarma-memory/go/sign"
)

type Binding struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}
type Location struct {
	Remote string `json:"remote"`
	Branch string `json:"branch"`
}
type PolicyPin struct {
	Version int64  `json:"version"`
	Digest  string `json:"digest"`
}
type Advertisement struct {
	Format         string    `json:"format"`
	SpaceID        string    `json:"space_id"`
	Kind           string    `json:"kind"`
	Bindings       []Binding `json:"bindings"`
	Git            Location  `json:"git"`
	GenesisDigest  string    `json:"genesis_digest"`
	ObservedPolicy PolicyPin `json:"observed_policy"`
	Author         string    `json:"author"`
}
type SignedAdvertisement struct {
	Advertisement Advertisement  `json:"advertisement"`
	Signature     sign.Signature `json:"signature"`
}
type DirectoryEntry struct {
	Format         string               `json:"format"`
	DirectorySpace string               `json:"directory_space"`
	SpaceID        string               `json:"space_id"`
	Version        int64                `json:"version"`
	Previous       *string              `json:"previous"`
	Status         string               `json:"status"`
	Advertisement  *SignedAdvertisement `json:"advertisement"`
	Author         string               `json:"author"`
}
type SignedDirectory struct {
	Entry     DirectoryEntry `json:"entry"`
	Signature sign.Signature `json:"signature"`
}
type CanonicalAdvertisement struct{ canonical, author string }
type CanonicalDirectory struct{ canonical, author string }

func (p CanonicalAdvertisement) Bytes() []byte  { return []byte(p.canonical) }
func (p CanonicalAdvertisement) Author() string { return p.author }
func (p CanonicalDirectory) Bytes() []byte      { return []byte(p.canonical) }
func (p CanonicalDirectory) Author() string     { return p.author }

type AdvertisementSigner interface {
	SignAdvertisement(CanonicalAdvertisement) (sign.Signature, error)
}
type DirectorySigner interface {
	SignDirectory(CanonicalDirectory) (sign.Signature, error)
}

func NewCanonicalAdvertisement(a Advertisement) (CanonicalAdvertisement, error) {
	b, e := canonicalStruct(a, "advertisement")
	if e != nil {
		return CanonicalAdvertisement{}, e
	}
	if a.SpaceID == "" || a.Author == "" || a.Git.Remote == "" || !safeBranch(a.Git.Branch) || !validDigest(a.GenesisDigest) || !validDigest(a.ObservedPolicy.Digest) || a.ObservedPolicy.Version < 1 || a.ObservedPolicy.Version > 9007199254740991 {
		return CanonicalAdvertisement{}, fail("invalid_advertisement")
	}
	for i, b := range a.Bindings {
		if b.ID == "" || i > 0 && (a.Bindings[i-1].Kind > b.Kind || a.Bindings[i-1].Kind == b.Kind && a.Bindings[i-1].ID >= b.ID) {
			return CanonicalAdvertisement{}, fail("invalid_bindings")
		}
	}
	return CanonicalAdvertisement{string(b), a.Author}, nil
}
func NewCanonicalDirectory(d DirectoryEntry) (CanonicalDirectory, error) {
	if d.Advertisement != nil && d.Advertisement.Signature.Purpose != sign.AdvertisementPurpose {
		return CanonicalDirectory{}, sign.Fail(sign.PurposeMismatch, "advertisement.signature.purpose")
	}
	b, e := canonicalStruct(d, "directory")
	if e != nil {
		return CanonicalDirectory{}, e
	}
	if d.DirectorySpace == "" || d.SpaceID == "" || d.Author == "" || d.Version < 1 || d.Version > 9007199254740991 || (d.Version == 1) != (d.Previous == nil) || d.Previous != nil && !validDigest(*d.Previous) || (d.Status == "active") != (d.Advertisement != nil) {
		return CanonicalDirectory{}, fail("invalid_directory")
	}
	if d.Advertisement != nil {
		if _, e := NewCanonicalAdvertisement(d.Advertisement.Advertisement); e != nil {
			return CanonicalDirectory{}, e
		}
		if d.Advertisement.Advertisement.SpaceID != d.SpaceID {
			return CanonicalDirectory{}, fail("directory_mismatch")
		}
	}
	return CanonicalDirectory{string(b), d.Author}, nil
}
func parseDirectoryObject(data []byte, schema string, out any) error {
	v, r := kernel.DecodeJSON(data)
	if r != nil {
		return sign.Fail(sign.InvalidJSON, "directory")
	}
	m, _ := v.(map[string]any)
	check := func(m map[string]any, purpose string) error {
		sig, _ := m["signature"].(map[string]any)
		if p, ok := sig["purpose"].(string); ok && p != purpose {
			return sign.Fail(sign.PurposeMismatch, "signature.purpose")
		}
		return nil
	}
	if schema == "signed-directory" {
		if e := check(m, sign.DirectoryPurpose); e != nil {
			return e
		}
		d, _ := m["entry"].(map[string]any)
		ad, _ := d["advertisement"].(map[string]any)
		if ad != nil {
			if e := check(ad, sign.AdvertisementPurpose); e != nil {
				return e
			}
		}
	} else if e := check(m, sign.AdvertisementPurpose); e != nil {
		return e
	}
	if r := schemas().Validate(v, "urn:bounded-evidence:space:1:"+schema); r != nil {
		return sign.Fail(sign.InvalidShape, "directory")
	}
	if e := json.Unmarshal(data, out); e != nil {
		return sign.Fail(sign.InvalidShape, "directory")
	}
	return nil
}
func ParseAdvertisement(data []byte) (SignedAdvertisement, error) {
	var a SignedAdvertisement
	if e := parseDirectoryObject(data, "signed-advertisement", &a); e != nil {
		return a, e
	}
	_, e := NewCanonicalAdvertisement(a.Advertisement)
	return a, e
}
func ParseDirectory(data []byte) (SignedDirectory, error) {
	var d SignedDirectory
	if e := parseDirectoryObject(data, "signed-directory", &d); e != nil {
		return d, e
	}
	_, e := NewCanonicalDirectory(d.Entry)
	return d, e
}
func DirectoryPath(d DirectoryEntry) string {
	return "directory/" + hex.EncodeToString([]byte(d.SpaceID)) + "/" + strconv.FormatInt(d.Version, 10) + ".json"
}
func DirectoryDigest(d DirectoryEntry) string {
	c, e := NewCanonicalDirectory(d)
	if e != nil {
		return ""
	}
	h := sha256.Sum256(sign.Frame(sign.DirectoryPurpose, c.Bytes()))
	return "sha256:" + hex.EncodeToString(h[:])
}
func (p *VerifiedPolicy) verifyOwnerObject(author, purpose string, body []byte, sig sign.Signature) error {
	if p == nil || !has(p.policy.Owners, author) {
		return fail("directory_unauthorized")
	}
	k, ok := p.keys[sig.Key]
	if !ok || k.identity != author {
		return fail("directory_unauthorized")
	}
	return (sign.Ed25519Verifier{}).Verify(purpose, body, sig, k.public)
}
func verifyDirectory(p *VerifiedPolicy, d SignedDirectory) error {
	if d.Signature.Purpose != sign.DirectoryPurpose {
		return sign.Fail(sign.PurposeMismatch, "signature.purpose")
	}
	c, e := NewCanonicalDirectory(d.Entry)
	if e != nil {
		return e
	}
	if p == nil || p.policy.Kind != "platform" {
		return fail("directory_not_platform")
	}
	if d.Entry.DirectorySpace != p.policy.SpaceID {
		return fail("directory_mismatch")
	}
	return p.verifyOwnerObject(d.Entry.Author, sign.DirectoryPurpose, c.Bytes(), d.Signature)
}

// Advertisement builds from verified state; caller supplies location from its
// trusted local configuration. It never infers identity bindings from a space id.
func (r *Repository) Advertisement(author string, location Location, bindings []Binding, signer AdvertisementSigner) (SignedAdvertisement, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.policy == nil || !has(r.policy.policy.Owners, author) || signer == nil {
		return SignedAdvertisement{}, fail("directory_unauthorized")
	}
	a := Advertisement{sign.AdvertisementPurpose, r.policy.policy.SpaceID, r.policy.policy.Kind, bindings, location, r.config.GenesisDigest, PolicyPin{r.policy.policy.Version, r.policy.digest}, author}
	c, e := NewCanonicalAdvertisement(a)
	if e != nil {
		return SignedAdvertisement{}, e
	}
	sig, e := signer.SignAdvertisement(c)
	if e == nil {
		e = r.policy.verifyOwnerObject(author, sign.AdvertisementPurpose, c.Bytes(), sig)
	}
	if e != nil {
		return SignedAdvertisement{}, e
	}
	return SignedAdvertisement{a, sig}, nil
}

// VerifyAdvertisement authenticates the observed historical policy and rollback
// floor. Current access remains exclusively the target policy's responsibility.
func (r *Repository) VerifyAdvertisement(a SignedAdvertisement) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, e := NewCanonicalAdvertisement(a.Advertisement)
	if e != nil {
		return fail("directory_mismatch")
	}
	ad := a.Advertisement
	if r.current == nil || r.policy == nil || ad.GenesisDigest != r.config.GenesisDigest || ad.SpaceID != r.policy.policy.SpaceID || ad.Kind != r.policy.policy.Kind {
		return fail("directory_mismatch")
	}
	for _, p := range r.current.Policies {
		if p.policy.Version == ad.ObservedPolicy.Version && p.digest == ad.ObservedPolicy.Digest {
			if e = p.verifyOwnerObject(ad.Author, sign.AdvertisementPurpose, c.Bytes(), a.Signature); e == nil {
				return nil
			}
			break
		}
	}
	return fail("directory_mismatch")
}

type DirectoryItem struct {
	SignedDirectory
	State  string `json:"state"`
	Digest string `json:"digest"`
}

func (r *Repository) directoryItem(d SignedDirectory) DirectoryItem {
	state := d.Entry.Status
	if state == "active" && !has(r.policy.policy.Owners, d.Entry.Author) {
		state = "stale"
	}
	return DirectoryItem{d, state, DirectoryDigest(d.Entry)}
}

// Directory reads detached data through the platform's current reader grant.
func (r *Repository) Directory(principal string) ([]DirectoryItem, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.policy == nil || r.policy.policy.Kind != "platform" {
		return nil, fail("directory_not_platform")
	}
	if !r.policy.readable(principal) {
		return nil, fail("not_authorized")
	}
	out := []DirectoryItem{}
	for _, d := range r.current.Directory {
		b, _ := json.Marshal(d)
		var copy SignedDirectory
		_ = json.Unmarshal(b, &copy)
		out = append(out, r.directoryItem(copy))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Entry.SpaceID < out[j].Entry.SpaceID })
	return out, nil
}
func (r *Repository) LookupDirectory(principal, id string) (SignedAdvertisement, error) {
	items, e := r.Directory(principal)
	if e != nil {
		return SignedAdvertisement{}, e
	}
	for _, item := range items {
		if item.Entry.SpaceID == id {
			if item.State == "withdrawn" {
				return SignedAdvertisement{}, fail("directory_withdrawn")
			}
			if item.State == "stale" {
				return SignedAdvertisement{}, fail("directory_stale")
			}
			return *item.Entry.Advertisement, nil
		}
	}
	return SignedAdvertisement{}, fail("directory_missing")
}

// PublishDirectory serializes an owner publication against the replayed chain.
// Failed racing pushes never replace another head; callers retry explicitly.
func (r *Repository) PublishDirectory(ctx context.Context, author, id string, ad *SignedAdvertisement, signer DirectorySigner) (head string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if e := r.checkoutVerified(cleanup, true); e != nil {
			err = e
		}
	}()
	if signer == nil {
		return "", fail("invalid_request")
	}
	dirty, e := r.git(ctx, nil, "status", "--porcelain", "--untracked-files=all")
	if e != nil {
		return "", e
	}
	if len(dirty) != 0 {
		return "", fail("dirty_clone")
	}
	if e = r.sync(ctx); e != nil {
		return "", e
	}
	if r.policy == nil || r.policy.policy.Kind != "platform" {
		return "", fail("directory_not_platform")
	}
	if !has(r.policy.policy.Owners, author) {
		return "", fail("directory_unauthorized")
	}
	d := DirectoryEntry{Format: sign.DirectoryPurpose, DirectorySpace: r.policy.policy.SpaceID, SpaceID: id, Version: 1, Status: "withdrawn", Advertisement: ad, Author: author}
	if ad != nil {
		d.Status = "active"
	}
	if old, ok := r.current.Directory[id]; ok {
		prev := DirectoryDigest(old.Entry)
		d.Previous = &prev
		d.Version = old.Entry.Version + 1
	}
	c, e := NewCanonicalDirectory(d)
	if e != nil {
		return "", e
	}
	sig, e := signer.SignDirectory(c)
	if e != nil {
		return "", e
	}
	signed := SignedDirectory{d, sig}
	if e = verifyDirectory(r.policy, signed); e != nil {
		return "", e
	}
	data, e := encode(signed)
	if e != nil {
		return "", e
	}
	head, e = r.commit(ctx, r.current.Cursor, map[string][]byte{DirectoryPath(d): data}, []transaction{})
	if e != nil {
		return "", e
	}
	if _, e = r.git(ctx, nil, "push", "--porcelain", "origin", "HEAD:refs/heads/"+r.config.Branch); e != nil {
		return "", fail("version_conflict")
	}
	return head, r.sync(ctx)
}

// replayDirectory never removes accepted state, including on physical deletion.
// An invalid neighbour returns only its own diagnostics.
func (r *Repository) replayDirectory(ctx context.Context, policy *VerifiedPolicy, path string, tree map[string]treeEntry, heads map[string]SignedDirectory, accepted map[string]bool) []error {
	if policy == nil || policy.policy.Kind != "platform" {
		return []error{fail("directory_not_platform")}
	}
	if accepted[path] {
		out := []error{fail("directory_rewritten")}
		// A competing signed version at an accepted immutable path is also a fork.
		if current, ok := tree[path]; ok {
			if data, err := r.blob(ctx, current); err == nil {
				if candidate, err := ParseDirectory(data); err == nil && DirectoryPath(candidate.Entry) == path {
					if err = verifyDirectory(policy, candidate); err == nil {
						out = append(out, fail("directory_sequence"))
					}
				}
			}
		}
		return out
	}
	entry, exists := tree[path]
	if !exists {
		return []error{fail("directory_rewritten")}
	}
	data, err := r.blob(ctx, entry)
	if err != nil {
		return []error{err}
	}
	signed, err := ParseDirectory(data)
	if err != nil {
		return []error{err}
	}
	if DirectoryPath(signed.Entry) != path {
		return []error{fail("directory_path_mismatch")}
	}
	if err = verifyDirectory(policy, signed); err != nil {
		return []error{err}
	}
	old, ok := heads[signed.Entry.SpaceID]
	d := signed.Entry
	if !ok && d.Version != 1 || ok && (d.Version != old.Entry.Version+1 || d.Previous == nil || *d.Previous != DirectoryDigest(old.Entry)) {
		return []error{fail("directory_sequence")}
	}
	heads[d.SpaceID] = signed
	accepted[path] = true
	return nil
}
