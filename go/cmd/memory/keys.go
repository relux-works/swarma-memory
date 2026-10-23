package main

import (
	"encoding/base64"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/relux-works/swarma-memory/go/sign"
	"github.com/relux-works/swarma-memory/go/sign/localkey"
	"github.com/relux-works/swarma-memory/go/sign/sshagent"
)

func initKeys(h home, a arguments) (any, error) {
	if e := a.allow("identity", "ssh-agent", "public-key"); e != nil {
		return nil, e
	}
	identity, e := a.required("identity")
	if e != nil {
		return nil, e
	}
	socket, hasSocket := a.flags["ssh-agent"]
	line, hasPublic := a.flags["public-key"]
	if hasSocket != hasPublic {
		return nil, cliError{"usage", 2}
	}
	if _, e := os.Lstat(h.filename()); !errors.Is(e, os.ErrNotExist) {
		return nil, cliError{"already_configured", 3}
	}
	if _, e := os.Lstat(h.keyfile()); !errors.Is(e, os.ErrNotExist) {
		return nil, sign.Fail(sign.KeyIO, "save")
	}
	c := localConfig{Identity: identity, KeyFile: h.keyfile(), Spaces: []localSpace{}}
	var k identityKey
	if hasSocket {
		if strings.HasPrefix(line, "@") {
			name := strings.TrimPrefix(line, "@")
			info, e := os.Lstat(name)
			if e != nil || !info.Mode().IsRegular() || info.Size() > sshagent.MaxFrameBytes {
				return nil, sign.Fail(sign.InvalidKey, "public_key")
			}
			f, e := os.Open(name)
			if e != nil {
				return nil, sign.Fail(sign.InvalidKey, "public_key")
			}
			b, e := io.ReadAll(io.LimitReader(f, sshagent.MaxFrameBytes+1))
			f.Close()
			if e != nil || len(b) > sshagent.MaxFrameBytes {
				return nil, sign.Fail(sign.InvalidKey, "public_key")
			}
			line = string(b)
		}
		pub, e := sshagent.ParsePublicKey(line)
		if e != nil {
			return nil, e
		}
		c.KeyFile = ""
		c.Signer = &agentConfig{Kind: "ssh-agent", Socket: socket, PublicKey: base64.StdEncoding.EncodeToString(pub)}
		if _, e = h.encodeConfig(c); e != nil {
			return nil, e
		}
		agent, e := sshagent.New(identity, socket, pub, 0)
		if e != nil {
			return nil, e
		}

		if e = agent.Check(); e != nil {
			return nil, e
		}
		k = agent
	} else {
		k, e = localkey.Generate(identity)
		if e != nil {
			return nil, e
		}
	}
	if _, e = h.encodeConfig(c); e != nil {
		return nil, e
	}
	if e = privateDir(h.config); e != nil {
		return nil, e
	}
	if file, ok := k.(*localkey.Key); ok {
		if e = file.Save(h.keyfile()); e != nil {
			return nil, e
		}
	}
	if e = h.writeConfig(c, true); e != nil {
		if _, ok := k.(*localkey.Key); ok {
			_ = os.Remove(h.keyfile())
		}
		return nil, e
	}
	return keyData(k), nil
}
