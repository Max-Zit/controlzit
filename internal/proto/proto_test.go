package proto

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func TestSignVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	c := Command{ID: "1", AgentID: "a", Kind: KindFSList, Args: []byte(`{"path":"C:\\"}`), IssuedAt: now, Expires: now.Add(time.Minute)}
	sc, err := Sign(priv, c)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Verify(pub, sc, "a", now); err != nil || got.Kind != KindFSList {
		t.Fatalf("verify: %v", err)
	}
	if _, err := Verify(pub, sc, "b", now); !errors.Is(err, ErrWrongAgent) {
		t.Fatal("command for another agent accepted")
	}
	if _, err := Verify(pub, sc, "a", now.Add(10*time.Minute)); !errors.Is(err, ErrExpired) {
		t.Fatal("expired command accepted")
	}
	tampered := sc
	tampered.Command = []byte(string(sc.Command[:len(sc.Command)-2]) + " }")
	if _, err := Verify(pub, tampered, "a", now); !errors.Is(err, ErrBadSignature) {
		t.Fatal("tampered command accepted")
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Verify(other, sc, "a", now); !errors.Is(err, ErrBadSignature) {
		t.Fatal("wrong key accepted")
	}
	long := c
	long.Expires = now.Add(time.Hour)
	sl, _ := Sign(priv, long)
	if _, err := Verify(pub, sl, "a", now); !errors.Is(err, ErrExpired) {
		t.Fatal("long-lived command accepted")
	}
}
