package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"testing"
	"time"
)

// TestSFTPLive runs against a real SFTP server:
//
//	CONTROLZIT_TEST_SFTP=host:port CONTROLZIT_TEST_SFTP_USER=… CONTROLZIT_TEST_SFTP_PASSWORD=… CONTROLZIT_TEST_SFTP_DIR=…
func TestSFTPLive(t *testing.T) {
	host := os.Getenv("CONTROLZIT_TEST_SFTP")
	if host == "" {
		t.Skip("CONTROLZIT_TEST_SFTP not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	c := SFTP{Host: host, Port: 22, User: os.Getenv("CONTROLZIT_TEST_SFTP_USER"), Password: os.Getenv("CONTROLZIT_TEST_SFTP_PASSWORD"),
		Dir: os.Getenv("CONTROLZIT_TEST_SFTP_DIR") + "/cz-sftp-test"}
	fp, err := TestSFTP(ctx, c)
	var hk *ErrHostKey
	if !errors.As(err, &hk) || fp == "" {
		t.Fatalf("an unknown host key was accepted: %v", err)
	}
	c.HostKey = fp
	if _, err := TestSFTP(ctx, c); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 3<<20+12345) // many pipelined writes
	_, _ = rand.Read(data)
	for i := 0; i < 3; i++ {
		name := "controlzit-backup-2026010" + string(rune('1'+i)) + "-000000.czb"
		if err := UploadSFTP(ctx, c, name, "controlzit-backup-", 2, bytes.NewReader(data)); err != nil {
			t.Fatal(err)
		}
	}
	cl, err := dialSFTP(ctx, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	names, err := cl.list(c.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Fatalf("kept %v", names)
	}
	for _, n := range names {
		if n == "controlzit-backup-20260101-000000.czb" {
			t.Fatalf("the oldest was not removed: %v", names)
		}
		_ = cl.remove(c.Dir + "/" + n)
	}
}
