package postgres

import (
	"testing"
	"time"
)

func TestEmbeddedMigrations(t *testing.T) {
	migrations, err := EmbeddedMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if len(migrations) == 0 {
		t.Fatal("expected embedded migrations")
	}
	if migrations[0].Name != "0001_init.sql" {
		t.Fatalf("unexpected first migration %s", migrations[0].Name)
	}
}

func TestUUIDv7Like(t *testing.T) {
	id, err := NewUUIDv7Like(time.UnixMilli(1782835200000).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if got := (id[6] & 0xf0); got != 0x70 {
		t.Fatalf("version nibble = %x", got)
	}
	if got := (id[8] & 0xc0); got != 0x80 {
		t.Fatalf("variant bits = %x", got)
	}
}
