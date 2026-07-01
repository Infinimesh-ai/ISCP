package main

import (
	"fmt"
	"time"

	"github.com/Chiiz0/ISCP/pkg/iscp/crypto"
	"github.com/Chiiz0/ISCP/pkg/iscp/envelope"
	"github.com/Chiiz0/ISCP/pkg/iscp/identity"
	"github.com/Chiiz0/ISCP/pkg/iscp/payload"
	"github.com/Chiiz0/ISCP/pkg/iscp/provisioning"
	"github.com/Chiiz0/ISCP/pkg/iscp/session"
)

func main() {
	if err := run(); err != nil {
		panic(err)
	}
}

func run() error {
	p := crypto.NewProvider()
	now := time.Now().UTC()
	phone, err := identity.NewDevice(p, "local", "phone", now)
	if err != nil {
		return err
	}
	watch, err := identity.NewDevice(p, "local", "watch", now)
	if err != nil {
		return err
	}
	channel, err := provisioning.EstablishLocalChannel(p, []byte("oob-123456"))
	if err != nil {
		return err
	}
	tp, _ := identity.Thumbprint(watch.Identity)
	bundle, err := provisioning.SignBundle(p, phone, provisioning.Bundle{
		BundleID:                    "bundle-watch",
		IssuedToDeviceID:            watch.Identity.DeviceID,
		IssuedToPublicKeyThumbprint: tp,
		RelayDescriptor:             []byte(`{"type":"relay"}`),
		TrustRootDescriptor:         []byte(`{"type":"trust"}`),
		AccessCredential:            []byte(`{"type":"access"}`),
		RefreshCredentialWrapped:    crypto.Base64URL([]byte("wrapped-refresh")),
		TrustGrant:                  []byte(`{"type":"grant"}`),
		IssuedAt:                    now,
		ExpiresAt:                   now.Add(time.Hour),
	})
	if err != nil {
		return err
	}
	if err := provisioning.ApplyBundle(p, channel, watch.Identity, bundle, phone.Identity, now); err != nil {
		return err
	}
	hp, _ := session.CreateHello(p, phone, "hot-audio-session", watch.Identity.DeviceID, "grant-audio", now)
	hw, _ := session.CreateHello(p, watch, "hot-audio-session", phone.Identity.DeviceID, "grant-audio", now)
	sp, _ := session.Establish(p, hp, hw.Hello, phone.Identity, watch.Identity)
	sw, _ := session.Establish(p, hw, hp.Hello, watch.Identity, phone.Identity)
	rp, _ := sp.CreateReady(p, phone)
	rw, _ := sw.CreateReady(p, watch)
	_ = sp.VerifyReady(p, rw, watch.Identity)
	_ = sw.VerifyReady(p, rp, phone.Identity)
	frame := []byte(`{"codec":"pcm16","duration_ms":20,"data":"redacted"}`)
	env, err := envelope.Encrypt(p, sw, "audio-1", payload.TypeAudioFrame, envelope.Route{RelayID: "relay-local", TTLSeconds: 10, Priority: 5}, frame)
	if err != nil {
		return err
	}
	plain, err := envelope.Decrypt(p, sp, env)
	if err != nil {
		return err
	}
	fmt.Println("phone-watch-simulator ok audio.frame bytes", len(plain))
	return nil
}
