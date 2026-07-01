package postgres

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

func NewUUIDv7Like(now time.Time) ([16]byte, error) {
	var id [16]byte
	ms := uint64(now.UnixMilli())
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], ms)
	copy(id[:6], encoded[2:])
	if _, err := rand.Read(id[6:]); err != nil {
		return id, err
	}
	id[6] = (id[6] & 0x0f) | 0x70
	id[8] = (id[8] & 0x3f) | 0x80
	return id, nil
}

func UUIDString(id [16]byte) string {
	return stringHex(id[0:4]) + "-" +
		stringHex(id[4:6]) + "-" +
		stringHex(id[6:8]) + "-" +
		stringHex(id[8:10]) + "-" +
		stringHex(id[10:16])
}

func stringHex(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hex[v>>4]
		out[i*2+1] = hex[v&0x0f]
	}
	return string(out)
}

func UUIDTimePrefix(id [16]byte) uint64 {
	var buf [8]byte
	copy(buf[2:], id[:6])
	return binary.BigEndian.Uint64(buf[:])
}
