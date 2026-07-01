package canonical

import "testing"

func TestMarshalSortsKeys(t *testing.T) {
	got, err := Marshal([]byte(`{"b":2,"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"a":1,"b":2}` {
		t.Fatalf("unexpected canonical bytes: %s", got)
	}
}

func TestRejectDuplicate(t *testing.T) {
	if _, err := Marshal([]byte(`{"a":1,"a":2}`)); err == nil {
		t.Fatal("expected duplicate field rejection")
	}
}

func TestRejectFloat(t *testing.T) {
	if _, err := Marshal([]byte(`{"a":1.2}`)); err == nil {
		t.Fatal("expected float rejection")
	}
}

func TestSignatureInputRemovesSignature(t *testing.T) {
	got, err := SignatureInput("iscp.test.v2", []byte(`{"b":2,"signature":{"value":"x"},"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	want := "ISCP-V2-SIGNATURE\x00iscp.test.v2\x00" + `{"a":1,"b":2}`
	if string(got) != want {
		t.Fatalf("unexpected signature input: %q", got)
	}
}
