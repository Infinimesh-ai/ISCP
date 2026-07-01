package canonical

import "testing"

func FuzzMarshal(f *testing.F) {
	f.Add([]byte(`{"a":1,"b":"x"}`))
	f.Add([]byte(`{"a":1,"a":2}`))
	f.Add([]byte(`{"a":1.2}`))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = Marshal(input)
	})
}
