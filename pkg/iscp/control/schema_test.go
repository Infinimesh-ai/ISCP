// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestEmbeddedSchemaMatchesCandidateSource(t *testing.T) {
	raw, err := os.ReadFile("../../../schemas/candidates/operation-recovery.v2.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, schemaJSON) {
		t.Fatal("embedded control schema differs from canonical candidate")
	}
}
func TestCandidateSchemaVectors(t *testing.T) {
	f := fixture(t)
	positive := map[string]string{"intent": "intent", "challenge": "challenge", "request": "request_recover", "authentication_context": "authentication_context", "result": "result", "disposition": "disposition_receipt", "status_record": "status", "child_result": "result", "child_disposition": "disposition_receipt", "child_delegated_disposition": "disposition_receipt", "parent_recovery_intent": "intent", "parent_recovery_result": "result"}
	for name, def := range positive {
		t.Run(name, func(t *testing.T) {
			var out any
			if err := Decode(f[name], def, &out); err != nil {
				t.Fatal(err)
			}
		})
	}
	var lexical []struct {
		Name string `json:"name"`
		Raw  string `json:"raw"`
		Hex  string `json:"raw_hex"`
	}
	if err := json.Unmarshal(f["negative_raw"], &lexical); err != nil {
		t.Fatal(err)
	}
	for _, item := range lexical {
		t.Run(item.Name, func(t *testing.T) {
			raw := []byte(item.Raw)
			if item.Hex != "" {
				var err error
				raw, err = hex.DecodeString(item.Hex)
				if err != nil {
					t.Fatal(err)
				}
			}
			var out any
			if Decode(raw, "intent", &out) == nil {
				t.Fatal("accepted invalid lexical JSON")
			}
		})
	}
	for _, group := range []struct{ mutation, source, def string }{{"negative_schema", "request", "request_recover"}, {"negative_status", "status_record", "status"}} {
		var cases []struct {
			Name  string   `json:"name"`
			Path  []string `json:"path"`
			Value any      `json:"value"`
		}
		if err := json.Unmarshal(f[group.mutation], &cases); err != nil {
			t.Fatal(err)
		}
		for _, item := range cases {
			t.Run(item.Name, func(t *testing.T) {
				var value map[string]any
				if err := json.Unmarshal(f[group.source], &value); err != nil {
					t.Fatal(err)
				}
				target := value
				for _, key := range item.Path[:len(item.Path)-1] {
					target = target[key].(map[string]any)
				}
				target[item.Path[len(item.Path)-1]] = item.Value
				if Validate(value, group.def) == nil {
					t.Fatal("accepted contradictory/unknown schema fields")
				}
			})
		}
	}
}
