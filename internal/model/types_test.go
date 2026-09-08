package model

import (
	"encoding/json"
	"testing"
)

// CloneNodeSpec backs the desired, prepared and applied snapshots and the
// hash is computed from the JSON form, so a clone must serialise exactly like
// its original (nil and empty containers kept apart) and must not share any
// nested value with it.
func TestCloneNodeSpecPreservesJSONFormAndIsolatesNestedValues(t *testing.T) {
	spec := &NodeSpec{
		Protocol: "vless",
		NetworkSettings: map[string]any{
			"headers": map[string]any{"Host": "a.example.test"},
			"extra":   []any{map[string]any{"k": "v"}, "plain"},
		},
		TLSSettings:     map[string]any{},
		Routes:          []RouteRule{},
		CustomRoutes:    []map[string]any{{"outboundTag": "direct", "domain": []any{"example.test"}}},
		CustomOutbounds: []OutboundConfig{{Tag: "out", Settings: map[string]any{}}},
	}
	original, _ := json.Marshal(spec)

	clone := CloneNodeSpec(spec)
	if cloned, _ := json.Marshal(clone); string(cloned) != string(original) {
		t.Fatalf("clone serialises differently:\n%s\n%s", original, cloned)
	}

	clone.NetworkSettings["headers"].(map[string]any)["Host"] = "changed"
	clone.NetworkSettings["extra"].([]any)[0].(map[string]any)["k"] = "changed"
	clone.CustomRoutes[0]["domain"].([]any)[0] = "changed"
	clone.TLSSettings["added"] = true
	clone.CustomOutbounds[0].Settings["added"] = true
	if after, _ := json.Marshal(spec); string(after) != string(original) {
		t.Fatalf("mutating the clone changed the original:\n%s\n%s", original, after)
	}

	empty := CloneNodeSpec(&NodeSpec{Protocol: "vless"})
	if empty.NetworkSettings != nil || empty.TLSSettings != nil || empty.Routes != nil || empty.CustomRoutes != nil || empty.CustomOutbounds != nil || empty.CustomRouteRules != nil {
		t.Fatalf("nil containers must stay nil: %+v", empty)
	}
}

func TestCloneNodeSpecPreservesNestedNilAndEmptySlices(t *testing.T) {
	for name, value := range map[string]any{
		"null":        nil,
		"nil slice":   []any(nil),
		"empty slice": []any{},
		"nested":      []any{[]any(nil), []any{}, map[string]any{"items": []any(nil)}},
	} {
		t.Run(name, func(t *testing.T) {
			spec := &NodeSpec{Protocol: "vless", NetworkSettings: map[string]any{"extra": value}}
			original, err := json.Marshal(spec)
			if err != nil {
				t.Fatal(err)
			}
			cloned, err := json.Marshal(CloneNodeSpec(spec))
			if err != nil {
				t.Fatal(err)
			}
			if string(cloned) != string(original) {
				t.Fatalf("clone changed the configuration's JSON form:\noriginal: %s\nclone: %s", original, cloned)
			}
		})
	}
}
