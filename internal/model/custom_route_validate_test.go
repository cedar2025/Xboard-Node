package model

import (
	"strings"
	"testing"
)

func TestValidateCustomRouteRules(t *testing.T) {
	available := map[string]struct{}{"direct": {}, "block": {}, "warp": {}, "proxy": {}}
	tests := []struct {
		name    string
		rules   []CustomRouteRule
		kernel  string
		wantErr string
	}{
		{
			name: "valid route target",
			rules: []CustomRouteRule{{
				Match:  RouteMatch{DomainSuffixes: []string{"example.com"}, Ports: []string{"443"}, Networks: []string{"tcp"}},
				Action: RouteAction{Type: "route", Target: "warp"},
			}},
			kernel: "xray",
		},
		{
			name:    "missing match",
			rules:   []CustomRouteRule{{Action: RouteAction{Type: "direct"}}},
			kernel:  "xray",
			wantErr: "custom_route_rules[0].match is required",
		},
		{
			name:    "unknown target",
			rules:   []CustomRouteRule{{Match: RouteMatch{DomainSuffixes: []string{"example.com"}}, Action: RouteAction{Type: "route", Target: "missing"}}},
			kernel:  "xray",
			wantErr: `custom_route_rules[0].action.target references unknown outbound "missing"`,
		},
		{
			name:    "route target required",
			rules:   []CustomRouteRule{{Match: RouteMatch{DomainSuffixes: []string{"example.com"}}, Action: RouteAction{Type: "route"}}},
			kernel:  "xray",
			wantErr: "custom_route_rules[0].action.target is required when action.type is route",
		},
		{
			name:    "direct target forbidden",
			rules:   []CustomRouteRule{{Match: RouteMatch{DomainSuffixes: []string{"example.com"}}, Action: RouteAction{Type: "direct", Target: "warp"}}},
			kernel:  "xray",
			wantErr: "custom_route_rules[0].action.target is only allowed when action.type is route",
		},
		{
			name:    "unsupported action",
			rules:   []CustomRouteRule{{Match: RouteMatch{DomainSuffixes: []string{"example.com"}}, Action: RouteAction{Type: "dns"}}},
			kernel:  "xray",
			wantErr: `custom_route_rules[0].action.type "dns" is not supported by kernel "xray"`,
		},
		{
			name:    "invalid port range",
			rules:   []CustomRouteRule{{Match: RouteMatch{Ports: []string{"2000-1000"}}, Action: RouteAction{Type: "direct"}}},
			kernel:  "xray",
			wantErr: `custom_route_rules[0].match.ports contains invalid port range "2000-1000"`,
		},
		{
			name:    "invalid network",
			rules:   []CustomRouteRule{{Match: RouteMatch{Networks: []string{"icmp"}}, Action: RouteAction{Type: "direct"}}},
			kernel:  "xray",
			wantErr: `custom_route_rules[0].match.networks contains unsupported network "icmp"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateCustomRouteRules(tc.rules, tc.kernel, available)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if tc.wantErr != "" {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}
