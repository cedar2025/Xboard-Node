package dnsproviders

import (
	"github.com/caddyserver/certmagic"
	"github.com/libdns/azure"
)

func init() {
	Register(&Provider{
		Names: []string{"azure"},
		EnvVars: []string{
			"AZURE_SUBSCRIPTION_ID", "AZURE_RESOURCE_GROUP_NAME",
			"AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET",
		},
		Build: func(env map[string]string) (certmagic.DNSProvider, error) {
			sub := firstOf(env, "AZURE_SUBSCRIPTION_ID")
			rg := firstOf(env, "AZURE_RESOURCE_GROUP_NAME", "AZURE_RESOURCE_GROUP")
			if sub == "" || rg == "" {
				return nil, missingEnvErr("azure", "AZURE_SUBSCRIPTION_ID", "AZURE_RESOURCE_GROUP_NAME")
			}
			// TenantId/ClientId/ClientSecret are optional — when omitted, libdns
			// falls back to the default Azure credential chain (managed identity,
			// CLI login, etc.).
			return &azure.Provider{
				SubscriptionId:    sub,
				ResourceGroupName: rg,
				TenantId:          firstOf(env, "AZURE_TENANT_ID"),
				ClientId:          firstOf(env, "AZURE_CLIENT_ID"),
				ClientSecret:      firstOf(env, "AZURE_CLIENT_SECRET"),
			}, nil
		},
	})
}
