package dnsproviders

import (
	"github.com/caddyserver/certmagic"
	"github.com/libdns/alidns"
)

func init() {
	Register(&Provider{
		Names:   []string{"alidns", "aliyun"},
		EnvVars: []string{"ALICLOUD_ACCESS_KEY_ID", "ALICLOUD_ACCESS_KEY_SECRET"},
		Build: func(env map[string]string) (certmagic.DNSProvider, error) {
			keyID := firstOf(env, "ALICLOUD_ACCESS_KEY_ID", "ALI_ACCESS_KEY_ID", "ALIYUN_ACCESS_KEY_ID")
			keySecret := firstOf(env, "ALICLOUD_ACCESS_KEY_SECRET", "ALI_ACCESS_KEY_SECRET", "ALIYUN_ACCESS_KEY_SECRET")
			if keyID == "" || keySecret == "" {
				return nil, missingEnvErr("alidns", "ALICLOUD_ACCESS_KEY_ID", "ALICLOUD_ACCESS_KEY_SECRET")
			}
			return &alidns.Provider{
				CredentialInfo: alidns.CredentialInfo{
					AccessKeyID:     keyID,
					AccessKeySecret: keySecret,
				},
			}, nil
		},
	})
}
