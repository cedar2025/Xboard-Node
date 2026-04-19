package dnsproviders

import (
	"github.com/caddyserver/certmagic"
	"github.com/libdns/huaweicloud"
)

func init() {
	Register(&Provider{
		Names:   []string{"huaweicloud", "huawei"},
		EnvVars: []string{"HUAWEICLOUD_ACCESS_KEY_ID", "HUAWEICLOUD_SECRET_ACCESS_KEY", "HUAWEICLOUD_REGION_ID"},
		Build: func(env map[string]string) (certmagic.DNSProvider, error) {
			id := firstOf(env, "HUAWEICLOUD_ACCESS_KEY_ID", "HUAWEI_ACCESS_KEY_ID")
			secret := firstOf(env, "HUAWEICLOUD_SECRET_ACCESS_KEY", "HUAWEI_SECRET_ACCESS_KEY")
			if id == "" || secret == "" {
				return nil, missingEnvErr("huaweicloud", "HUAWEICLOUD_ACCESS_KEY_ID", "HUAWEICLOUD_SECRET_ACCESS_KEY")
			}
			return &huaweicloud.Provider{
				AccessKeyId:     id,
				SecretAccessKey: secret,
				RegionId:        firstOf(env, "HUAWEICLOUD_REGION_ID", "HUAWEI_REGION"),
			}, nil
		},
	})
}
