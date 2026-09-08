package singbox

import (
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
)

// serviceInboundManager exposes the running box's inbound manager to tests.
// Caller holds k.mu.
func serviceInboundManager(k *SingBox) adapter.InboundManager {
	return service.FromContext[adapter.InboundManager](k.ctx)
}
