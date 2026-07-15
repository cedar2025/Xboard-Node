package controlplane

import (
	"sync"

	"github.com/cedar2025/xboard-node/internal/model"
)

// MailboxState is the coalesced snapshot drained from a NodeMailbox.
type MailboxState struct {
	Config         *model.NodeSpec
	Users          []model.UserSpec
	DeviceUsers    map[int][]string
	HasConfig      bool
	HasUsers       bool
	HasDevices     bool
	NeedsReconcile bool
}

// NodeMailbox buffers WS events for a machine-mode node service that is not
// yet ready to process them. Events are coalesced (latest-wins) and drained
// as a single snapshot once the service marks the mailbox as ready.
type NodeMailbox struct {
	mu               sync.Mutex
	ready            bool
	config           *model.NodeSpec
	users            []model.UserSpec
	deviceUsers      map[int][]string
	dirtyConfig      bool
	dirtyUsers       bool
	dirtyDevices     bool
	needsReconcile   bool
	hasFullUserState bool
	notifyCh         chan struct{}
}

func NewNodeMailbox() *NodeMailbox {
	return &NodeMailbox{notifyCh: make(chan struct{}, 1)}
}

func (m *NodeMailbox) MarkReady() {
	m.mu.Lock()
	m.ready = true
	m.mu.Unlock()
	m.notify()
}

// SeedBaseline initializes the mailbox with the REST-derived baseline so that
// subsequent delta events can be applied incrementally instead of triggering
// a full REST reconciliation.
func (m *NodeMailbox) SeedBaseline(users []model.UserSpec, config *model.NodeSpec) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if users != nil && !m.hasFullUserState {
		m.users = cloneUsers(users)
		m.hasFullUserState = true
	}
	if config != nil && m.config == nil {
		m.config = cloneNodeSpec(config)
	}
}

func (m *NodeMailbox) Apply(event Event) {
	m.mu.Lock()
	changed := false

	switch event.Type {
	case EventSyncConfig:
		if event.Config != nil {
			m.config = cloneNodeSpec(event.Config)
			m.dirtyConfig = true
			changed = true
		}
	case EventSyncUsers:
		if event.Users != nil {
			m.users = cloneUsers(event.Users)
			m.dirtyUsers = true
			m.hasFullUserState = true
			changed = true
		}
	case EventSyncDevices:
		if event.DeviceUsers != nil {
			m.deviceUsers = cloneDeviceUsers(event.DeviceUsers)
			m.dirtyDevices = true
			changed = true
		}
	case EventSyncUserDelta:
		if len(event.DeltaUsers) > 0 {
			if !m.hasFullUserState {
				m.needsReconcile = true
				changed = true
			} else if !applyUserDelta(&m.users, event.DeltaAction, event.DeltaUsers) {
				m.needsReconcile = true
				changed = true
			} else {
				m.dirtyUsers = true
				changed = true
			}
		}
	}
	m.mu.Unlock()

	if changed {
		m.notify()
	}
}

func (m *NodeMailbox) notify() {
	select {
	case m.notifyCh <- struct{}{}:
	default:
	}
}

func (m *NodeMailbox) NotifyCh() <-chan struct{} { return m.notifyCh }

func (m *NodeMailbox) DrainIfReady() MailboxState {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.ready {
		return MailboxState{}
	}
	state := MailboxState{NeedsReconcile: m.needsReconcile}
	if m.dirtyConfig && m.config != nil {
		// Transfer ownership: swap out the stored config instead of cloning.
		state.Config = m.config
		state.HasConfig = true
		m.config = nil
		m.dirtyConfig = false
	}
	if m.dirtyUsers {
		state.Users = cloneUsers(m.users)
		state.HasUsers = true
		m.dirtyUsers = false
	}
	if m.dirtyDevices && m.deviceUsers != nil {
		state.DeviceUsers = cloneDeviceUsers(m.deviceUsers)
		state.HasDevices = true
		m.dirtyDevices = false
	}
	m.needsReconcile = false
	return state
}

func cloneNodeSpec(spec *model.NodeSpec) *model.NodeSpec {
	if spec == nil {
		return nil
	}
	clone := *spec
	if spec.NetworkSettings != nil {
		clone.NetworkSettings = make(map[string]interface{}, len(spec.NetworkSettings))
		for k, v := range spec.NetworkSettings {
			clone.NetworkSettings[k] = v
		}
	}
	if spec.TLSSettings != nil {
		clone.TLSSettings = make(map[string]interface{}, len(spec.TLSSettings))
		for k, v := range spec.TLSSettings {
			clone.TLSSettings[k] = v
		}
	}
	if spec.Routes != nil {
		clone.Routes = append([]model.RouteRule(nil), spec.Routes...)
	}
	if spec.CustomOutbounds != nil {
		clone.CustomOutbounds = append([]model.OutboundConfig(nil), spec.CustomOutbounds...)
	}
	if spec.CustomRoutes != nil {
		clone.CustomRoutes = make([]map[string]any, len(spec.CustomRoutes))
		for i, route := range spec.CustomRoutes {
			if route == nil {
				continue
			}
			copied := make(map[string]any, len(route))
			for k, v := range route {
				copied[k] = v
			}
			clone.CustomRoutes[i] = copied
		}
	}
	if spec.CustomRouteRules != nil {
		clone.CustomRouteRules = append([]model.CustomRouteRule(nil), spec.CustomRouteRules...)
	}
	if spec.CertConfig != nil {
		certCopy := *spec.CertConfig
		if spec.CertConfig.DNSEnv != nil {
			certCopy.DNSEnv = make(map[string]string, len(spec.CertConfig.DNSEnv))
			for k, v := range spec.CertConfig.DNSEnv {
				certCopy.DNSEnv[k] = v
			}
		}
		clone.CertConfig = &certCopy
	}
	if spec.Multiplex != nil {
		muxCopy := *spec.Multiplex
		if spec.Multiplex.Brutal != nil {
			brutalCopy := *spec.Multiplex.Brutal
			muxCopy.Brutal = &brutalCopy
		}
		clone.Multiplex = &muxCopy
	}
	return &clone
}

func cloneUsers(users []model.UserSpec) []model.UserSpec {
	if users == nil {
		return nil
	}
	cloned := make([]model.UserSpec, len(users))
	copy(cloned, users)
	return cloned
}

func cloneDeviceUsers(devices map[int][]string) map[int][]string {
	if devices == nil {
		return nil
	}
	cloned := make(map[int][]string, len(devices))
	for uid, ips := range devices {
		dup := make([]string, len(ips))
		copy(dup, ips)
		cloned[uid] = dup
	}
	return cloned
}

func applyUserDelta(users *[]model.UserSpec, action string, delta []model.UserSpec) bool {
	current := cloneUsers(*users)
	index := make(map[int]int, len(current))
	for i, user := range current {
		index[user.ID] = i
	}

	switch action {
	case "add":
		for _, user := range delta {
			if idx, ok := index[user.ID]; ok {
				current[idx] = user
				continue
			}
			index[user.ID] = len(current)
			current = append(current, user)
		}
	case "remove":
		removeIDs := make(map[int]struct{}, len(delta))
		for _, user := range delta {
			removeIDs[user.ID] = struct{}{}
		}
		filtered := current[:0]
		for _, user := range current {
			if _, ok := removeIDs[user.ID]; ok {
				continue
			}
			filtered = append(filtered, user)
		}
		current = append([]model.UserSpec(nil), filtered...)
	default:
		return false
	}

	*users = current
	return true
}
