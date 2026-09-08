package xray

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/model"
	xraynet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	xrayCore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/routing"
	xrayProxy "github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Native failure injection for the user-management entry points.
//
// A stub UserManager is mounted on a bare xray-core instance through a stub
// inbound manager, so AddUsers / RemoveUsers / UpdateUsers reach it through
// the production getUserManager path unchanged. The stub keeps the account
// set the way the real validators do (AddUser rejects a duplicate email,
// RemoveUser reports an unknown email, GetUser proves absence) and lets a test
// fail one operation. The recovery path rebuilds a real xray instance, so the
// tests check the account set the rebuilt kernel actually holds.

const (
	uuidA = "11111111-1111-4111-8111-111111111111"
	uuidB = "22222222-2222-4222-8222-222222222222"
	uuidC = "33333333-3333-4333-8333-333333333333"
	uuidD = "44444444-4444-4444-8444-444444444444"
	uuidE = "55555555-5555-4555-8555-555555555555"
	// invalidCredential is longer than the 36 characters of a UUID and longer
	// than the 30 characters xray maps to a UUIDv5, so toMemoryUser rejects it.
	invalidCredential = "this-credential-is-not-a-valid-uuid-at-all"
)

type stubUserManager struct {
	mu        sync.Mutex
	users     map[string]*protocol.MemoryUser
	addErr    map[string]error
	removeErr map[string]error
	ops       []string
}

func newStubUserManager(users ...model.UserSpec) *stubUserManager {
	m := &stubUserManager{
		users:     make(map[string]*protocol.MemoryUser),
		addErr:    make(map[string]error),
		removeErr: make(map[string]error),
	}
	for _, u := range users {
		mu, err := toMemoryUser("vless", &model.NodeSpec{Protocol: "vless"}, u)
		if err != nil {
			panic(err)
		}
		m.users[strings.ToLower(mu.Email)] = mu
	}
	return m
}

func (m *stubUserManager) AddUser(_ context.Context, u *protocol.MemoryUser) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	email := strings.ToLower(u.Email)
	m.ops = append(m.ops, "add "+email)
	if err := m.addErr[email]; err != nil {
		return err
	}
	if _, exists := m.users[email]; exists {
		return fmt.Errorf("User %s already exists.", u.Email)
	}
	m.users[email] = u
	return nil
}

func (m *stubUserManager) RemoveUser(_ context.Context, email string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	email = strings.ToLower(email)
	m.ops = append(m.ops, "remove "+email)
	if err := m.removeErr[email]; err != nil {
		return err
	}
	if _, exists := m.users[email]; !exists {
		return fmt.Errorf("User %s not found.", email)
	}
	delete(m.users, email)
	return nil
}

func (m *stubUserManager) GetUser(_ context.Context, email string) *protocol.MemoryUser {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.users[strings.ToLower(email)]
}

func (m *stubUserManager) GetUsers(context.Context) []*protocol.MemoryUser {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*protocol.MemoryUser, 0, len(m.users))
	for _, u := range m.users {
		out = append(out, u)
	}
	return out
}

func (m *stubUserManager) GetUsersCount(context.Context) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return int64(len(m.users))
}

func (m *stubUserManager) Network() []xraynet.Network { return nil }
func (m *stubUserManager) Process(context.Context, xraynet.Network, stat.Connection, routing.Dispatcher) error {
	return nil
}

// emails returns the sorted account emails the stub currently holds.
func (m *stubUserManager) emails() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.users))
	for email := range m.users {
		out = append(out, email)
	}
	sort.Strings(out)
	return out
}

func (m *stubUserManager) operations() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.ops...)
}

type stubInboundHandler struct {
	tag string
	um  *stubUserManager
}

func (h *stubInboundHandler) Start() error                           { return nil }
func (h *stubInboundHandler) Close() error                           { return nil }
func (h *stubInboundHandler) Tag() string                            { return h.tag }
func (h *stubInboundHandler) ReceiverSettings() *serial.TypedMessage { return nil }
func (h *stubInboundHandler) ProxySettings() *serial.TypedMessage    { return nil }
func (h *stubInboundHandler) GetInbound() xrayProxy.Inbound          { return h.um }

type stubInboundManager struct {
	mu       sync.Mutex
	handlers map[string]inbound.Handler
}

func (m *stubInboundManager) Type() interface{} { return inbound.ManagerType() }
func (m *stubInboundManager) Start() error      { return nil }
func (m *stubInboundManager) Close() error      { return nil }
func (m *stubInboundManager) GetHandler(_ context.Context, tag string) (inbound.Handler, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.handlers[tag]
	if !ok {
		return nil, fmt.Errorf("handler not found: %s", tag)
	}
	return h, nil
}
func (m *stubInboundManager) AddHandler(_ context.Context, h inbound.Handler) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers[h.Tag()] = h
	return nil
}
func (m *stubInboundManager) RemoveHandler(_ context.Context, tag string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.handlers, tag)
	return nil
}
func (m *stubInboundManager) ListHandlers(context.Context) []inbound.Handler {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]inbound.Handler, 0, len(m.handlers))
	for _, h := range m.handlers {
		out = append(out, h)
	}
	return out
}

var (
	_ inbound.Manager       = (*stubInboundManager)(nil)
	_ xrayProxy.UserManager = (*stubUserManager)(nil)
	_ xrayProxy.Inbound     = (*stubUserManager)(nil)
	_ xrayProxy.GetInbound  = (*stubInboundHandler)(nil)
)

func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

// stubBackedXray is a running Xray whose instance is a bare xray-core
// instance carrying only the stub inbound manager. Its node configuration is
// a real plain VLESS target, so a controlled rebuild creates a real instance.
type stubBackedXray struct {
	x    *Xray
	inst *xrayCore.Instance
	um   *stubUserManager
}

func newStubBackedXray(t *testing.T, users []model.UserSpec) *stubBackedXray {
	t.Helper()
	um := newStubUserManager(users...)
	inst := new(xrayCore.Instance)
	mgr := &stubInboundManager{handlers: map[string]inbound.Handler{
		"vless-in": &stubInboundHandler{tag: "vless-in", um: um},
	}}
	if err := inst.AddFeature(mgr); err != nil {
		t.Fatalf("Instance.AddFeature(inbound manager) error = %v", err)
	}
	x := New(config.KernelConfig{Type: "xray", LogLevel: "warn"})
	x.instance = inst
	x.users = model.CloneUserSpecs(users)
	x.protocol = "vless"
	x.inboundTag = "vless-in"
	x.nodeConfig = &model.NodeSpec{Protocol: "vless", Network: "tcp", ListenIP: "127.0.0.1", ServerPort: freeLoopbackPort(t)}
	x.cumTraffic = make(map[int][2]int64)
	x.running.Store(true)
	t.Cleanup(x.Stop)
	return &stubBackedXray{x: x, inst: inst, um: um}
}

// unrebuildable makes a controlled rebuild fail deterministically: the
// listen address is TEST-NET-1, which no local interface carries.
func (s *stubBackedXray) unrebuildable() {
	s.x.nodeConfig.ListenIP = "192.0.2.1"
}

// realAccountEmails reads the account set of the real instance the kernel
// runs after a rebuild, through the production UserManager lookup.
func (s *stubBackedXray) realAccountEmails(t *testing.T) []string {
	t.Helper()
	s.x.mu.Lock()
	um, err := s.x.getUserManager()
	s.x.mu.Unlock()
	if err != nil {
		t.Fatalf("getUserManager() after rebuild: %v", err)
	}
	var out []string
	for _, u := range um.GetUsers(context.Background()) {
		out = append(out, strings.ToLower(u.Email))
	}
	sort.Strings(out)
	return out
}

func (s *stubBackedXray) rebuilt() bool {
	s.x.mu.Lock()
	defer s.x.mu.Unlock()
	return s.x.instance != s.inst
}

func bookkeeping(x *Xray) []model.UserSpec {
	x.mu.Lock()
	defer x.mu.Unlock()
	out := model.CloneUserSpecs(x.users)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func emailsOf(users ...model.UserSpec) []string {
	out := make([]string, 0, len(users))
	for _, u := range users {
		out = append(out, userEmail(u.ID))
	}
	sort.Strings(out)
	return out
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameUsers(a, b []model.UserSpec) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The bookkeeping must always describe the accounts the manager holds.
func assertBookkeepingMatchesStub(t *testing.T, s *stubBackedXray) {
	t.Helper()
	if got, want := emailsOf(bookkeeping(s.x)...), s.um.emails(); !sameStrings(got, want) {
		t.Fatalf("bookkeeping %v does not describe the native account set %v", got, want)
	}
}

func TestXrayUpdateUsersRejectsInvalidCredentialBeforeAnyNativeChange(t *testing.T) {
	current := []model.UserSpec{{ID: 1, UUID: uuidA}, {ID: 2, UUID: uuidB}}
	s := newStubBackedXray(t, current)

	desired := []model.UserSpec{{ID: 2, UUID: uuidB}, {ID: 3, UUID: invalidCredential}}
	added, removed, err := s.x.UpdateUsers(desired)
	if err == nil {
		t.Fatal("an unusable credential must be reported, not skipped")
	}
	if added != 0 || removed != 0 {
		t.Fatalf("counts = (%d, %d), want (0, 0) for an update that did nothing", added, removed)
	}
	if ops := s.um.operations(); len(ops) != 0 {
		t.Fatalf("native operations ran before the credentials were checked: %v", ops)
	}
	if got := bookkeeping(s.x); !sameUsers(got, current) {
		t.Fatalf("bookkeeping changed to %v although the kernel still holds %v", got, current)
	}
	assertBookkeepingMatchesStub(t, s)
	if s.rebuilt() || !s.x.IsRunning() {
		t.Fatal("a rejected credential must leave the running instance alone")
	}
}

func TestXrayAddUsersRejectsInvalidCredentialBeforeAnyNativeChange(t *testing.T) {
	current := []model.UserSpec{{ID: 1, UUID: uuidA}}
	s := newStubBackedXray(t, current)

	added, err := s.x.AddUsers([]model.UserSpec{{ID: 2, UUID: uuidB}, {ID: 3, UUID: invalidCredential}})
	if err == nil || added != 0 {
		t.Fatalf("AddUsers() = (%d, %v), want an error and no additions", added, err)
	}
	if ops := s.um.operations(); len(ops) != 0 {
		t.Fatalf("native operations ran before the credentials were checked: %v", ops)
	}
	if got := bookkeeping(s.x); !sameUsers(got, current) {
		t.Fatalf("bookkeeping = %v, want unchanged %v", got, current)
	}
	assertBookkeepingMatchesStub(t, s)
}

func TestXrayUpdateUsersAddFailureRebuildsInstanceWithDesiredUsers(t *testing.T) {
	s := newStubBackedXray(t, []model.UserSpec{{ID: 1, UUID: uuidA}, {ID: 2, UUID: uuidB}})
	s.um.addErr[userEmail(3)] = errors.New("injected AddUser failure")

	desired := []model.UserSpec{{ID: 2, UUID: uuidB}, {ID: 3, UUID: uuidC}}
	added, removed, err := s.x.UpdateUsers(desired)
	if err != nil {
		t.Fatalf("UpdateUsers() error = %v, want recovery through a controlled rebuild", err)
	}
	if added != 1 || removed != 1 {
		t.Fatalf("counts = (%d, %d), want the completed transition (1, 1)", added, removed)
	}
	if !s.rebuilt() || !s.x.IsRunning() {
		t.Fatal("a failed native add must be recovered by rebuilding the instance")
	}
	// The stub saw the removal succeed and the addition fail; the rebuilt
	// instance holds exactly the desired set.
	if ops := s.um.operations(); !sameStrings(ops, []string{"remove " + userEmail(1), "add " + userEmail(3)}) {
		t.Fatalf("native operations = %v", ops)
	}
	if got, want := s.realAccountEmails(t), emailsOf(desired...); !sameStrings(got, want) {
		t.Fatalf("rebuilt instance holds %v, want %v", got, want)
	}
	if got := bookkeeping(s.x); !sameUsers(got, desired) {
		t.Fatalf("bookkeeping = %v, want %v", got, desired)
	}
}

func TestXrayUpdateUsersAddFailureWithoutRebuildIsAnError(t *testing.T) {
	s := newStubBackedXray(t, []model.UserSpec{{ID: 1, UUID: uuidA}, {ID: 2, UUID: uuidB}})
	s.um.addErr[userEmail(3)] = errors.New("injected AddUser failure")
	s.unrebuildable()

	added, removed, err := s.x.UpdateUsers([]model.UserSpec{{ID: 2, UUID: uuidB}, {ID: 3, UUID: uuidC}})
	if err == nil {
		t.Fatal("a native add failure that could not be recovered was reported as success")
	}
	if added != 0 || removed != 0 {
		t.Fatalf("counts = (%d, %d), want (0, 0) on failure", added, removed)
	}
	if s.x.IsRunning() {
		t.Fatal("after a failed rebuild the kernel must not keep accepting connections with a mixed account set")
	}
	// The snapshot records what really happened: user 1 is gone, user 3 was
	// never accepted.
	if got, want := bookkeeping(s.x), []model.UserSpec{{ID: 2, UUID: uuidB}}; !sameUsers(got, want) {
		t.Fatalf("bookkeeping = %v, want the partially applied set %v", got, want)
	}
	assertBookkeepingMatchesStub(t, s)
}

func TestXrayUpdateUsersRemoveFailureStopsBeforeAddingAndIsAnError(t *testing.T) {
	current := []model.UserSpec{{ID: 1, UUID: uuidA}, {ID: 2, UUID: uuidB}}
	s := newStubBackedXray(t, current)
	s.um.removeErr[userEmail(1)] = errors.New("injected RemoveUser failure")
	s.unrebuildable()

	_, _, err := s.x.UpdateUsers([]model.UserSpec{{ID: 2, UUID: uuidB}, {ID: 3, UUID: uuidC}})
	if err == nil {
		t.Fatal("a removal that left the account in place was reported as success")
	}
	if ops := s.um.operations(); !sameStrings(ops, []string{"remove " + userEmail(1)}) {
		t.Fatalf("native operations = %v, want the update to stop at the failed removal", ops)
	}
	if got := bookkeeping(s.x); !sameUsers(got, current) {
		t.Fatalf("bookkeeping = %v, want unchanged %v: the kernel still holds the old account", got, current)
	}
	assertBookkeepingMatchesStub(t, s)
	if s.x.IsRunning() {
		t.Fatal("the kernel must stop rather than keep serving a revoked credential")
	}
}

func TestXrayUpdateUsersPartialFailureRecordsExactlyWhatSucceeded(t *testing.T) {
	s := newStubBackedXray(t, []model.UserSpec{{ID: 1, UUID: uuidA}, {ID: 2, UUID: uuidB}, {ID: 3, UUID: uuidC}})
	s.um.addErr[userEmail(5)] = errors.New("injected AddUser failure")
	s.unrebuildable()

	desired := []model.UserSpec{{ID: 1, UUID: uuidA}, {ID: 4, UUID: uuidD}, {ID: 5, UUID: uuidE}, {ID: 6, UUID: uuidB}}
	added, removed, err := s.x.UpdateUsers(desired)
	if err == nil {
		t.Fatal("partial success was reported as success")
	}
	if added != 0 || removed != 0 {
		t.Fatalf("counts = (%d, %d), want (0, 0) on failure", added, removed)
	}
	want := []string{"remove " + userEmail(2), "remove " + userEmail(3), "add " + userEmail(4), "add " + userEmail(5)}
	if ops := s.um.operations(); !sameStrings(ops, want) {
		t.Fatalf("native operations = %v, want %v (user 6 never attempted)", ops, want)
	}
	if got, want := bookkeeping(s.x), []model.UserSpec{{ID: 1, UUID: uuidA}, {ID: 4, UUID: uuidD}}; !sameUsers(got, want) {
		t.Fatalf("bookkeeping = %v, want exactly the accounts the manager holds %v", got, want)
	}
	assertBookkeepingMatchesStub(t, s)
}

func TestXrayUpdateUsersRotationRemovesOldCredentialOnce(t *testing.T) {
	s := newStubBackedXray(t, []model.UserSpec{{ID: 1, UUID: uuidA}, {ID: 2, UUID: uuidB}})

	desired := []model.UserSpec{{ID: 1, UUID: uuidC}, {ID: 2, UUID: uuidB}}
	added, removed, err := s.x.UpdateUsers(desired)
	if err != nil {
		t.Fatalf("UpdateUsers() error = %v", err)
	}
	if added != 1 || removed != 1 {
		t.Fatalf("counts = (%d, %d), want (1, 1)", added, removed)
	}
	if ops := s.um.operations(); !sameStrings(ops, []string{"remove " + userEmail(1), "add " + userEmail(1)}) {
		t.Fatalf("native operations = %v, want exactly one removal before the addition", ops)
	}
	if s.rebuilt() {
		t.Fatal("a normal rotation must stay on the hitless UserManager path")
	}
	account, ok := s.um.GetUser(context.Background(), userEmail(1)).Account.(*vless.MemoryAccount)
	if !ok || account.ID.String() != uuidC {
		t.Fatalf("rotated account = %+v, want the new credential", account)
	}
	if got := bookkeeping(s.x); !sameUsers(got, desired) {
		t.Fatalf("bookkeeping = %v, want %v", got, desired)
	}
	assertBookkeepingMatchesStub(t, s)
}

func TestXrayUpdateUsersTreatsVerifiedAbsentAccountAsRemoved(t *testing.T) {
	// Bookkeeping drift: the kernel knows user 1 but the manager never held it.
	s := newStubBackedXray(t, []model.UserSpec{{ID: 2, UUID: uuidB}})
	s.x.users = []model.UserSpec{{ID: 1, UUID: uuidA}, {ID: 2, UUID: uuidB}}

	desired := []model.UserSpec{{ID: 2, UUID: uuidB}, {ID: 3, UUID: uuidC}}
	added, removed, err := s.x.UpdateUsers(desired)
	if err != nil {
		t.Fatalf("UpdateUsers() error = %v, want an absent account to count as already removed", err)
	}
	if added != 1 || removed != 0 {
		t.Fatalf("counts = (%d, %d), want (1, 0): nothing was removed natively", added, removed)
	}
	if s.rebuilt() {
		t.Fatal("an already absent account must not trigger a rebuild")
	}
	if got := bookkeeping(s.x); !sameUsers(got, desired) {
		t.Fatalf("bookkeeping = %v, want %v", got, desired)
	}
	assertBookkeepingMatchesStub(t, s)
}

func TestXrayUpdateUsersRemoveFailureWithPresentAccountIsNotIdempotent(t *testing.T) {
	s := newStubBackedXray(t, []model.UserSpec{{ID: 1, UUID: uuidA}, {ID: 2, UUID: uuidB}})
	// The manager reports "not found" but still holds the account.
	s.um.removeErr[userEmail(1)] = fmt.Errorf("User %s not found.", userEmail(1))
	s.unrebuildable()

	if _, _, err := s.x.UpdateUsers([]model.UserSpec{{ID: 2, UUID: uuidB}}); err == nil {
		t.Fatal("a removal error must only be forgiven when the account is provably absent")
	}
	if got := s.um.emails(); !sameStrings(got, []string{userEmail(1), userEmail(2)}) {
		t.Fatalf("stub state = %v", got)
	}
	assertBookkeepingMatchesStub(t, s)
}

func TestXrayAddUsersNativeFailureIsNotReportedAsSuccess(t *testing.T) {
	current := []model.UserSpec{{ID: 1, UUID: uuidA}}
	s := newStubBackedXray(t, current)
	s.um.addErr[userEmail(2)] = errors.New("injected AddUser failure")
	s.unrebuildable()

	added, err := s.x.AddUsers([]model.UserSpec{{ID: 2, UUID: uuidB}})
	if err == nil || added != 0 {
		t.Fatalf("AddUsers() = (%d, %v), want an error and no additions", added, err)
	}
	if got := bookkeeping(s.x); !sameUsers(got, current) {
		t.Fatalf("bookkeeping = %v, want unchanged %v", got, current)
	}
	assertBookkeepingMatchesStub(t, s)
}

func TestXrayAddUsersNativeFailureRebuildsWithMergedUsers(t *testing.T) {
	s := newStubBackedXray(t, []model.UserSpec{{ID: 1, UUID: uuidA}})
	s.um.addErr[userEmail(3)] = errors.New("injected AddUser failure")

	added, err := s.x.AddUsers([]model.UserSpec{{ID: 2, UUID: uuidB}, {ID: 3, UUID: uuidC}})
	if err != nil {
		t.Fatalf("AddUsers() error = %v, want recovery through a controlled rebuild", err)
	}
	if added != 2 {
		t.Fatalf("added = %d, want 2 after the rebuild applied the merged set", added)
	}
	if !s.rebuilt() {
		t.Fatal("expected a rebuild after the native failure")
	}
	want := emailsOf(model.UserSpec{ID: 1}, model.UserSpec{ID: 2}, model.UserSpec{ID: 3})
	if got := s.realAccountEmails(t); !sameStrings(got, want) {
		t.Fatalf("rebuilt instance holds %v, want %v", got, want)
	}
	if got := emailsOf(bookkeeping(s.x)...); !sameStrings(got, want) {
		t.Fatalf("bookkeeping = %v, want %v", got, want)
	}
}

func TestXrayRemoveUsersNativeFailureIsNotReportedAsSuccess(t *testing.T) {
	current := []model.UserSpec{{ID: 1, UUID: uuidA}, {ID: 2, UUID: uuidB}}
	s := newStubBackedXray(t, current)
	s.um.removeErr[userEmail(1)] = errors.New("injected RemoveUser failure")
	s.unrebuildable()

	removed, err := s.x.RemoveUsers([]model.UserSpec{{ID: 1, UUID: uuidA}})
	if err == nil || removed != 0 {
		t.Fatalf("RemoveUsers() = (%d, %v), want an error and no removals", removed, err)
	}
	if got := bookkeeping(s.x); !sameUsers(got, current) {
		t.Fatalf("bookkeeping = %v, want unchanged %v: the revoked account is still held", got, current)
	}
	assertBookkeepingMatchesStub(t, s)
	if s.x.IsRunning() {
		t.Fatal("the kernel must stop rather than keep serving a revoked credential")
	}
}

func TestXrayRemoveUsersNativeFailureRebuildsWithRemainingUsers(t *testing.T) {
	s := newStubBackedXray(t, []model.UserSpec{{ID: 1, UUID: uuidA}, {ID: 2, UUID: uuidB}, {ID: 3, UUID: uuidC}})
	s.um.removeErr[userEmail(2)] = errors.New("injected RemoveUser failure")

	removed, err := s.x.RemoveUsers([]model.UserSpec{{ID: 1, UUID: uuidA}, {ID: 2, UUID: uuidB}})
	if err != nil {
		t.Fatalf("RemoveUsers() error = %v, want recovery through a controlled rebuild", err)
	}
	if removed != 2 {
		t.Fatalf("removed = %d, want 2 after the rebuild applied the remaining set", removed)
	}
	if got, want := s.realAccountEmails(t), []string{userEmail(3)}; !sameStrings(got, want) {
		t.Fatalf("rebuilt instance holds %v, want %v", got, want)
	}
}

func TestXrayRemoveUsersVerifiedAbsentAccountIsIdempotent(t *testing.T) {
	s := newStubBackedXray(t, []model.UserSpec{{ID: 2, UUID: uuidB}})
	s.x.users = []model.UserSpec{{ID: 1, UUID: uuidA}, {ID: 2, UUID: uuidB}}

	removed, err := s.x.RemoveUsers([]model.UserSpec{{ID: 1, UUID: uuidA}})
	if err != nil {
		t.Fatalf("RemoveUsers() error = %v, want an absent account to be treated as removed", err)
	}
	if removed != 0 {
		t.Fatalf("removed = %d, want 0: nothing was removed natively", removed)
	}
	if s.rebuilt() {
		t.Fatal("an already absent account must not trigger a rebuild")
	}
	if got, want := bookkeeping(s.x), []model.UserSpec{{ID: 2, UUID: uuidB}}; !sameUsers(got, want) {
		t.Fatalf("bookkeeping = %v, want %v", got, want)
	}
}

func TestXrayUpdateUsersLimitOnlyChangeStaysOnTheHitlessPath(t *testing.T) {
	s := newStubBackedXray(t, []model.UserSpec{{ID: 1, UUID: uuidA, SpeedLimit: 4}})

	added, removed, err := s.x.UpdateUsers([]model.UserSpec{{ID: 1, UUID: uuidA, SpeedLimit: 16, DeviceLimit: 2}})
	if err != nil || added != 0 || removed != 0 {
		t.Fatalf("UpdateUsers() = (%d, %d, %v), want (0, 0, nil)", added, removed, err)
	}
	if ops := s.um.operations(); len(ops) != 0 {
		t.Fatalf("a limit-only change must not touch the UserManager, got %v", ops)
	}
	if s.rebuilt() {
		t.Fatal("a limit-only change must not rebuild the instance")
	}
	if got := bookkeeping(s.x); len(got) != 1 || got[0].SpeedLimit != 16 || got[0].DeviceLimit != 2 {
		t.Fatalf("bookkeeping = %v, want the new limits", got)
	}
}
