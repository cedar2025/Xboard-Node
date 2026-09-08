package panel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/nlog"
	"github.com/go-viper/mapstructure/v2"
)

var (
	trafficMapPool = sync.Pool{New: func() interface{} { return make(map[string][2]int64) }}
	aliveMapPool   = sync.Pool{New: func() interface{} { return make(map[string][]string) }}
	onlineMapPool  = sync.Pool{New: func() interface{} { return make(map[string]int) }}
)

// Client communicates with the Xboard panel API.
// When machineID > 0 the client uses machine-level authentication
// (machine_id + token) instead of the legacy (token + node_type) scheme.
type Client struct {
	baseURL    string
	token      string
	nodeID     int
	nodeType   string
	machineID  int
	httpClient *http.Client

	cacheMu         sync.Mutex
	cacheGeneration uint64
	configETag      string
	userETag        string

	apiSuccess atomic.Uint64
	apiFailure atomic.Uint64
}

// NewClient creates a new panel API client.
func NewClient(cfg config.PanelConfig) *Client {
	return &Client{
		baseURL:   strings.TrimRight(cfg.URL, "/"),
		token:     cfg.Token,
		nodeID:    cfg.NodeID,
		nodeType:  cfg.NodeType,
		machineID: cfg.MachineID,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

// ForNode returns a new client bound to a specific node_id, sharing the
// same base URL, auth and HTTP transport. ETags and metric counters start fresh.
func (c *Client) ForNode(nodeID int) *Client {
	return &Client{
		baseURL:    c.baseURL,
		token:      c.token,
		nodeID:     nodeID,
		nodeType:   c.nodeType,
		machineID:  c.machineID,
		httpClient: c.httpClient,
	}
}

// ResetConfigETag clears the cached config ETag so the next GetConfig call
// returns a full response instead of 304. Used by machine mode after a
// pre-fetch to probe the transport type.
func (c *Client) ResetConfigETag() {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	c.cacheGeneration++
	c.configETag = ""
}

func (c *Client) cachedETag(nodeConfig bool) (string, uint64) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	if nodeConfig {
		return c.configETag, c.cacheGeneration
	}
	return c.userETag, c.cacheGeneration
}

func (c *Client) rememberETag(nodeConfig bool, etag string, generation uint64) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	// A response already in flight cannot undo a forced full resync.
	if generation != c.cacheGeneration {
		return
	}
	if nodeConfig {
		c.configETag = etag
	} else {
		c.userETag = etag
	}
}

// Handshake calls the new v2 API to get WS config + initial data in one shot.
func (c *Client) Handshake() (*HandshakeResponse, error) {
	resp, err := c.doRequest("POST", "/api/v2/server/handshake", nil, "")
	if err != nil {
		return nil, fmt.Errorf("handshake: %w", err)
	}
	defer drainAndClose(resp.Body)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("handshake status %d: %s", resp.StatusCode, body)
	}

	var hs HandshakeResponse
	if err := json.NewDecoder(resp.Body).Decode(&hs); err != nil {
		return nil, fmt.Errorf("decode handshake: %w", err)
	}
	return &hs, nil
}

// Report sends consolidated traffic + alive + status data to the panel.
// The optional metrics map allows the node to submit richer telemetry
// (active connections, per-core CPU, GC stats, limiter hits, etc.)
// without changing the core schema of status.
func (c *Client) Report(traffic map[int][2]int64, alive map[int][]string, online map[int]int,
	cpu float64, mem, swap, disk [2]uint64,
	metrics map[string]interface{},
) error {
	payload := make(map[string]interface{})

	if len(traffic) > 0 {
		t := trafficMapPool.Get().(map[string][2]int64)
		for uid, d := range traffic {
			t[strconv.Itoa(uid)] = d
		}
		payload["traffic"] = t
		defer func() {
			for k := range t {
				delete(t, k)
			}
			trafficMapPool.Put(t)
		}()
	}

	if len(alive) > 0 {
		a := aliveMapPool.Get().(map[string][]string)
		for uid, ips := range alive {
			a[strconv.Itoa(uid)] = ips
		}
		payload["alive"] = a
		defer func() {
			for k := range a {
				delete(a, k)
			}
			aliveMapPool.Put(a)
		}()
	}

	if len(online) > 0 {
		o := onlineMapPool.Get().(map[string]int)
		for uid, count := range online {
			o[strconv.Itoa(uid)] = count
		}
		payload["online"] = o
		defer func() {
			for k := range o {
				delete(o, k)
			}
			onlineMapPool.Put(o)
		}()
	}

	status := map[string]interface{}{
		"cpu":  cpu,
		"mem":  map[string]interface{}{"total": mem[0], "used": mem[1]},
		"swap": map[string]interface{}{"total": swap[0], "used": swap[1]},
		"disk": map[string]interface{}{"total": disk[0], "used": disk[1]},
	}
	payload["status"] = status

	if len(metrics) > 0 {
		payload["metrics"] = metrics
	}

	return c.postJSON("/api/v2/server/report", payload)
}

// decodeWeakRaw decodes an interface (from JSON map) into a struct using weak type conversion.
func decodeWeakRaw(input map[string]interface{}, output interface{}) error {
	config := &mapstructure.DecoderConfig{
		Metadata:         nil,
		Result:           output,
		WeaklyTypedInput: true,
		TagName:          "json",
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			func(f, t reflect.Type, v interface{}) (interface{}, error) {
				// Handle []interface{} -> StringOrArray
				if t == reflect.TypeOf(StringOrArray("")) && f.Kind() == reflect.Slice {
					arr, _ := v.([]interface{})
					var strs []string
					for _, x := range arr {
						if s, ok := x.(string); ok {
							strs = append(strs, s)
						}
					}
					return StringOrArray(strings.Join(strs, "\n")), nil
				}
				return v, nil
			},
			mapstructure.StringToSliceHookFunc(","),
		),
	}
	decoder, _ := mapstructure.NewDecoder(config)
	return decoder.Decode(input)
}

// configPath returns the API path for config fetching.
// Machine mode uses the v2 endpoint; legacy mode uses the v1 UniProxy endpoint.
func (c *Client) configPath() string {
	if c.machineID > 0 {
		return "/api/v2/server/config"
	}
	return "/api/v1/server/UniProxy/config"
}

// userPath returns the API path for user fetching.
func (c *Client) userPath() string {
	if c.machineID > 0 {
		return "/api/v2/server/user"
	}
	return "/api/v1/server/UniProxy/user"
}

// GetConfig fetches node configuration. Returns nil if not modified (304).
func (c *Client) GetConfig() (*NodeConfig, error) {
	etag, generation := c.cachedETag(true)
	resp, err := c.doRequest("GET", c.configPath(), nil, etag)
	if err != nil {
		return nil, fmt.Errorf("get config: %w", err)
	}
	defer drainAndClose(resp.Body)

	if resp.StatusCode == http.StatusNotModified {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, body)
	}

	var raw map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode raw config: %w", err)
	}

	var cfg NodeConfig
	// Use mapstructure for weak type conversion (string -> int, bool -> string, etc.)
	if err := decodeWeakRaw(raw, &cfg); err != nil {
		return nil, fmt.Errorf("weak decode config: %w", err)
	}

	// Basic validation
	if cfg.Protocol == "" {
		return nil, fmt.Errorf("invalid config: missing protocol")
	}

	if etag := resp.Header.Get("ETag"); etag != "" {
		c.rememberETag(true, etag, generation)
	}
	return &cfg, nil
}

// GetUsers fetches available users. Returns nil if not modified (304).
func (c *Client) GetUsers() ([]User, error) {
	etag, generation := c.cachedETag(false)
	resp, err := c.doRequest("GET", c.userPath(), nil, etag)
	if err != nil {
		return nil, fmt.Errorf("get users: %w", err)
	}
	defer drainAndClose(resp.Body)

	if resp.StatusCode == http.StatusNotModified {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, body)
	}

	var usersResp UsersResponse
	if err := json.NewDecoder(resp.Body).Decode(&usersResp); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	if etag := resp.Header.Get("ETag"); etag != "" {
		c.rememberETag(false, etag, generation)
	}
	return usersResp.Users, nil
}

// PushTraffic submits per-user traffic data
func (c *Client) PushTraffic(data map[int][2]int64) error {
	if len(data) == 0 {
		return nil
	}
	payload := make(map[string]interface{}, len(data))
	for uid, traffic := range data {
		payload[strconv.Itoa(uid)] = traffic
	}
	return c.postJSON("/api/v1/server/UniProxy/push", payload)
}

// PushAlive submits online user IPs
func (c *Client) PushAlive(data map[int][]string) error {
	if len(data) == 0 {
		return nil
	}
	payload := make(map[string]interface{}, len(data))
	for uid, ips := range data {
		payload[strconv.Itoa(uid)] = ips
	}
	return c.postJSON("/api/v1/server/UniProxy/alive", payload)
}

// PushStatus submits system status to the panel
func (c *Client) PushStatus(cpu float64, mem, swap, disk [2]uint64) error {
	payload := map[string]interface{}{
		"cpu":  cpu,
		"mem":  map[string]interface{}{"total": mem[0], "used": mem[1]},
		"swap": map[string]interface{}{"total": swap[0], "used": swap[1]},
		"disk": map[string]interface{}{"total": disk[0], "used": disk[1]},
	}
	return c.postJSON("/api/v1/server/UniProxy/status", payload)
}

// ResetETags clears cached ETags, forcing full responses
func (c *Client) ResetETags() {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	c.cacheGeneration++
	c.configETag = ""
	c.userETag = ""
}

// GetMachineNodes fetches the list of active nodes bound to this machine.
func (c *Client) GetMachineNodes() (*MachineNodesResponse, error) {
	resp, err := c.doRequest("POST", "/api/v2/server/machine/nodes", nil, "")
	if err != nil {
		return nil, fmt.Errorf("get machine nodes: %w", err)
	}
	defer drainAndClose(resp.Body)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("machine nodes status %d: %s", resp.StatusCode, body)
	}

	var out MachineNodesResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode machine nodes: %w", err)
	}
	return &out, nil
}

// ReportMachineStatus sends machine-level load metrics to the panel.
// netIn/netOut are bytes/sec; negative values mean "unavailable" (first sample).
func (c *Client) ReportMachineStatus(cpu float64, mem, swap, disk [2]uint64, netIn, netOut float64) error {
	payload := map[string]interface{}{
		"cpu":  cpu,
		"mem":  map[string]interface{}{"total": mem[0], "used": mem[1]},
		"swap": map[string]interface{}{"total": swap[0], "used": swap[1]},
		"disk": map[string]interface{}{"total": disk[0], "used": disk[1]},
	}
	if netIn >= 0 && netOut >= 0 {
		payload["net"] = map[string]interface{}{"in_speed": netIn, "out_speed": netOut}
	}
	return c.postJSON("/api/v2/server/machine/status", payload)
}

// injectAuth writes authentication fields into a payload map.
func (c *Client) injectAuth(m map[string]interface{}) {
	m["token"] = c.token
	if c.machineID > 0 {
		m["machine_id"] = c.machineID
		if c.nodeID > 0 {
			m["node_id"] = c.nodeID
		}
	} else {
		m["node_id"] = c.nodeID
		if c.nodeType != "" {
			m["node_type"] = c.nodeType
		}
	}
}

// authQuery builds URL query parameters for GET requests.
func (c *Client) authQuery() url.Values {
	q := url.Values{}
	q.Set("token", c.token)
	if c.machineID > 0 {
		q.Set("machine_id", strconv.Itoa(c.machineID))
		if c.nodeID > 0 {
			q.Set("node_id", strconv.Itoa(c.nodeID))
		}
	} else {
		q.Set("node_id", strconv.Itoa(c.nodeID))
		if c.nodeType != "" {
			q.Set("node_type", c.nodeType)
		}
	}
	return q
}

// postJSON marshals a map payload (with auth fields injected) and POSTs it.
func (c *Client) postJSON(path string, payload map[string]interface{}) error {
	c.injectAuth(payload)

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	resp, err := c.doRequest("POST", path, body, "")
	if err != nil {
		return fmt.Errorf("post %s: %w", path, err)
	}
	defer drainAndClose(resp.Body)

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("status %d: %s", resp.StatusCode, respBody)
	}
	c.apiSuccess.Add(1)
	return nil
}

func (c *Client) doRequest(method, path string, body []byte, ifNoneMatch string) (*http.Response, error) {
	fullURL := c.baseURL + path

	var bodyReader io.Reader
	if method == "GET" {
		fullURL += "?" + c.authQuery().Encode()
	} else if body != nil {
		bodyReader = bytes.NewReader(body)
	} else {
		authOnly := make(map[string]interface{})
		c.injectAuth(authOnly)
		merged, _ := json.Marshal(authOnly)
		bodyReader = bytes.NewReader(merged)
	}

	req, err := http.NewRequest(method, fullURL, bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", ifNoneMatch)
	}

	nlog.Core().Debug("panel request", "method", method, "path", path)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.apiFailure.Add(1)
		return nil, err
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		c.apiSuccess.Add(1)
	} else {
		c.apiFailure.Add(1)
	}

	nlog.Core().Debug("panel response", "method", method, "path", path, "status", resp.StatusCode)
	return resp, nil
}

// drainAndClose reads any remaining bytes (up to 512B) and closes the body.
// This allows the HTTP transport to reuse the underlying TCP connection.
func drainAndClose(body io.ReadCloser) {
	io.CopyN(io.Discard, body, 512)
	body.Close()
}

// APIMetrics holds aggregated API call statistics.
type APIMetrics struct {
	Success uint64
	Failure uint64
}

// SnapshotMetrics returns a snapshot of API metrics.
func (c *Client) SnapshotMetrics() APIMetrics {
	return APIMetrics{
		Success: c.apiSuccess.Load(),
		Failure: c.apiFailure.Load(),
	}
}
