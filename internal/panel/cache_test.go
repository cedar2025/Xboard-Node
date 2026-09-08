package panel

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
)

func TestInflightResponseCannotUndoETagInvalidation(t *testing.T) {
	for _, nodeConfig := range []bool{true, false} {
		name := "users"
		if nodeConfig {
			name = "config"
		}
		t.Run(name, func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			var calls atomic.Int32
			secondHeader := make(chan string, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == 1 {
					close(started)
					<-release
				} else {
					secondHeader <- r.Header.Get("If-None-Match")
				}
				w.Header().Set("ETag", "old-response")
				if nodeConfig {
					w.Write([]byte("{\"protocol\":\"vless\",\"server_port\":12345}"))
				} else {
					w.Write([]byte("{\"users\":[]}"))
				}
			}))
			defer server.Close()
			defer unblock()
			c := NewClient(config.PanelConfig{URL: server.URL, NodeID: 1})
			fetch := func() error {
				if nodeConfig {
					_, e := c.GetConfig()
					return e
				}
				_, e := c.GetUsers()
				return e
			}
			done := make(chan error, 1)
			go func() { done <- fetch() }()
			<-started
			c.ResetETags()
			unblock()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if err := fetch(); err != nil {
				t.Fatal(err)
			}
			if h := <-secondHeader; h != "" {
				t.Fatalf("an old response restored the invalidated ETag: %q", h)
			}
		})
	}
}

func TestConcurrentETagRefreshAndInvalidation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", "users-v1")
		w.Write([]byte("{\"users\":[]}"))
	}))
	defer server.Close()
	c := NewClient(config.PanelConfig{URL: server.URL, NodeID: 1})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			c.ResetETags()
			c.ResetConfigETag()
		}
	}()
	for i := 0; i < 30; i++ {
		if _, err := c.GetUsers(); err != nil {
			t.Fatal(err)
		}
	}
	<-done
}
