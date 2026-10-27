package xray

import (
	"bytes"
	"encoding/base64"
	"io"
	"net"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	"github.com/sagernet/sing/common/metadata"
	ss2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
)

func TestSS2022MemoryAccountMatchesColdStart(t *testing.T) {
	for _, cipher := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"} {
		for _, credential := range []string{rotationOldUUID, rotationNewUUID, "short"} {
			t.Run(cipher+"/"+credential, func(t *testing.T) {
				nc := &model.NodeSpec{Protocol: "shadowsocks", Cipher: cipher}
				user := model.UserSpec{ID: 1, UUID: credential}
				config := buildShadowsocks(M{}, nc, []model.UserSpec{user})
				coldKey := config["settings"].(M)["clients"].([]M)[0]["password"].(string)
				account, err := toMemoryUser("shadowsocks", nc, user)
				if err != nil {
					t.Fatal(err)
				}
				hotKey := account.Account.(*ss2022.MemoryAccount).Key
				if hotKey != coldKey {
					t.Fatal("hot-update key differs from the working cold-start key")
				}
				raw, err := base64.StdEncoding.DecodeString(hotKey)
				if err != nil || len(raw) != ss2022Methods[cipher].size {
					t.Fatalf("invalid hot-update key size: %d, err=%v", len(raw), err)
				}
			})
		}
	}
}

func TestSS2022UUIDRotationAcceptsNewRejectsOld(t *testing.T) {
	for _, cipher := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"} {
		t.Run(cipher, func(t *testing.T) {
			reservation, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := reservation.Addr().String()
			port := reservation.Addr().(*net.TCPAddr).Port
			reservation.Close()
			keySize := ss2022Methods[cipher].size
			serverKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{42}, keySize))
			nc := &model.NodeSpec{Protocol: "shadowsocks", Cipher: cipher, ServerKey: serverKey, ListenIP: "127.0.0.1", ServerPort: port}
			x := New(config.KernelConfig{Type: "xray", CustomRoute: []map[string]any{{"type": "field", "ip": []string{"127.0.0.1/32"}, "outboundTag": "direct"}}})
			old := model.UserSpec{ID: 1, UUID: rotationOldUUID}
			if err := x.Start(nc, []model.UserSpec{old}, kernel.TLSCert{}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(x.Stop)
			target := rotationEchoServer(t)
			probe := func(credential string) error {
				key := make([]byte, keySize)
				copy(key, credential)
				method, err := shadowaead_2022.NewWithPassword(cipher, serverKey+":"+base64.StdEncoding.EncodeToString(key), nil)
				if err != nil {
					return err
				}
				raw, err := net.DialTimeout("tcp", addr, time.Second)
				if err != nil {
					return err
				}
				defer raw.Close()
				raw.SetDeadline(time.Now().Add(time.Second))
				conn, err := method.DialConn(raw, metadata.ParseSocksaddr(target))
				if err != nil {
					return err
				}
				payload := []byte("ss2022-uuid-probe")
				if _, err = conn.Write(payload); err != nil {
					return err
				}
				got := make([]byte, len(payload))
				_, err = io.ReadFull(conn, got)
				if err == nil && !bytes.Equal(payload, got) {
					return io.ErrUnexpectedEOF
				}
				return err
			}
			if err := probe(old.UUID); err != nil {
				t.Fatalf("cold-start credential failed: %v", err)
			}
			replacement := old
			replacement.UUID = rotationNewUUID
			if _, _, err := x.UpdateUsers([]model.UserSpec{replacement}); err != nil {
				t.Fatal(err)
			}
			if err := probe(replacement.UUID); err != nil {
				t.Fatalf("rotated SS2022 credential failed: %v", err)
			}
			if err := probe(old.UUID); err == nil {
				t.Fatal("old SS2022 credential still accepted")
			}
		})
	}
}
