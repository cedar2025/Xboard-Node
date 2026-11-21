package geodata

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/cedar2025/xboard-node/internal/nlog"
)

const (
	xrayGeoIPURL   = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
	xrayGeoSiteURL = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
)

var httpClient = &http.Client{Timeout: 10 * time.Minute}

func Ensure(dir string, needGeoIP, needGeoSite bool) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create geo_data_dir %q: %w", dir, err)
	}

	type entry struct {
		name string
		url  string
	}

	var files []entry
	if needGeoIP {
		files = append(files, entry{"geoip.dat", xrayGeoIPURL})
	}
	if needGeoSite {
		files = append(files, entry{"geosite.dat", xrayGeoSiteURL})
	}

	var firstErr error
	for _, f := range files {
		if err := ensureFile(dir, f.name, f.url); err != nil {
			nlog.Core().Warn("geo database auto-download failed", "file", f.name, "error", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func ensureFile(dir, name, url string) error {
	dst := filepath.Join(dir, name)
	if _, err := os.Stat(dst); err == nil {
		return nil
	}
	nlog.Core().Info("geo database missing, downloading automatically", "file", name, "url", url)
	if err := atomicDownload(dst, url); err != nil {
		return err
	}
	if fi, err := os.Stat(dst); err == nil {
		nlog.Core().Info("geo database ready", "file", name, "size_kb", fi.Size()/1024)
	}
	return nil
}

func atomicDownload(dst, url string) error {
	resp, err := httpClient.Get(url)
	if err != nil {
		return fmt.Errorf("http get %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status from %s: %s", url, resp.Status)
	}

	tmp := dst + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmp)

	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return fmt.Errorf("write geo database: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		return fmt.Errorf("rename to destination: %w", err)
	}
	return nil
}
