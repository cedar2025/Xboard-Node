package kernel

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/cedar2025/xboard-node/internal/nlog"
	"gopkg.in/yaml.v3"
)

// customConfigCache caches parsed custom config to avoid repeated file I/O + parsing.
var customConfigCache struct {
	sync.Mutex
	path string
	size int64
	data map[string]any
}

// LoadCustomConfig reads a custom config file (JSON or YAML) and returns it
// as a generic map. Returns nil if path is empty or file does not exist.
// Results are cached: re-parsing only occurs when the file's size changes.
func LoadCustomConfig(path string) (map[string]any, error) {
	if path == "" {
		return nil, nil
	}

	// Check cache.
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			nlog.Core().Warn("custom config file not found, skipping", "path", path)
			return nil, nil
		}
		return nil, fmt.Errorf("stat custom config %s: %w", path, err)
	}

	customConfigCache.Lock()
	if path == customConfigCache.path && info.Size() == customConfigCache.size && customConfigCache.data != nil {
		result := customConfigCache.data
		customConfigCache.Unlock()
		return result, nil
	}
	customConfigCache.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read custom config %s: %w", path, err)
	}

	if len(data) == 0 {
		return nil, nil
	}

	result := make(map[string]any)

	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "{") {
		if err := json.Unmarshal(data, &result); err != nil {
			return nil, fmt.Errorf("parse custom config as JSON: %w", err)
		}
	} else {
		if err := yaml.Unmarshal(data, &result); err != nil {
			return nil, fmt.Errorf("parse custom config as YAML: %w", err)
		}
	}

	// Update cache.
	customConfigCache.Lock()
	customConfigCache.path = path
	customConfigCache.size = info.Size()
	customConfigCache.data = result
	customConfigCache.Unlock()

	nlog.Core().Info("loaded custom config", "path", path, "keys", mapKeys(result))
	return result, nil
}

// MergeAppendList appends items from src list into dst, returning the merged list.
// Each item is converted to map[string]any for JSON-marshal compatibility.
func MergeAppendList(dst []map[string]any, srcRaw any) []map[string]any {
	srcList, ok := toSliceOfMaps(srcRaw)
	if !ok {
		return dst
	}
	return append(dst, srcList...)
}

// MergePrependList prepends items from src list before dst items.
func MergePrependList(dst []map[string]any, srcRaw any) []map[string]any {
	srcList, ok := toSliceOfMaps(srcRaw)
	if !ok {
		return dst
	}
	return append(srcList, dst...)
}

func toSliceOfMaps(v any) ([]map[string]any, bool) {
	if v == nil {
		return nil, false
	}
	switch items := v.(type) {
	case []any:
		result := make([]map[string]any, 0, len(items))
		for _, item := range items {
			if m, ok := toMap(item); ok {
				result = append(result, m)
			}
		}
		return result, len(result) > 0
	case []map[string]any:
		return items, len(items) > 0
	default:
		return nil, false
	}
}

func toMap(v any) (map[string]any, bool) {
	switch m := v.(type) {
	case map[string]any:
		return m, true
	case map[any]any:
		result := make(map[string]any, len(m))
		for k, val := range m {
			result[fmt.Sprint(k)] = val
		}
		return result, true
	default:
		return nil, false
	}
}

func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
