package monitor

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Prometheus 导出注册表：各节点 Service 在上报周期把已采集的指标发布到这里，
// 健康服务器（/metrics）渲染文本格式。同一 metric 名下按 labels 维度区分实例/节点。
var (
	exportMu   sync.RWMutex
	exportData = map[string]map[string]float64{} // metric → labelSet → value
	exportHelp = map[string]string{}
)

// ExportPublish 覆盖式发布某个 labelSet 下的一组指标（同 labelSet 旧值被替换）。
func ExportPublish(labelSet string, metrics map[string]interface{}, help map[string]string) {
	exportMu.Lock()
	defer exportMu.Unlock()
	for name, v := range metrics {
		var f float64
		switch n := v.(type) {
		case uint64:
			f = float64(n)
		case int:
			f = float64(n)
		case int64:
			f = float64(n)
		case uint:
			f = float64(n)
		case float64:
			f = n
		case bool:
			if n {
				f = 1
			}
		default:
			continue
		}
		if exportData[name] == nil {
			exportData[name] = map[string]float64{}
		}
		exportData[name][labelSet] = f
		if h, ok := help[name]; ok {
			exportHelp[name] = h
		}
	}
}

// ExportDrop 移除某个 labelSet 的全部序列（实例下线时调用）。
func ExportDrop(labelSet string) {
	exportMu.Lock()
	defer exportMu.Unlock()
	for name, series := range exportData {
		delete(series, labelSet)
		if len(series) == 0 {
			delete(exportData, name)
		}
	}
}

// RenderPrometheus 输出 Prometheus 文本展示格式（按 metric 名与 label 排序，保证输出稳定）。
func RenderPrometheus() string {
	exportMu.RLock()
	defer exportMu.RUnlock()
	var b strings.Builder
	names := make([]string, 0, len(exportData))
	for name := range exportData {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		series := exportData[name]
		if len(series) == 0 {
			continue
		}
		if h, ok := exportHelp[name]; ok {
			fmt.Fprintf(&b, "# HELP %s %s\n", name, h)
		}
		fmt.Fprintf(&b, "# TYPE %s gauge\n", name)
		labels := make([]string, 0, len(series))
		for ls := range series {
			labels = append(labels, ls)
		}
		sort.Strings(labels)
		for _, ls := range labels {
			fmt.Fprintf(&b, "%s{%s} %v\n", name, ls, series[ls])
		}
	}
	return b.String()
}
