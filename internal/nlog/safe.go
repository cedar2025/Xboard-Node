package nlog

import "runtime/debug"

// Go 以 recover 保护启动一个 goroutine：任何 panic 被捕获并记录堆栈，
// 不再击穿整个进程（machine 模式下一个节点的 panic 曾会带走全部节点）。
// 用于所有运行期后台入口（WS 读写泵、上报、拉取、内核回收等）。
func Go(label string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				Core().Error("goroutine panicked", "where", label, "panic", r, "stack", string(debug.Stack()))
			}
		}()
		fn()
	}()
}

// GoCtx 是 Go 的带 ctx 变体，保持调用侧签名简洁。
func GoCtx(label string, fn func()) { Go(label, fn) }
