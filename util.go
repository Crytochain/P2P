package p2p
import (
	"container/heap"
	"github.com/Cryptochain-VON/common/mclock"
)
type expHeap []expItem
type expItem struct {
	item string
	exp  mclock.AbsTime
}
func (h *expHeap) nextExpiry() mclock.AbsTime {
	return (*h)[0].exp
}
func (h *expHeap) add(item string, exp mclock.AbsTime) {
	heap.Push(h, expItem{item, exp})
}
func (h expHeap) contains(item string) bool {
	for _, v := range h {
		if v.item == item {
			return true
		}
	}
	return false
}
func (h *expHeap) expire(now mclock.AbsTime, onExp func(string)) {
	for h.Len() > 0 && h.nextExpiry() < now {
		item := heap.Pop(h)
		if onExp != nil {
			onExp(item.(expItem).item)
		}
	}
}
func (h expHeap) Len() int            { return len(h) }
func (h expHeap) Less(i, j int) bool  { return h[i].exp < h[j].exp }
func (h expHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *expHeap) Push(x interface{}) { *h = append(*h, x.(expItem)) }
func (h *expHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}
