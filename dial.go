package p2p
import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	mrand "math/rand"
	"net"
	"sync"
	"time"
	"github.com/Cryptochain-VON/common/mclock"
	"github.com/Cryptochain-VON/log"
	"github.com/Cryptochain-VON/p2p/enode"
	"github.com/Cryptochain-VON/p2p/netutil"
)
const (
	dialHistoryExpiration = inboundThrottleTime + 5*time.Second
	dialStatsLogInterval = 10 * time.Second 
	dialStatsPeerLimit   = 3                
	initialResolveDelay = 60 * time.Second
	maxResolveDelay     = time.Hour
)
type NodeDialer interface {
	Dial(context.Context, *enode.Node) (net.Conn, error)
}
type nodeResolver interface {
	Resolve(*enode.Node) *enode.Node
}
type tcpDialer struct {
	d *net.Dialer
}
func (t tcpDialer) Dial(ctx context.Context, dest *enode.Node) (net.Conn, error) {
	return t.d.DialContext(ctx, "tcp", nodeAddr(dest).String())
}
func nodeAddr(n *enode.Node) net.Addr {
	return &net.TCPAddr{IP: n.IP(), Port: n.TCP()}
}
var (
	errSelf             = errors.New("is self")
	errAlreadyDialing   = errors.New("already dialing")
	errAlreadyConnected = errors.New("already connected")
	errRecentlyDialed   = errors.New("recently dialed")
	errNotWhitelisted   = errors.New("not contained in netrestrict whitelist")
	errNoPort           = errors.New("node does not provide TCP port")
)
type dialScheduler struct {
	dialConfig
	setupFunc   dialSetupFunc
	wg          sync.WaitGroup
	cancel      context.CancelFunc
	ctx         context.Context
	nodesIn     chan *enode.Node
	doneCh      chan *dialTask
	addStaticCh chan *enode.Node
	remStaticCh chan *enode.Node
	addPeerCh   chan *conn
	remPeerCh   chan *conn
	dialing   map[enode.ID]*dialTask 
	peers     map[enode.ID]connFlag  
	dialPeers int                    
	static     map[enode.ID]*dialTask
	staticPool []*dialTask
	history          expHeap
	historyTimer     mclock.Timer
	historyTimerTime mclock.AbsTime
	lastStatsLog     mclock.AbsTime
	doneSinceLastLog int
}
type dialSetupFunc func(net.Conn, connFlag, *enode.Node) error
type dialConfig struct {
	self           enode.ID         
	maxDialPeers   int              
	maxActiveDials int              
	netRestrict    *netutil.Netlist 
	resolver       nodeResolver
	dialer         NodeDialer
	log            log.Logger
	clock          mclock.Clock
	rand           *mrand.Rand
}
func (cfg dialConfig) withDefaults() dialConfig {
	if cfg.maxActiveDials == 0 {
		cfg.maxActiveDials = defaultMaxPendingPeers
	}
	if cfg.log == nil {
		cfg.log = log.Root()
	}
	if cfg.clock == nil {
		cfg.clock = mclock.System{}
	}
	if cfg.rand == nil {
		seedb := make([]byte, 8)
		crand.Read(seedb)
		seed := int64(binary.BigEndian.Uint64(seedb))
		cfg.rand = mrand.New(mrand.NewSource(seed))
	}
	return cfg
}
func newDialScheduler(config dialConfig, it enode.Iterator, setupFunc dialSetupFunc) *dialScheduler {
	d := &dialScheduler{
		dialConfig:  config.withDefaults(),
		setupFunc:   setupFunc,
		dialing:     make(map[enode.ID]*dialTask),
		static:      make(map[enode.ID]*dialTask),
		peers:       make(map[enode.ID]connFlag),
		doneCh:      make(chan *dialTask),
		nodesIn:     make(chan *enode.Node),
		addStaticCh: make(chan *enode.Node),
		remStaticCh: make(chan *enode.Node),
		addPeerCh:   make(chan *conn),
		remPeerCh:   make(chan *conn),
	}
	d.lastStatsLog = d.clock.Now()
	d.ctx, d.cancel = context.WithCancel(context.Background())
	d.wg.Add(2)
	go d.readNodes(it)
	go d.loop(it)
	return d
}
func (d *dialScheduler) stop() {
	d.cancel()
	d.wg.Wait()
}
func (d *dialScheduler) addStatic(n *enode.Node) {
	select {
	case d.addStaticCh <- n:
	case <-d.ctx.Done():
	}
}
func (d *dialScheduler) removeStatic(n *enode.Node) {
	select {
	case d.remStaticCh <- n:
	case <-d.ctx.Done():
	}
}
func (d *dialScheduler) peerAdded(c *conn) {
	select {
	case d.addPeerCh <- c:
	case <-d.ctx.Done():
	}
}
func (d *dialScheduler) peerRemoved(c *conn) {
	select {
	case d.remPeerCh <- c:
	case <-d.ctx.Done():
	}
}
func (d *dialScheduler) loop(it enode.Iterator) {
	var (
		nodesCh    chan *enode.Node
		historyExp = make(chan struct{}, 1)
	)
loop:
	for {
		slots := d.freeDialSlots()
		slots -= d.startStaticDials(slots)
		if slots > 0 {
			nodesCh = d.nodesIn
		} else {
			nodesCh = nil
		}
		d.rearmHistoryTimer(historyExp)
		d.logStats()
		select {
		case node := <-nodesCh:
			if err := d.checkDial(node); err != nil {
				d.log.Trace("Discarding dial candidate", "id", node.ID(), "ip", node.IP(), "reason", err)
			} else {
				d.startDial(newDialTask(node, dynDialedConn))
			}
		case task := <-d.doneCh:
			id := task.dest.ID()
			delete(d.dialing, id)
			d.updateStaticPool(id)
			d.doneSinceLastLog++
		case c := <-d.addPeerCh:
			if c.is(dynDialedConn) || c.is(staticDialedConn) {
				d.dialPeers++
			}
			id := c.node.ID()
			d.peers[id] = c.flags
			task := d.static[id]
			if task != nil && task.staticPoolIndex >= 0 {
				d.removeFromStaticPool(task.staticPoolIndex)
			}
		case c := <-d.remPeerCh:
			if c.is(dynDialedConn) || c.is(staticDialedConn) {
				d.dialPeers--
			}
			delete(d.peers, c.node.ID())
			d.updateStaticPool(c.node.ID())
		case node := <-d.addStaticCh:
			id := node.ID()
			_, exists := d.static[id]
			d.log.Trace("Adding static node", "id", id, "ip", node.IP(), "added", !exists)
			if exists {
				continue loop
			}
			task := newDialTask(node, staticDialedConn)
			d.static[id] = task
			if d.checkDial(node) == nil {
				d.addToStaticPool(task)
			}
		case node := <-d.remStaticCh:
			id := node.ID()
			task := d.static[id]
			d.log.Trace("Removing static node", "id", id, "ok", task != nil)
			if task != nil {
				delete(d.static, id)
				if task.staticPoolIndex >= 0 {
					d.removeFromStaticPool(task.staticPoolIndex)
				}
			}
		case <-historyExp:
			d.expireHistory()
		case <-d.ctx.Done():
			it.Close()
			break loop
		}
	}
	d.stopHistoryTimer(historyExp)
	for range d.dialing {
		<-d.doneCh
	}
	d.wg.Done()
}
func (d *dialScheduler) readNodes(it enode.Iterator) {
	defer d.wg.Done()
	for it.Next() {
		select {
		case d.nodesIn <- it.Node():
		case <-d.ctx.Done():
		}
	}
}
func (d *dialScheduler) logStats() {
	now := d.clock.Now()
	if d.lastStatsLog.Add(dialStatsLogInterval) > now {
		return
	}
	if d.dialPeers < dialStatsPeerLimit && d.dialPeers < d.maxDialPeers {
		d.log.Info("Looking for peers", "peercount", len(d.peers), "tried", d.doneSinceLastLog, "static", len(d.static))
	}
	d.doneSinceLastLog = 0
	d.lastStatsLog = now
}
func (d *dialScheduler) rearmHistoryTimer(ch chan struct{}) {
	if len(d.history) == 0 || d.historyTimerTime == d.history.nextExpiry() {
		return
	}
	d.stopHistoryTimer(ch)
	d.historyTimerTime = d.history.nextExpiry()
	timeout := time.Duration(d.historyTimerTime - d.clock.Now())
	d.historyTimer = d.clock.AfterFunc(timeout, func() { ch <- struct{}{} })
}
func (d *dialScheduler) stopHistoryTimer(ch chan struct{}) {
	if d.historyTimer != nil && !d.historyTimer.Stop() {
		<-ch
	}
}
func (d *dialScheduler) expireHistory() {
	d.historyTimer.Stop()
	d.historyTimer = nil
	d.historyTimerTime = 0
	d.history.expire(d.clock.Now(), func(hkey string) {
		var id enode.ID
		copy(id[:], hkey)
		d.updateStaticPool(id)
	})
}
func (d *dialScheduler) freeDialSlots() int {
	slots := (d.maxDialPeers - d.dialPeers) * 2
	if slots > d.maxActiveDials {
		slots = d.maxActiveDials
	}
	free := slots - len(d.dialing)
	return free
}
func (d *dialScheduler) checkDial(n *enode.Node) error {
	if n.ID() == d.self {
		return errSelf
	}
	if n.IP() != nil && n.TCP() == 0 {
		return errNoPort
	}
	if _, ok := d.dialing[n.ID()]; ok {
		return errAlreadyDialing
	}
	if _, ok := d.peers[n.ID()]; ok {
		return errAlreadyConnected
	}
	if d.netRestrict != nil && !d.netRestrict.Contains(n.IP()) {
		return errNotWhitelisted
	}
	if d.history.contains(string(n.ID().Bytes())) {
		return errRecentlyDialed
	}
	return nil
}
func (d *dialScheduler) startStaticDials(n int) (started int) {
	for started = 0; started < n && len(d.staticPool) > 0; started++ {
		idx := d.rand.Intn(len(d.staticPool))
		task := d.staticPool[idx]
		d.startDial(task)
		d.removeFromStaticPool(idx)
	}
	return started
}
func (d *dialScheduler) updateStaticPool(id enode.ID) {
	task, ok := d.static[id]
	if ok && task.staticPoolIndex < 0 && d.checkDial(task.dest) == nil {
		d.addToStaticPool(task)
	}
}
func (d *dialScheduler) addToStaticPool(task *dialTask) {
	if task.staticPoolIndex >= 0 {
		panic("attempt to add task to staticPool twice")
	}
	d.staticPool = append(d.staticPool, task)
	task.staticPoolIndex = len(d.staticPool) - 1
}
func (d *dialScheduler) removeFromStaticPool(idx int) {
	task := d.staticPool[idx]
	end := len(d.staticPool) - 1
	d.staticPool[idx] = d.staticPool[end]
	d.staticPool[idx].staticPoolIndex = idx
	d.staticPool[end] = nil
	d.staticPool = d.staticPool[:end]
	task.staticPoolIndex = -1
}
func (d *dialScheduler) startDial(task *dialTask) {
	d.log.Trace("Starting p2p dial", "id", task.dest.ID(), "ip", task.dest.IP(), "flag", task.flags)
	hkey := string(task.dest.ID().Bytes())
	d.history.add(hkey, d.clock.Now().Add(dialHistoryExpiration))
	d.dialing[task.dest.ID()] = task
	go func() {
		task.run(d)
		d.doneCh <- task
	}()
}
type dialTask struct {
	staticPoolIndex int
	flags           connFlag
	dest         *enode.Node
	lastResolved mclock.AbsTime
	resolveDelay time.Duration
}
func newDialTask(dest *enode.Node, flags connFlag) *dialTask {
	return &dialTask{dest: dest, flags: flags, staticPoolIndex: -1}
}
type dialError struct {
	error
}
func (t *dialTask) run(d *dialScheduler) {
	if t.needResolve() && !t.resolve(d) {
		return
	}
	err := t.dial(d, t.dest)
	if err != nil {
		if _, ok := err.(*dialError); ok && t.flags&staticDialedConn != 0 {
			if t.resolve(d) {
				t.dial(d, t.dest)
			}
		}
	}
}
func (t *dialTask) needResolve() bool {
	return t.flags&staticDialedConn != 0 && t.dest.IP() == nil
}
func (t *dialTask) resolve(d *dialScheduler) bool {
	if d.resolver == nil {
		return false
	}
	if t.resolveDelay == 0 {
		t.resolveDelay = initialResolveDelay
	}
	if t.lastResolved > 0 && time.Duration(d.clock.Now()-t.lastResolved) < t.resolveDelay {
		return false
	}
	resolved := d.resolver.Resolve(t.dest)
	t.lastResolved = d.clock.Now()
	if resolved == nil {
		t.resolveDelay *= 2
		if t.resolveDelay > maxResolveDelay {
			t.resolveDelay = maxResolveDelay
		}
		d.log.Debug("Resolving node failed", "id", t.dest.ID(), "newdelay", t.resolveDelay)
		return false
	}
	t.resolveDelay = initialResolveDelay
	t.dest = resolved
	d.log.Debug("Resolved node", "id", t.dest.ID(), "addr", &net.TCPAddr{IP: t.dest.IP(), Port: t.dest.TCP()})
	return true
}
func (t *dialTask) dial(d *dialScheduler, dest *enode.Node) error {
	fd, err := d.dialer.Dial(d.ctx, t.dest)
	if err != nil {
		d.log.Trace("Dial error", "id", t.dest.ID(), "addr", nodeAddr(t.dest), "conn", t.flags, "err", cleanupDialErr(err))
		return &dialError{err}
	}
	mfd := newMeteredConn(fd, false, &net.TCPAddr{IP: dest.IP(), Port: dest.TCP()})
	return d.setupFunc(mfd, t.flags, dest)
}
func (t *dialTask) String() string {
	id := t.dest.ID()
	return fmt.Sprintf("%v %x %v:%d", t.flags, id[:8], t.dest.IP(), t.dest.TCP())
}
func cleanupDialErr(err error) error {
	if netErr, ok := err.(*net.OpError); ok && netErr.Op == "dial" {
		return netErr.Err
	}
	return err
}
