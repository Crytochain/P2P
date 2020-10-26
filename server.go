package p2p
import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
	"github.com/Cryptochain-VON/common"
	"github.com/Cryptochain-VON/common/mclock"
	"github.com/Cryptochain-VON/crypto"
	"github.com/Cryptochain-VON/event"
	"github.com/Cryptochain-VON/log"
	"github.com/Cryptochain-VON/p2p/discover"
	"github.com/Cryptochain-VON/p2p/discv5"
	"github.com/Cryptochain-VON/p2p/enode"
	"github.com/Cryptochain-VON/p2p/enr"
	"github.com/Cryptochain-VON/p2p/nat"
	"github.com/Cryptochain-VON/p2p/netutil"
)
const (
	defaultDialTimeout = 15 * time.Second
	discmixTimeout = 5 * time.Second
	defaultMaxPendingPeers = 50
	defaultDialRatio       = 3
	inboundThrottleTime = 30 * time.Second
	frameReadTimeout = 30 * time.Second
	frameWriteTimeout = 20 * time.Second
)
var errServerStopped = errors.New("server stopped")
type Config struct {
	PrivateKey *ecdsa.PrivateKey `toml:"-"`
	MaxPeers int
	MaxPendingPeers int `toml:",omitempty"`
	DialRatio int `toml:",omitempty"`
	NoDiscovery bool
	DiscoveryV5 bool `toml:",omitempty"`
	Name string `toml:"-"`
	BootstrapNodes []*enode.Node
	BootstrapNodesV5 []*discv5.Node `toml:",omitempty"`
	StaticNodes []*enode.Node
	TrustedNodes []*enode.Node
	NetRestrict *netutil.Netlist `toml:",omitempty"`
	NodeDatabase string `toml:",omitempty"`
	Protocols []Protocol `toml:"-"`
	ListenAddr string
	NAT nat.Interface `toml:",omitempty"`
	Dialer NodeDialer `toml:"-"`
	NoDial bool `toml:",omitempty"`
	EnableMsgEvents bool
	Logger log.Logger `toml:",omitempty"`
	clock mclock.Clock
}
type Server struct {
	Config
	newTransport func(net.Conn) transport
	newPeerHook  func(*Peer)
	listenFunc   func(network, addr string) (net.Listener, error)
	lock    sync.Mutex 
	running bool
	listener     net.Listener
	ourHandshake *protoHandshake
	loopWG       sync.WaitGroup 
	peerFeed     event.Feed
	log          log.Logger
	nodedb    *enode.DB
	localnode *enode.LocalNode
	ntab      *discover.UDPv4
	DiscV5    *discv5.Network
	discmix   *enode.FairMix
	dialsched *dialScheduler
	quit                    chan struct{}
	addtrusted              chan *enode.Node
	removetrusted           chan *enode.Node
	peerOp                  chan peerOpFunc
	peerOpDone              chan struct{}
	delpeer                 chan peerDrop
	checkpointPostHandshake chan *conn
	checkpointAddPeer       chan *conn
	inboundHistory expHeap
}
type peerOpFunc func(map[enode.ID]*Peer)
type peerDrop struct {
	*Peer
	err       error
	requested bool 
}
type connFlag int32
const (
	dynDialedConn connFlag = 1 << iota
	staticDialedConn
	inboundConn
	trustedConn
)
type conn struct {
	fd net.Conn
	transport
	node  *enode.Node
	flags connFlag
	cont  chan error 
	caps  []Cap      
	name  string     
}
type transport interface {
	doEncHandshake(prv *ecdsa.PrivateKey, dialDest *ecdsa.PublicKey) (*ecdsa.PublicKey, error)
	doProtoHandshake(our *protoHandshake) (*protoHandshake, error)
	MsgReadWriter
	close(err error)
}
func (c *conn) String() string {
	s := c.flags.String()
	if (c.node.ID() != enode.ID{}) {
		s += " " + c.node.ID().String()
	}
	s += " " + c.fd.RemoteAddr().String()
	return s
}
func (f connFlag) String() string {
	s := ""
	if f&trustedConn != 0 {
		s += "-trusted"
	}
	if f&dynDialedConn != 0 {
		s += "-dyndial"
	}
	if f&staticDialedConn != 0 {
		s += "-staticdial"
	}
	if f&inboundConn != 0 {
		s += "-inbound"
	}
	if s != "" {
		s = s[1:]
	}
	return s
}
func (c *conn) is(f connFlag) bool {
	flags := connFlag(atomic.LoadInt32((*int32)(&c.flags)))
	return flags&f != 0
}
func (c *conn) set(f connFlag, val bool) {
	for {
		oldFlags := connFlag(atomic.LoadInt32((*int32)(&c.flags)))
		flags := oldFlags
		if val {
			flags |= f
		} else {
			flags &= ^f
		}
		if atomic.CompareAndSwapInt32((*int32)(&c.flags), int32(oldFlags), int32(flags)) {
			return
		}
	}
}
func (srv *Server) LocalNode() *enode.LocalNode {
	return srv.localnode
}
func (srv *Server) Peers() []*Peer {
	var ps []*Peer
	srv.doPeerOp(func(peers map[enode.ID]*Peer) {
		for _, p := range peers {
			ps = append(ps, p)
		}
	})
	return ps
}
func (srv *Server) PeerCount() int {
	var count int
	srv.doPeerOp(func(ps map[enode.ID]*Peer) {
		count = len(ps)
	})
	return count
}
func (srv *Server) AddPeer(node *enode.Node) {
	srv.dialsched.addStatic(node)
}
func (srv *Server) RemovePeer(node *enode.Node) {
	var (
		ch  chan *PeerEvent
		sub event.Subscription
	)
	srv.doPeerOp(func(peers map[enode.ID]*Peer) {
		srv.dialsched.removeStatic(node)
		if peer := peers[node.ID()]; peer != nil {
			ch = make(chan *PeerEvent, 1)
			sub = srv.peerFeed.Subscribe(ch)
			peer.Disconnect(DiscRequested)
		}
	})
	if ch != nil {
		defer sub.Unsubscribe()
		for ev := range ch {
			if ev.Peer == node.ID() && ev.Type == PeerEventTypeDrop {
				return
			}
		}
	}
}
func (srv *Server) AddTrustedPeer(node *enode.Node) {
	select {
	case srv.addtrusted <- node:
	case <-srv.quit:
	}
}
func (srv *Server) RemoveTrustedPeer(node *enode.Node) {
	select {
	case srv.removetrusted <- node:
	case <-srv.quit:
	}
}
func (srv *Server) SubscribeEvents(ch chan *PeerEvent) event.Subscription {
	return srv.peerFeed.Subscribe(ch)
}
func (srv *Server) Self() *enode.Node {
	srv.lock.Lock()
	ln := srv.localnode
	srv.lock.Unlock()
	if ln == nil {
		return enode.NewV4(&srv.PrivateKey.PublicKey, net.ParseIP("0.0.0.0"), 0, 0)
	}
	return ln.Node()
}
func (srv *Server) Stop() {
	srv.lock.Lock()
	if !srv.running {
		srv.lock.Unlock()
		return
	}
	srv.running = false
	if srv.listener != nil {
		srv.listener.Close()
	}
	close(srv.quit)
	srv.lock.Unlock()
	srv.loopWG.Wait()
}
type sharedUDPConn struct {
	*net.UDPConn
	unhandled chan discover.ReadPacket
}
func (s *sharedUDPConn) ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error) {
	packet, ok := <-s.unhandled
	if !ok {
		return 0, nil, errors.New("connection was closed")
	}
	l := len(packet.Data)
	if l > len(b) {
		l = len(b)
	}
	copy(b[:l], packet.Data[:l])
	return l, packet.Addr, nil
}
func (s *sharedUDPConn) Close() error {
	return nil
}
func (srv *Server) Start() (err error) {
	srv.lock.Lock()
	defer srv.lock.Unlock()
	if srv.running {
		return errors.New("server already running")
	}
	srv.running = true
	srv.log = srv.Config.Logger
	if srv.log == nil {
		srv.log = log.Root()
	}
	if srv.clock == nil {
		srv.clock = mclock.System{}
	}
	if srv.NoDial && srv.ListenAddr == "" {
		srv.log.Warn("P2P server will be useless, neither dialing nor listening")
	}
	if srv.PrivateKey == nil {
		return errors.New("Server.PrivateKey must be set to a non-nil key")
	}
	if srv.newTransport == nil {
		srv.newTransport = newRLPX
	}
	if srv.listenFunc == nil {
		srv.listenFunc = net.Listen
	}
	srv.quit = make(chan struct{})
	srv.delpeer = make(chan peerDrop)
	srv.checkpointPostHandshake = make(chan *conn)
	srv.checkpointAddPeer = make(chan *conn)
	srv.addtrusted = make(chan *enode.Node)
	srv.removetrusted = make(chan *enode.Node)
	srv.peerOp = make(chan peerOpFunc)
	srv.peerOpDone = make(chan struct{})
	if err := srv.setupLocalNode(); err != nil {
		return err
	}
	if srv.ListenAddr != "" {
		if err := srv.setupListening(); err != nil {
			return err
		}
	}
	if err := srv.setupDiscovery(); err != nil {
		return err
	}
	srv.setupDialScheduler()
	srv.loopWG.Add(1)
	go srv.run()
	return nil
}
func (srv *Server) setupLocalNode() error {
	pubkey := crypto.FromECDSAPub(&srv.PrivateKey.PublicKey)
	srv.ourHandshake = &protoHandshake{Version: baseProtocolVersion, Name: srv.Name, ID: pubkey[1:]}
	for _, p := range srv.Protocols {
		srv.ourHandshake.Caps = append(srv.ourHandshake.Caps, p.cap())
	}
	sort.Sort(capsByNameAndVersion(srv.ourHandshake.Caps))
	db, err := enode.OpenDB(srv.Config.NodeDatabase)
	if err != nil {
		return err
	}
	srv.nodedb = db
	srv.localnode = enode.NewLocalNode(db, srv.PrivateKey)
	srv.localnode.SetFallbackIP(net.IP{127, 0, 0, 1})
	for _, p := range srv.Protocols {
		for _, e := range p.Attributes {
			srv.localnode.Set(e)
		}
	}
	switch srv.NAT.(type) {
	case nil:
	case nat.ExtIP:
		ip, _ := srv.NAT.ExternalIP()
		srv.localnode.SetStaticIP(ip)
	default:
		srv.loopWG.Add(1)
		go func() {
			defer srv.loopWG.Done()
			if ip, err := srv.NAT.ExternalIP(); err == nil {
				srv.localnode.SetStaticIP(ip)
			}
		}()
	}
	return nil
}
func (srv *Server) setupDiscovery() error {
	srv.discmix = enode.NewFairMix(discmixTimeout)
	added := make(map[string]bool)
	for _, proto := range srv.Protocols {
		if proto.DialCandidates != nil && !added[proto.Name] {
			srv.discmix.AddSource(proto.DialCandidates)
			added[proto.Name] = true
		}
	}
	if srv.NoDiscovery && !srv.DiscoveryV5 {
		return nil
	}
	addr, err := net.ResolveUDPAddr("udp", srv.ListenAddr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	realaddr := conn.LocalAddr().(*net.UDPAddr)
	srv.log.Debug("UDP listener up", "addr", realaddr)
	if srv.NAT != nil {
		if !realaddr.IP.IsLoopback() {
			srv.loopWG.Add(1)
			go func() {
				nat.Map(srv.NAT, srv.quit, "udp", realaddr.Port, realaddr.Port, "ethereum discovery")
				srv.loopWG.Done()
			}()
		}
	}
	srv.localnode.SetFallbackUDP(realaddr.Port)
	var unhandled chan discover.ReadPacket
	var sconn *sharedUDPConn
	if !srv.NoDiscovery {
		if srv.DiscoveryV5 {
			unhandled = make(chan discover.ReadPacket, 100)
			sconn = &sharedUDPConn{conn, unhandled}
		}
		cfg := discover.Config{
			PrivateKey:  srv.PrivateKey,
			NetRestrict: srv.NetRestrict,
			Bootnodes:   srv.BootstrapNodes,
			Unhandled:   unhandled,
			Log:         srv.log,
		}
		ntab, err := discover.ListenUDP(conn, srv.localnode, cfg)
		if err != nil {
			return err
		}
		srv.ntab = ntab
		srv.discmix.AddSource(ntab.RandomNodes())
	}
	if srv.DiscoveryV5 {
		var ntab *discv5.Network
		var err error
		if sconn != nil {
			ntab, err = discv5.ListenUDP(srv.PrivateKey, sconn, "", srv.NetRestrict)
		} else {
			ntab, err = discv5.ListenUDP(srv.PrivateKey, conn, "", srv.NetRestrict)
		}
		if err != nil {
			return err
		}
		if err := ntab.SetFallbackNodes(srv.BootstrapNodesV5); err != nil {
			return err
		}
		srv.DiscV5 = ntab
	}
	return nil
}
func (srv *Server) setupDialScheduler() {
	config := dialConfig{
		self:           srv.localnode.ID(),
		maxDialPeers:   srv.maxDialedConns(),
		maxActiveDials: srv.MaxPendingPeers,
		log:            srv.Logger,
		netRestrict:    srv.NetRestrict,
		dialer:         srv.Dialer,
		clock:          srv.clock,
	}
	if srv.ntab != nil {
		config.resolver = srv.ntab
	}
	if config.dialer == nil {
		config.dialer = tcpDialer{&net.Dialer{Timeout: defaultDialTimeout}}
	}
	srv.dialsched = newDialScheduler(config, srv.discmix, srv.SetupConn)
	for _, n := range srv.StaticNodes {
		srv.dialsched.addStatic(n)
	}
}
func (srv *Server) maxInboundConns() int {
	return srv.MaxPeers - srv.maxDialedConns()
}
func (srv *Server) maxDialedConns() (limit int) {
	if srv.NoDial || srv.MaxPeers == 0 {
		return 0
	}
	if srv.DialRatio == 0 {
		limit = srv.MaxPeers / defaultDialRatio
	} else {
		limit = srv.MaxPeers / srv.DialRatio
	}
	if limit == 0 {
		limit = 1
	}
	return limit
}
func (srv *Server) setupListening() error {
	listener, err := srv.listenFunc("tcp", srv.ListenAddr)
	if err != nil {
		return err
	}
	srv.listener = listener
	srv.ListenAddr = listener.Addr().String()
	if tcp, ok := listener.Addr().(*net.TCPAddr); ok {
		srv.localnode.Set(enr.TCP(tcp.Port))
		if !tcp.IP.IsLoopback() && srv.NAT != nil {
			srv.loopWG.Add(1)
			go func() {
				nat.Map(srv.NAT, srv.quit, "tcp", tcp.Port, tcp.Port, "ethereum p2p")
				srv.loopWG.Done()
			}()
		}
	}
	srv.loopWG.Add(1)
	go srv.listenLoop()
	return nil
}
func (srv *Server) doPeerOp(fn peerOpFunc) {
	select {
	case srv.peerOp <- fn:
		<-srv.peerOpDone
	case <-srv.quit:
	}
}
func (srv *Server) run() {
	srv.log.Info("Started P2P networking", "self", srv.localnode.Node().URLv4())
	defer srv.loopWG.Done()
	defer srv.nodedb.Close()
	defer srv.discmix.Close()
	defer srv.dialsched.stop()
	var (
		peers        = make(map[enode.ID]*Peer)
		inboundCount = 0
		trusted      = make(map[enode.ID]bool, len(srv.TrustedNodes))
	)
	for _, n := range srv.TrustedNodes {
		trusted[n.ID()] = true
	}
running:
	for {
		select {
		case <-srv.quit:
			break running
		case n := <-srv.addtrusted:
			srv.log.Trace("Adding trusted node", "node", n)
			trusted[n.ID()] = true
			if p, ok := peers[n.ID()]; ok {
				p.rw.set(trustedConn, true)
			}
		case n := <-srv.removetrusted:
			srv.log.Trace("Removing trusted node", "node", n)
			delete(trusted, n.ID())
			if p, ok := peers[n.ID()]; ok {
				p.rw.set(trustedConn, false)
			}
		case op := <-srv.peerOp:
			op(peers)
			srv.peerOpDone <- struct{}{}
		case c := <-srv.checkpointPostHandshake:
			if trusted[c.node.ID()] {
				c.flags |= trustedConn
			}
			c.cont <- srv.postHandshakeChecks(peers, inboundCount, c)
		case c := <-srv.checkpointAddPeer:
			err := srv.addPeerChecks(peers, inboundCount, c)
			if err == nil {
				p := srv.launchPeer(c)
				peers[c.node.ID()] = p
				srv.log.Debug("Adding p2p peer", "peercount", len(peers), "id", p.ID(), "conn", c.flags, "addr", p.RemoteAddr(), "name", truncateName(c.name))
				srv.dialsched.peerAdded(c)
				if p.Inbound() {
					inboundCount++
				}
			}
			c.cont <- err
		case pd := <-srv.delpeer:
			d := common.PrettyDuration(mclock.Now() - pd.created)
			delete(peers, pd.ID())
			srv.log.Debug("Removing p2p peer", "peercount", len(peers), "id", pd.ID(), "duration", d, "req", pd.requested, "err", pd.err)
			srv.dialsched.peerRemoved(pd.rw)
			if pd.Inbound() {
				inboundCount--
			}
		}
	}
	srv.log.Trace("P2P networking is spinning down")
	if srv.ntab != nil {
		srv.ntab.Close()
	}
	if srv.DiscV5 != nil {
		srv.DiscV5.Close()
	}
	for _, p := range peers {
		p.Disconnect(DiscQuitting)
	}
	for len(peers) > 0 {
		p := <-srv.delpeer
		p.log.Trace("<-delpeer (spindown)")
		delete(peers, p.ID())
	}
}
func (srv *Server) postHandshakeChecks(peers map[enode.ID]*Peer, inboundCount int, c *conn) error {
	switch {
	case !c.is(trustedConn) && len(peers) >= srv.MaxPeers:
		return DiscTooManyPeers
	case !c.is(trustedConn) && c.is(inboundConn) && inboundCount >= srv.maxInboundConns():
		return DiscTooManyPeers
	case peers[c.node.ID()] != nil:
		return DiscAlreadyConnected
	case c.node.ID() == srv.localnode.ID():
		return DiscSelf
	default:
		return nil
	}
}
func (srv *Server) addPeerChecks(peers map[enode.ID]*Peer, inboundCount int, c *conn) error {
	if len(srv.Protocols) > 0 && countMatchingProtocols(srv.Protocols, c.caps) == 0 {
		return DiscUselessPeer
	}
	return srv.postHandshakeChecks(peers, inboundCount, c)
}
func (srv *Server) listenLoop() {
	srv.log.Debug("TCP listener up", "addr", srv.listener.Addr())
	tokens := defaultMaxPendingPeers
	if srv.MaxPendingPeers > 0 {
		tokens = srv.MaxPendingPeers
	}
	slots := make(chan struct{}, tokens)
	for i := 0; i < tokens; i++ {
		slots <- struct{}{}
	}
	defer srv.loopWG.Done()
	defer func() {
		for i := 0; i < cap(slots); i++ {
			<-slots
		}
	}()
	for {
		<-slots
		var (
			fd  net.Conn
			err error
		)
		for {
			fd, err = srv.listener.Accept()
			if netutil.IsTemporaryError(err) {
				srv.log.Debug("Temporary read error", "err", err)
				continue
			} else if err != nil {
				srv.log.Debug("Read error", "err", err)
				slots <- struct{}{}
				return
			}
			break
		}
		remoteIP := netutil.AddrIP(fd.RemoteAddr())
		if err := srv.checkInboundConn(fd, remoteIP); err != nil {
			srv.log.Debug("Rejected inbound connnection", "addr", fd.RemoteAddr(), "err", err)
			fd.Close()
			slots <- struct{}{}
			continue
		}
		if remoteIP != nil {
			var addr *net.TCPAddr
			if tcp, ok := fd.RemoteAddr().(*net.TCPAddr); ok {
				addr = tcp
			}
			fd = newMeteredConn(fd, true, addr)
			srv.log.Trace("Accepted connection", "addr", fd.RemoteAddr())
		}
		go func() {
			srv.SetupConn(fd, inboundConn, nil)
			slots <- struct{}{}
		}()
	}
}
func (srv *Server) checkInboundConn(fd net.Conn, remoteIP net.IP) error {
	if remoteIP == nil {
		return nil
	}
	if srv.NetRestrict != nil && !srv.NetRestrict.Contains(remoteIP) {
		return fmt.Errorf("not whitelisted in NetRestrict")
	}
	now := srv.clock.Now()
	srv.inboundHistory.expire(now, nil)
	if !netutil.IsLAN(remoteIP) && srv.inboundHistory.contains(remoteIP.String()) {
		return fmt.Errorf("too many attempts")
	}
	srv.inboundHistory.add(remoteIP.String(), now.Add(inboundThrottleTime))
	return nil
}
func (srv *Server) SetupConn(fd net.Conn, flags connFlag, dialDest *enode.Node) error {
	c := &conn{fd: fd, transport: srv.newTransport(fd), flags: flags, cont: make(chan error)}
	err := srv.setupConn(c, flags, dialDest)
	if err != nil {
		c.close(err)
	}
	return err
}
func (srv *Server) setupConn(c *conn, flags connFlag, dialDest *enode.Node) error {
	srv.lock.Lock()
	running := srv.running
	srv.lock.Unlock()
	if !running {
		return errServerStopped
	}
	var dialPubkey *ecdsa.PublicKey
	if dialDest != nil {
		dialPubkey = new(ecdsa.PublicKey)
		if err := dialDest.Load((*enode.Secp256k1)(dialPubkey)); err != nil {
			err = errors.New("dial destination doesn't have a secp256k1 public key")
			srv.log.Trace("Setting up connection failed", "addr", c.fd.RemoteAddr(), "conn", c.flags, "err", err)
			return err
		}
	}
	remotePubkey, err := c.doEncHandshake(srv.PrivateKey, dialPubkey)
	if err != nil {
		srv.log.Trace("Failed RLPx handshake", "addr", c.fd.RemoteAddr(), "conn", c.flags, "err", err)
		return err
	}
	if dialDest != nil {
		if dialPubkey.X.Cmp(remotePubkey.X) != 0 || dialPubkey.Y.Cmp(remotePubkey.Y) != 0 {
			return DiscUnexpectedIdentity
		}
		c.node = dialDest
	} else {
		c.node = nodeFromConn(remotePubkey, c.fd)
	}
	clog := srv.log.New("id", c.node.ID(), "addr", c.fd.RemoteAddr(), "conn", c.flags)
	err = srv.checkpoint(c, srv.checkpointPostHandshake)
	if err != nil {
		clog.Trace("Rejected peer", "err", err)
		return err
	}
	phs, err := c.doProtoHandshake(srv.ourHandshake)
	if err != nil {
		clog.Trace("Failed p2p handshake", "err", err)
		return err
	}
	if id := c.node.ID(); !bytes.Equal(crypto.Keccak256(phs.ID), id[:]) {
		clog.Trace("Wrong devp2p handshake identity", "phsid", hex.EncodeToString(phs.ID))
		return DiscUnexpectedIdentity
	}
	c.caps, c.name = phs.Caps, phs.Name
	err = srv.checkpoint(c, srv.checkpointAddPeer)
	if err != nil {
		clog.Trace("Rejected peer", "err", err)
		return err
	}
	return nil
}
func nodeFromConn(pubkey *ecdsa.PublicKey, conn net.Conn) *enode.Node {
	var ip net.IP
	var port int
	if tcp, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		ip = tcp.IP
		port = tcp.Port
	}
	return enode.NewV4(pubkey, ip, port, port)
}
func truncateName(s string) string {
	if len(s) > 20 {
		return s[:20] + "..."
	}
	return s
}
func (srv *Server) checkpoint(c *conn, stage chan<- *conn) error {
	select {
	case stage <- c:
	case <-srv.quit:
		return errServerStopped
	}
	return <-c.cont
}
func (srv *Server) launchPeer(c *conn) *Peer {
	p := newPeer(srv.log, c, srv.Protocols)
	if srv.EnableMsgEvents {
		p.events = &srv.peerFeed
	}
	go srv.runPeer(p)
	return p
}
func (srv *Server) runPeer(p *Peer) {
	if srv.newPeerHook != nil {
		srv.newPeerHook(p)
	}
	srv.peerFeed.Send(&PeerEvent{
		Type:          PeerEventTypeAdd,
		Peer:          p.ID(),
		RemoteAddress: p.RemoteAddr().String(),
		LocalAddress:  p.LocalAddr().String(),
	})
	remoteRequested, err := p.run()
	srv.delpeer <- peerDrop{p, err, remoteRequested}
	srv.peerFeed.Send(&PeerEvent{
		Type:          PeerEventTypeDrop,
		Peer:          p.ID(),
		Error:         err.Error(),
		RemoteAddress: p.RemoteAddr().String(),
		LocalAddress:  p.LocalAddr().String(),
	})
}
type NodeInfo struct {
	ID    string `json:"id"`    
	Name  string `json:"name"`  
	Enode string `json:"enode"` 
	ENR   string `json:"enr"`   
	IP    string `json:"ip"`    
	Ports struct {
		Discovery int `json:"discovery"` 
		Listener  int `json:"listener"`  
	} `json:"ports"`
	ListenAddr string                 `json:"listenAddr"`
	Protocols  map[string]interface{} `json:"protocols"`
}
func (srv *Server) NodeInfo() *NodeInfo {
	node := srv.Self()
	info := &NodeInfo{
		Name:       srv.Name,
		Enode:      node.URLv4(),
		ID:         node.ID().String(),
		IP:         node.IP().String(),
		ListenAddr: srv.ListenAddr,
		Protocols:  make(map[string]interface{}),
	}
	info.Ports.Discovery = node.UDP()
	info.Ports.Listener = node.TCP()
	info.ENR = node.String()
	for _, proto := range srv.Protocols {
		if _, ok := info.Protocols[proto.Name]; !ok {
			nodeInfo := interface{}("unknown")
			if query := proto.NodeInfo; query != nil {
				nodeInfo = proto.NodeInfo()
			}
			info.Protocols[proto.Name] = nodeInfo
		}
	}
	return info
}
func (srv *Server) PeersInfo() []*PeerInfo {
	infos := make([]*PeerInfo, 0, srv.PeerCount())
	for _, peer := range srv.Peers() {
		if peer != nil {
			infos = append(infos, peer.Info())
		}
	}
	for i := 0; i < len(infos); i++ {
		for j := i + 1; j < len(infos); j++ {
			if infos[i].ID > infos[j].ID {
				infos[i], infos[j] = infos[j], infos[i]
			}
		}
	}
	return infos
}
