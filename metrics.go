package p2p
import (
	"net"
	"github.com/Cryptochain-VON/metrics"
)
const (
	ingressMeterName = "p2p/ingress"
	egressMeterName  = "p2p/egress"
)
var (
	ingressConnectMeter = metrics.NewRegisteredMeter("p2p/serves", nil)
	ingressTrafficMeter = metrics.NewRegisteredMeter(ingressMeterName, nil)
	egressConnectMeter  = metrics.NewRegisteredMeter("p2p/dials", nil)
	egressTrafficMeter  = metrics.NewRegisteredMeter(egressMeterName, nil)
	activePeerGauge     = metrics.NewRegisteredGauge("p2p/peers", nil)
)
type meteredConn struct {
	net.Conn
}
func newMeteredConn(conn net.Conn, ingress bool, addr *net.TCPAddr) net.Conn {
	if !metrics.Enabled {
		return conn
	}
	if ingress {
		ingressConnectMeter.Mark(1)
	} else {
		egressConnectMeter.Mark(1)
	}
	activePeerGauge.Inc(1)
	return &meteredConn{Conn: conn}
}
func (c *meteredConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	ingressTrafficMeter.Mark(int64(n))
	return n, err
}
func (c *meteredConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	egressTrafficMeter.Mark(int64(n))
	return n, err
}
func (c *meteredConn) Close() error {
	err := c.Conn.Close()
	if err == nil {
		activePeerGauge.Dec(1)
	}
	return err
}
