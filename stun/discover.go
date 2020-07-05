// Copyright 2016 Cong Ding
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stun

import (
	"errors"
	"net"
)

// Follow RFC 3489 and RFC 5389.
// Figure 2: Flow for type discovery process (from RFC 3489).
//                        +--------+
//                        |  Test  |
//                        |   I    |
//                        +--------+
//                             |
//                             |
//                             V
//                            /\              /\
//                         N /  \ Y          /  \ Y             +--------+
//          UDP     <-------/Resp\--------->/ IP \------------->|  Test  |
//          Blocked         \ ?  /          \Same/              |   II   |
//                           \  /            \? /               +--------+
//                            \/              \/                    |
//                                             | N                  |
//                                             |                    V
//                                             V                    /\
//                                         +--------+  Sym.      N /  \
//                                         |  Test  |  UDP    <---/Resp\
//                                         |   II   |  Firewall   \ ?  /
//                                         +--------+              \  /
//                                             |                    \/
//                                             V                     |Y
//                  /\                         /\                    |
//   Symmetric  N  /  \       +--------+   N  /  \                   V
//      NAT  <--- / IP \<-----|  Test  |<--- /Resp\               Open
//                \Same/      |   I    |     \ ?  /               Internet
//                 \? /       +--------+      \  /
//                  \/                         \/
//                  |Y                          |Y
//                  |                           |
//                  |                           V
//                  |                           Full
//                  |                           Cone
//                  V              /\
//              +--------+        /  \ Y
//              |  Test  |------>/Resp\---->Restricted
//              |   III  |       \ ?  /
//              +--------+        \  /
//                                 \/
//                                  |N
//                                  |       Port
//                                  +------>Restricted
/*
事先声明: stun服务器一般有2台，具体原理见 印象笔记-webrtc专业技术 部分
NAT分为以下4种:
完全锥形NAT:【anyIp:anyPort】可以通过映射的NAT请求到内网特定服务
对称型NAT:内网服务访问不同外网服务，对应不同的NAT映射，此时需要通过中继服务器转发，否则无法访问
限制型NAT:【anyIp:anyPort】可以通过映射的NAT请求到内网特定服务，但是前提是需要内部服务先发送请求，外部服务才能访问到内部服务
端口限制型NAT:【anyIp:特定Port】可以通过映射的NAT请求到内网特定服务，但是前提是需要内部服务先发送请求，外部服务才能访问到内部服务
 */
func (c *Client) discover(conn net.PacketConn, addr *net.UDPAddr) (NATType, *Host, error) {
	// Perform test1 to check if it is under NAT.
	c.logger.Debugln("Do Test1")
	c.logger.Debugln("Send To:", addr)
	//给第一台stun服务器发送请求
	resp, err := c.test1(conn, addr)
	if err != nil {
		return NATError, nil, err
	}
	c.logger.Debugln("Received:", resp)
	if resp == nil {
		return NATBlocked, nil, nil
	}
	// identical used to check if it is open Internet or not.
	identical := resp.identical
	// changedAddr is used to perform second time test1 and test3.
	//changedAddr是另一台stun服务器
	changedAddr := resp.changedAddr
	// mappedAddr is used as the return value, its IP is used for tests
	mappedAddr := resp.mappedAddr
	// Make sure IP and port are not changed.
	//请求的目的地址和返回的stun服务器源地址应该是一致的
	if resp.serverAddr.IP() != addr.IP.String() ||
		resp.serverAddr.Port() != uint16(addr.Port) {
		return NATError, mappedAddr, errors.New("Server error: response IP/port")
	}
	// if changedAddr is not available, use otherAddr as changedAddr,
	// which is updated in RFC 5780
	if changedAddr == nil {
		changedAddr = resp.otherAddr
	}
	// changedAddr shall not be nil
	//如果changedAddr为空，说明第2台stun服务器不存在，失败
	if changedAddr == nil {
		return NATError, mappedAddr, errors.New("Server error: no changed address.")
	}
	// Perform test2 to see if the client can receive packet sent from
	// another IP and port.
	c.logger.Debugln("Do Test2")
	c.logger.Debugln("Send To:", addr)
	//发送请求给第1台stun服务器，但是使用第2台stun服务器返回，如果此时也顺利收到resp，说明是完全锥形NAT
	resp, err = c.test2(conn, addr)
	if err != nil {
		return NATError, mappedAddr, err
	}
	c.logger.Debugln("Received:", resp)
	// Make sure IP and port are changed.
	if resp != nil &&
		(resp.serverAddr.IP() == addr.IP.String() ||
			resp.serverAddr.Port() == uint16(addr.Port)) {
		return NATError, mappedAddr, errors.New("Server error: response IP/port")
	}
	if identical {
		if resp == nil {
			return NATSymmetricUDPFirewall, mappedAddr, nil
		}
		return NATNone, mappedAddr, nil
	}
	//如果成功返回，说明是完全锥形NAT
	if resp != nil {
		return NATFull, mappedAddr, nil
	}
	// Perform test1 to another IP and port to see if the NAT use the same
	// external IP.
	c.logger.Debugln("Do Test1")
	c.logger.Debugln("Send To:", changedAddr)
	//发送请求给第2台stun服务器，如果返回的外网IP:Port不同，说明是对称性NAT，即发送的目的IP:Port不同，就使用不同的NAT映射
	caddr, err := net.ResolveUDPAddr("udp", changedAddr.String())
	if err != nil {
		c.logger.Debugf("ResolveUDPAddr error: %v", err)
	}
	resp, err = c.test1(conn, caddr)
	if err != nil {
		return NATError, mappedAddr, err
	}
	c.logger.Debugln("Received:", resp)
	if resp == nil {
		// It should be NAT_BLOCKED, but will be detected in the first
		// step. So this will never happen.
		return NATUnknown, mappedAddr, nil
	}
	// Make sure IP/port is not changed.
	if resp.serverAddr.IP() != caddr.IP.String() ||
		resp.serverAddr.Port() != uint16(caddr.Port) {
		return NATError, mappedAddr, errors.New("Server error: response IP/port")
	}
	//如果上述返回相同的外网IP:Port，则为限制型锥形NAT，至于是否为端口限制型，还需要进一步验证
	//限制型锥形NAT的特点是，只有在内网发送请求后，才能收到外网的请求；外网无法主动发起请求
	if mappedAddr.IP() == resp.mappedAddr.IP() && mappedAddr.Port() == resp.mappedAddr.Port() {
		// Perform test3 to see if the client can receive packet sent
		// from another port.
		c.logger.Debugln("Do Test3")
		c.logger.Debugln("Send To:", caddr)
		//发送给第2台stun服务器，但是要求返回使用不同的port，用来验证是否为端口限制型
		resp, err = c.test3(conn, caddr)
		if err != nil {
			return NATError, mappedAddr, err
		}
		c.logger.Debugln("Received:", resp)
		//如果此时无法收到更改端口后的resp，则说明为端口限制型，该NAT的IP:Port只能接收anyIp:固定Port的外网请求
		if resp == nil {
			return NATPortRestricted, mappedAddr, nil
		}
		// Make sure IP is not changed, and port is changed.
		if resp.serverAddr.IP() != caddr.IP.String() ||
			resp.serverAddr.Port() == uint16(caddr.Port) {
			return NATError, mappedAddr, errors.New("Server error: response IP/port")
		}
		//如果收到了resp，说明不是端口限制型，该NAT的Ip:Port能接收anyIp:anyPort对应的外网请求
		return NATRestricted, mappedAddr, nil
	}
	return NATSymmetric, mappedAddr, nil
}
