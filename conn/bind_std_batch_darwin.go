//go:build darwin

package conn

import (
	"encoding/binary"
	"net"
	"unsafe"

	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/darwinmsgx"
)

const stdNetBindBatches = true

func (s *StdNetBind) setupBatch(v4conn, v6conn *net.UDPConn) {
	if v4conn != nil {
		s.batch4 = &darwinBatchConn{conn: v4conn}
	}
	if v6conn != nil {
		s.batch6 = &darwinBatchConn{conn: v6conn}
	}
}

type darwinBatchConn struct {
	conn *net.UDPConn
}

func (c *darwinBatchConn) ReadBatch(msgs []ipv6.Message, flags int) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}
	_ = flags

	msghdrs := make([]darwinmsgx.MsghdrX, len(msgs))
	sas := make([]unix.RawSockaddrAny, len(msgs))

	for i := range msgs {
		buf := msgs[i].Buffers[0]
		if len(buf) == 0 {
			continue
		}
		msghdrs[i].Name = (*byte)(unsafe.Pointer(&sas[i]))
		msghdrs[i].Namelen = uint32(unix.SizeofSockaddrAny)
		msghdrs[i].Iov = &unix.Iovec{Base: &buf[0], Len: uint64(len(buf))}
		msghdrs[i].Iovlen = 1
	}

	rc, err := c.conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	n, err := darwinmsgx.RecvmsgX(rc, msghdrs)
	if err != nil {
		return n, err
	}
	for i := 0; i < n; i++ {
		msgs[i].N = int(msghdrs[i].DataLen)
		msgs[i].Addr = sockaddrAnyToUDPAddr(&sas[i])
	}
	return n, nil
}

func (c *darwinBatchConn) WriteBatch(msgs []ipv6.Message, flags int) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}
	_ = flags

	msghdrs := make([]darwinmsgx.MsghdrX, len(msgs))
	sa4s := make([]unix.RawSockaddrInet4, len(msgs))
	sa6s := make([]unix.RawSockaddrInet6, len(msgs))

	for i, msg := range msgs {
		addr := msg.Addr.(*net.UDPAddr)
		if ip4 := addr.IP.To4(); ip4 != nil {
			sa4s[i].Len = unix.SizeofSockaddrInet4
			sa4s[i].Family = unix.AF_INET
			p := (*[2]byte)(unsafe.Pointer(&sa4s[i].Port))
			p[0] = byte(addr.Port >> 8)
			p[1] = byte(addr.Port)
			copy(sa4s[i].Addr[:], ip4)
			msghdrs[i].Name = (*byte)(unsafe.Pointer(&sa4s[i]))
			msghdrs[i].Namelen = unix.SizeofSockaddrInet4
		} else {
			ip6 := addr.IP.To16()
			sa6s[i].Len = unix.SizeofSockaddrInet6
			sa6s[i].Family = unix.AF_INET6
			p := (*[2]byte)(unsafe.Pointer(&sa6s[i].Port))
			p[0] = byte(addr.Port >> 8)
			p[1] = byte(addr.Port)
			copy(sa6s[i].Addr[:], ip6)
			msghdrs[i].Name = (*byte)(unsafe.Pointer(&sa6s[i]))
			msghdrs[i].Namelen = unix.SizeofSockaddrInet6
			// TODO: handle IPv6 zone / Scope_id
		}

		buf := msg.Buffers[0]
		msghdrs[i].Iov = &unix.Iovec{Base: &buf[0], Len: uint64(len(buf))}
		msghdrs[i].Iovlen = 1
	}

	rc, err := c.conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	return darwinmsgx.SendmsgX(rc, msghdrs)
}

func sockaddrAnyToUDPAddr(sa *unix.RawSockaddrAny) *net.UDPAddr {
	switch sa.Addr.Family {
	case unix.AF_INET:
		rsa := (*unix.RawSockaddrInet4)(unsafe.Pointer(sa))
		port := int(binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&rsa.Port))[:]))
		ip := make(net.IP, net.IPv4len)
		copy(ip, rsa.Addr[:])
		return &net.UDPAddr{IP: ip, Port: port}
	case unix.AF_INET6:
		rsa := (*unix.RawSockaddrInet6)(unsafe.Pointer(sa))
		port := int(binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&rsa.Port))[:]))
		ip := make(net.IP, net.IPv6len)
		copy(ip, rsa.Addr[:])
		return &net.UDPAddr{IP: ip, Port: port}
	default:
		return nil
	}
}
