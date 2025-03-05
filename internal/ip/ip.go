package ip

import (
	"fmt"
	"gotcp/internal/transport"
)

type IP [4]byte

func (ip IP) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

// 0|DF|MF
type Flags uint8

func (f Flags) DF() bool {
	return f&0b010 != 0
}

func (f Flags) MF() bool {
	return f&0b001 != 0
}

/*
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type IPPacket struct {
	Version  uint8  // 版本号
	IHL      uint8  // 头部长度,已经乘以4
	Tos      uint8  // type of service,用处不大
	TotLen   uint16 // 数据包总长
	ID       uint16 // 标识,用于分片
	Flags    Flags  // 标志位
	Offset   uint16 // 分片偏移
	TTL      uint8  // 生存时间
	Proto    uint8  // 协议
	Checksum uint16 // 校验和
	SrcIp    IP     // 源IP
	DstIp    IP     // 目的IP
	Options  []byte // 额外头部

	Payload []byte // 数据包内容
}

// 从下层数据包构造IP数据包
func NewIPPacketFromLower(data []byte) (*IPPacket, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("invalid ip packet length: %d", len(data))
	}
	rawData := make([]byte, len(data))
	copy(rawData, data)

	// TODO: checksum

	IHL := (rawData[0] & 0xf) * 4
	return &IPPacket{
		Version:  rawData[0] >> 4,
		IHL:      IHL,
		Tos:      rawData[1],
		TotLen:   uint16(rawData[2])<<8 | uint16(rawData[3]),
		ID:       uint16(rawData[4])<<8 | uint16(rawData[5]),
		Flags:    Flags(rawData[6] >> 5),
		Offset:   uint16(rawData[6]&0b00011111)<<8 | uint16(rawData[7]),
		TTL:      rawData[8],
		Proto:    rawData[9],
		Checksum: uint16(rawData[10])<<8 | uint16(rawData[11]),
		SrcIp:    IP{rawData[12], rawData[13], rawData[14], rawData[15]},
		DstIp:    IP{rawData[16], rawData[17], rawData[18], rawData[19]},
		Options:  rawData[20:IHL],
		Payload:  rawData[IHL:],
	}, nil
}

// TODO: 构造IP数据包
func NewIPPacketFromUpper(seg *transport.Segment) *IPPacket {
	ipkt := &IPPacket{}
	ipkt.Version = 4
	ipkt.IHL = 20
	ipkt.Tos = 0
	ipkt.TTL = 64
	ipkt.Proto = uint8(transport.IPProtoTCP)
	ipkt.SrcIp = IP(seg.SrcIp)
	ipkt.DstIp = IP(seg.DstIp)
	ipkt.Payload = seg.Data

	return ipkt
}

func (ipkt *IPPacket) HeaderByte() []byte {
	header := make([]byte, ipkt.IHL)
	header[0] = ipkt.Version<<4 | ipkt.IHL/4
	header[1] = ipkt.Tos
	header[2] = uint8(ipkt.TotLen >> 8)
	header[3] = uint8(ipkt.TotLen)
	header[4] = uint8(ipkt.ID >> 8)
	header[5] = uint8(ipkt.ID)
	header[6] = uint8(ipkt.Flags)<<5 | uint8(ipkt.Offset>>8)
	header[7] = uint8(ipkt.Offset)
	header[8] = ipkt.TTL
	header[9] = ipkt.Proto
	header[10] = uint8(ipkt.Checksum >> 8)
	header[11] = uint8(ipkt.Checksum)
	copy(header[12:], ipkt.SrcIp[:])
	copy(header[16:], ipkt.DstIp[:])
	copy(header[20:], ipkt.Options)
	return header
}
