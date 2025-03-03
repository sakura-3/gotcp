package transport

import (
	"fmt"
)

// URG | ACK | PSH | RST | SYN | FIN
type Flags uint8

func (f Flags) URG() bool {
	return (f>>5)&1 == 1
}

func (f Flags) ACK() bool {
	return (f>>4)&1 == 1
}

func (f Flags) PSH() bool {
	return (f>>3)&1 == 1
}

func (f Flags) RST() bool {
	return (f>>2)&1 == 1
}

func (f Flags) SYN() bool {
	return (f>>1)&1 == 1
}

func (f Flags) FIN() bool {
	return f&1 == 1
}

/*
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
|       |           |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type TCPSegment struct {
	Pseudo          // 伪首部
	SrcPort  uint16 // 源端口
	DstPort  uint16 // 目的端口
	Seq      uint32 // 序列号
	Ack      uint32 // 确认号
	Offset   uint8  // TCP头部长度,已经乘以4,
	Reserved uint8  // 保留字段,一定为0
	Flags    Flags  // 标志位
	Window   uint16 // 窗口大小
	Checksum uint16 // 校验和
	Urgent   uint16 // 紧急指针
	Options  []byte // 选项
	Data     []byte // 数据
}

// 从下层数据包构造TCP数据段,pseudo 依赖网络层提供, 用于计算校验和
func NewTCPSegmentFromLower(seg Segment) (*TCPSegment, error) {
	pseudo := Pseudo{
		SrcIp: seg.SrcIp,
		DstIp: seg.DstIp,
		Zero:  0,
		PTCL:  uint8(IPProtoTCP),
		Len:   uint16(len(seg.Data)),
	}

	if len(seg.Data) < 20 {
		return nil, fmt.Errorf("invalid tcp packet length: %d", len(seg.Data))
	}
	rawData := make([]byte, len(seg.Data))
	copy(rawData, seg.Data)

	// TODO: checksum校验

	offset := 4 * (rawData[12] >> 4)
	return &TCPSegment{
		Pseudo:   pseudo,
		SrcPort:  uint16(rawData[0])<<8 | uint16(rawData[1]),
		DstPort:  uint16(rawData[2])<<8 | uint16(rawData[3]),
		Seq:      uint32(rawData[4])<<24 | uint32(rawData[5])<<16 | uint32(rawData[6])<<8 | uint32(rawData[7]),
		Ack:      uint32(rawData[8])<<24 | uint32(rawData[9])<<16 | uint32(rawData[10])<<8 | uint32(rawData[11]),
		Offset:   offset,
		Reserved: (rawData[12]&0b00001111)<<2 | rawData[13]>>6,
		Flags:    Flags(rawData[13] & 0b00111111),
		Window:   uint16(rawData[14])<<8 | uint16(rawData[15]),
		Checksum: uint16(rawData[16])<<8 | uint16(rawData[17]),
		Options:  rawData[20:offset],
		Data:     rawData[offset:],
	}, nil
}
