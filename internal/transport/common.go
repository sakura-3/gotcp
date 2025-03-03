package transport

import (
	"gotcp/internal/ip"
)

const (
	IPProtoTCP  = 6
	IPProtoUDP  = 17
	IPProtoICMP = 1
)

type Pseudo struct {
	SrcIp ip.IP
	DstIp ip.IP
	Zero  uint8  // 保留位，必须为0
	PTCL  uint8  // 协议类型，对于TCP是6
	Len   uint16 // 数据包长度,header+data,不包括伪首部
}

type Segment struct {
	// Ip 用于生成pseudo，再计算校验和
	SrcIp   ip.IP
	DstIp   ip.IP
	Data    []byte
	HasNext bool
}
