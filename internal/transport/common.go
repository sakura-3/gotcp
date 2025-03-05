package transport

import (
	"fmt"
)

const (
	IPProtoTCP  = 6
	IPProtoUDP  = 17
	IPProtoICMP = 1
)

// ip包中也有定义,避免循环依赖
type IP [4]byte

func (ip IP) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

type Pseudo struct {
	SrcIp IP
	DstIp IP
	Zero  uint8  // 保留位，必须为0
	PTCL  uint8  // 协议类型，对于TCP是6
	Len   uint16 // 数据包长度,header+data,不包括伪首部
}

// TODO: 移除HasNext字段,IP层需要组装为一个完整的TCP segment,再发送给上层
type Segment struct {
	// Ip 用于生成pseudo，再计算校验和
	SrcIp   IP
	DstIp   IP
	Data    []byte
	HasNext bool
}
