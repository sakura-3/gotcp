package internal

import (
	"context"
	"log"

	"gotcp/internal/ip"
	"gotcp/internal/transport"

	"github.com/songgao/water"
)

type Filter func(ipPkt *ip.IPPacket) bool

type IpReader struct {
	*water.Interface
	upC    chan<- transport.Segment // IP -> transport,需要在IP层关闭
	downC  <-chan transport.Segment // transport -> IP,由传输层关闭
	filter Filter
}

func NewIpReader(name string, up chan<- transport.Segment, down <-chan transport.Segment) *IpReader {
	ifce, err := water.New(water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: name,
		},
	})

	if err != nil {
		panic(err)
	}

	ipReader := &IpReader{
		Interface: ifce,
		upC:       up,
		downC:     down,
		filter:    nil,
	}

	return ipReader
}

func (ir *IpReader) WithFilter(filter Filter) *IpReader {
	ir.filter = filter
	return ir
}

func (ir *IpReader) Run(ctx context.Context) {
	defer close(ir.upC)
	defer ir.Close()

	packet := make([]byte, 1500)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			n, err := ir.Read(packet)
			if err != nil {
				log.Println(err.Error())
				continue
			}
			ipPkt, err := ip.NewIPPacketFromLower(packet[:n])
			if err != nil {
				log.Println(err.Error())
				continue
			}

			if ir.filter != nil && !ir.filter(ipPkt) {
				continue
			}

			data := make([]byte, len(ipPkt.Payload))
			copy(data, ipPkt.Payload)
			ir.upC <- transport.Segment{
				SrcIp:   ipPkt.SrcIp,
				DstIp:   ipPkt.DstIp,
				Data:    data,
				HasNext: ipPkt.Flags.MF(),
			}
		}
	}
}
