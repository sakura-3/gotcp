package internal

import (
	"context"
	"log"

	"gotcp/internal/ip"
	"gotcp/internal/transport"

	"github.com/songgao/water"
)

type IpReader struct {
	*water.Interface
	upC   chan<- transport.Segment // IP -> transport,需要在IP层关闭
	downC <-chan transport.Segment // transport -> IP,由传输层关闭
}

func NewIpReader(up chan<- transport.Segment, down <-chan transport.Segment) (*IpReader, error) {
	ifce, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		return nil, err
	}

	ipReader := &IpReader{
		Interface: ifce,
		upC:       up,
		downC:     down,
	}

	return ipReader, nil
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
