package datasource

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
	upC    chan<- *transport.Segment // IP -> transport,需要在IP层关闭
	downC  <-chan *transport.Segment // transport -> IP,由传输层关闭
	filter Filter
}

func NewIpReader(ctx context.Context, name string, filter Filter) (<-chan *transport.Segment, chan<- *transport.Segment) {
	ifce, err := water.New(water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: name,
		},
	})

	if err != nil {
		panic(err)
	}

	up := make(chan *transport.Segment)
	down := make(chan *transport.Segment)

	ipReader := &IpReader{
		Interface: ifce,
		upC:       up,
		downC:     down,
		filter:    filter,
	}

	go ipReader.Run(ctx)

	return up, down
}

func (ir *IpReader) Run(ctx context.Context) {
	defer close(ir.upC)
	defer ir.Close()

	packet := make([]byte, 1500)
	for {
		select {
		case <-ctx.Done():
			return

		// TODO: 将上层数据按MTU拆分
		case seg := <-ir.downC:
			ipkt := ip.NewIPPacketFromUpper(seg)
			bt := ipkt.HeaderByte()
			bt = append(bt, ipkt.Payload...)
			if _, err := ir.Write(bt); err != nil {
				log.Println(err.Error())
				continue
			}
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
			ir.upC <- &transport.Segment{
				SrcIp:   transport.IP(ipPkt.SrcIp),
				DstIp:   transport.IP(ipPkt.DstIp),
				Data:    data,
				HasNext: ipPkt.Flags.MF(),
			}
		}
	}
}
