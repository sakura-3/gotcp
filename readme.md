尝试使用`GO`实现[RFC793](https://datatracker.ietf.org/doc/html/rfc793)

为了在用户态实现TCP协议,并且处理真实的网络流量,项目使用了Linux内核中的[TUN/TAP](https://en.wikipedia.org/wiki/TUN/TAP)特性

TODO

- [x] 基于tun网卡接收和发送原始IP数据包
- [x] IP <-> TCP 的解析
- [ ] TCP 协议栈
- [ ] 测试
