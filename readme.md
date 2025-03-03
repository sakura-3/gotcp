This piece of code creates a TAP interface, and prints some header information for every frame. After pull up the main.go, you'll need to bring up the interface and assign an IP address. All of these need root permission.

```bash
sudo go run main.go
```
In a new terminal:

```bash
sudo ip addr add 10.1.0.10/24 dev gotcp
sudo ip link set dev gotcp up
```

Wait until the output main.go terminal, try sending some ICMP broadcast message:

```bash
ping -I gotcp 127.0.0.1
```