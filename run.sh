#!/bin/bash
set -ex

# 若服务已运行,先关停
PID=$(ps -aux | grep go-test | grep -v grep | awk '{print $2}')

if [ -n "$PID" ]; then
    echo "Killing process $PID..."
    sudo kill "$PID"
else
    echo "No process found for go-test."
fi

export PATH=/usr/local/go/bin:$PATH
export GOPATH=/home/sakura/go

echo $PATH

go build -o go-test
sudo setsid ./go-test > go-test.log 2>&1 &

sleep 2

PID=$(ps -aux | grep go-test | grep -v grep | awk '{print $2}')
echo $PID


sudo ip addr add 10.1.0.10/24 dev gotcp
sudo ip link set dev gotcp up