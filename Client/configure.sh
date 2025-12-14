sudo apt update
sudo apt -y install iperf3
sudo apt -y install moreutils python3-pip libjpeg-dev
sudo python3 -m pip install pandas matplotlib
sudo sysctl -w net.ipv4.tcp_no_metrics_save=1

ip addr
sudo tcpdump -i eth1 -w romeo.pcap tcp