iface_0=$(ip route get 10.10.1.100 | grep -oP "(?<=dev )[^ ]+") 
iface_1=$(ip route get 10.10.2.100 | grep -oP "(?<=dev )[^ ]+") 

while true; do
    for bandwidth in 10 2 15; do
        sudo tc qdisc del dev $iface_0 root 
        sudo tc qdisc del dev $iface_1 root 
        
        sudo tc qdisc add dev $iface_0 root handle 1: htb default 10 
        sudo tc class add dev $iface_0 parent 1: classid 1:10 htb rate ${bandwidth}Mbit 
        sudo tc qdisc add dev $iface_0 parent 1:10 handle 100: netem delay 15ms 15ms
        sudo tc qdisc add dev $iface_0 parent 100: handle 200: bfifo limit 0.1MB 
        
        sudo tc qdisc add dev $iface_1 root handle 1: htb default 10
        sudo tc class add dev $iface_1 parent 1: classid 1:10 htb rate ${bandwidth}Mbit 
        sudo tc qdisc add dev $iface_1 parent 1:10 handle 110: netem delay 15ms 15ms
        sudo tc qdisc add dev $iface_1 parent 110: handle 210: bfifo limit 0.1MB

        timestamp=$(date +%s)
        printf "%s,%s\n" "$timestamp" "$bandwidth" >> bandwidth_time.csv

        sleep 10
    done
done
