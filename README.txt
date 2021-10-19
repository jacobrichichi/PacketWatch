Hello! In analysis_pcap_tcp.py, you will find all the code for this assignment.
First, you must specify the name of the pcap file that you would like to test.

For part A.a, whenever a SYN flag was found on a packet, this meant a new flow has been found. I would then initialize
a new flow into my flow_list, with the port numbers and IP's of the sender and receiver.
Then, for A.b, I would count how many packets belonged to this flow, and once this count exceeded 2, this meant the
handshake was finished, and that I could now record the first 2 transactions, by grabbing the SEQ, ACK, and receive
window from the tcp dictionary for that given packet. The same went for the receiving packets, and the first two to
come in were recorded as the first two receiver to sender packets.

Lastly for part A, A.c was achieved by first recording the first timestamp in the flow. Then, for every packet that was
sent by the sender, I would sum the size of this packet into a total sum attribute for the flow. Then, when the FIN
flag came in for this flow, I would record this timestamp, and then take the throughput as the total size of all
packets, divided by the difference of the finish time and the start time.

Now for part B.a, I took the initial RTT to be the time between the first SYN flag packet, and the response to this
packet. Then, I started the first congestion window at the first packet after the handshake, and started a timer
that would end exactly one RTT from the timestamp of this packet. I would count every packet send by the sender
up until this timer is reached, at which I would begin a new timer.

For part B.b, I kept track of when the receiver would send an ACK for a packet that equaled the ACK of the last packet
it sent, meaning a duplicate ACK is occuring. FOr each consecutive dup ack, I would increment a counter, and I would
stop counting duplicate ACKs and reset the counter if an ACK came in that no longer equaled the duplicate ACK number.
Then, on the sender side, if a SEQ was sent out that was less than the most recent sequence number, this indicated a
retransmission. I would then check to see whether the receiver was currently sending duplicate ACKS more then 2 times.
If it did, and these duplicate ACKs were for the current seq number, I would increment the number of duplicate ACKs.
If this was not true though, I would increment the number of timeouts.