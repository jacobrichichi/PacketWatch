import dpkt


def parse_packet():
    fileName = input('Please enter the name of the pcap file you would like to read')
    f = open(fileName, 'rb')
    pcap = dpkt.pcap.Reader(f)
    flow_list = []
    counter = 0
    start_time = 0


    for ts, buf in pcap:
        #I use the start time variable so all time stamps go on a scale starting from 0, makes everything much more comprehensible

        if counter == 0:
            start_time = ts
        counter += 1
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data

        #a new SYN has been found, indicating a new flow
        if tcp.flags == 2:
            src_ip = str(ip.src[0]) + "." + str(ip.src[1]) + "." + str(ip.src[2]) + "." + str(ip.src[3])
            dst_ip = str(ip.dst[0]) + "." + str(ip.dst[1]) + "." + str(ip.dst[2]) + "." + str(ip.dst[3])


            flow_list.append({
                'sport': tcp.sport,
                'src_ip': src_ip,
                'raw_src_ip': ip.src,
                'dport': tcp.dport,
                'dst_ip': dst_ip,
                'raw_dst_ip': ip.dst,
                'count': 1,
                'size': len(tcp),
                'start_time': ts - start_time,
                'finish_time': -1,
                'first_send_seq': -1,
                'first_send_ack': -1,
                'first_send_win': -1,
                'second_send_seq': -1,
                'second_send_ack': -1,
                'second_send_win': -1,
                'first_rec_seq': -1,
                'first_rec_ack': -1,
                'first_rec_win': -1,
                'second_rec_seq': -1,
                'second_rec_ack': -1,
                'second_rec_win': -1,
                'initial_syn_time': ts - start_time,
                'rtt_value': -1,
                'congestion_windows': [0,0,0],
                'current_window_index': -1,
                'current_window_endtime': -1,
                'current_opening_seq': -1,
                'last_ack': -1,
                'dup_acking': False,
                'trip_dup_acks': 0,
                'dup_ack_num': -1,
                'dup_acks_in_a_row': 0,
                'last_unacked_ts': -1,
                'highest_seq': -1,
                'timeouts': 0,
                'unacked_timestamps': []


            })

        else:
            for flow in flow_list:
                #found which sender flow this transaction belongs to
                if (flow['sport'] == tcp.sport
                and flow['dport'] == tcp.dport
                and flow['raw_src_ip'] == ip.src
                and flow['raw_dst_ip'] == ip.dst):

                    #If past handshake, first transactions can be set
                    if flow['count'] > 2:
                        if flow['second_send_seq'] == -1:
                            #if first sequence unset, and ACK, set first transaction
                            if flow['first_send_seq'] == -1:
                                if tcp.flags == 16 or tcp.flags == 24:
                                    flow['first_send_seq'] = tcp.seq
                                    flow['first_send_ack'] = tcp.ack
                                    flow['first_send_win'] = tcp.win
                                    flow['current_window_index'] = 0
                                    flow['congestion_windows'][0] = 0
                                    flow['current_window_endtime'] = ts - start_time + flow['rtt_value']
                                    flow['current_opening_seq'] = tcp.seq
                            # if second transaction unset and ACK, and first is, set as second transaction
                            else:
                                if tcp.flags == 16 or tcp.flags == 24:
                                    flow['second_send_seq'] = tcp.seq
                                    flow['second_send_ack'] = tcp.ack
                                    flow['second_send_win'] = tcp.win
                        #1 RTT has passed since the last congestion window closed
                        #when seq is -1, this means a new opening sequence number needs to be set
                        if flow['current_opening_seq'] == -1:
                            flow['current_opening_seq'] = tcp.seq

                        #FIN flag!
                        if tcp.flags == 17:
                            flow['finish_time'] = ts - start_time

                        if tcp.seq>flow['highest_seq']:
                            flow['highest_seq'] = tcp.seq

                        #if the sequence number is less then the highest seq sent out, it must be a retransmission
                        else:
                            if flow['dup_acking'] and flow['dup_ack_num'] == tcp.seq and flow['dup_acks_in_a_row'] > 2:
                                flow['trip_dup_acks'] += 1
                            else:
                                flow['timeouts'] += 1


                       # flow['unacked_timestamps'].append((ts - start_time, tcp.seq))

                    #SYN ACK found means we can estimate the RTT
                    if(tcp.flags == 18):
                        flow['rtt_value'] = ts - flow['initial_syn_time'] - start_time

                    flow['count'] += 1
                    flow['size'] += len(tcp)
                    if flow['current_window_index'] < 3:
                        flow['congestion_windows'][flow['current_window_index']] += 1


                #found which reciever flow this transaction belongs to
                elif (flow['sport'] == tcp.dport
                and flow['dport'] == tcp.sport
                and flow['raw_dst_ip'] == ip.src
                and flow['raw_src_ip'] == ip.dst):
                    if flow['count'] > 3:
                        if flow['second_rec_seq'] == -1:
                            #if first sequence unset, and ACK, set first transaction
                            if flow['first_rec_seq'] == -1:
                                if tcp.flags == 16:
                                    flow['first_rec_seq'] = tcp.seq
                                    flow['first_rec_ack'] = tcp.ack
                                    flow['first_rec_win'] = tcp.win

                            # if second transaction unset and ACK, and first is, set as second transaction
                            else:
                                if tcp.flags == 16:
                                    flow['second_rec_seq'] = tcp.seq
                                    flow['second_rec_ack'] = tcp.ack
                                    flow['second_rec_win'] = tcp.win
                        # FIN flag!
                        elif tcp.flags == 17:
                            flow['finish_time'] = ts - start_time

                        #if not currently in a stream of dup acks
                        if not flow['dup_acking']:
                            #if a new dup ack stream has begun
                            if tcp.ack == flow['last_ack']:
                                #increment dup ack retransmissions
                                flow['dup_acking'] = True
                                flow['dup_ack_num'] = tcp.ack
                                flow['dup_acks_in_a_row'] = 1

                        #if in a stream of dup acks
                        else:
                            #if the stream has been broken
                            if tcp.ack != flow['last_ack']:
                                #indicate it has been broken
                                flow['dup_acking'] = False
                                flow['dup_ack_num'] = -1
                            else:
                                flow['dup_acks_in_a_row'] += 1

                        flow['last_ack'] = tcp.ack

                    #SYN ACK found means we can estimate the RTT
                    if (tcp.flags == 18):
                        flow['rtt_value'] = ts - flow['initial_syn_time'] - start_time

                    if (flow['current_window_index'] > -1
                        and tcp.ack >= flow['current_opening_seq']
                        and (ts - start_time) >= flow['current_window_endtime'] - .001):
                        flow['current_window_endtime'] = (ts - start_time) + flow['rtt_value']
                        flow['current_opening_seq'] = -1
                        flow['current_window_index'] += 1

                    flow['count'] += 1
                    #flow['size'] += len(tcp)


    for flow in flow_list:
        print('---------------------------------')
        print('A new flow goes as follows')
        print('The transactions were on these ports and IPs ('
              + str(flow['src_ip']) + ', ' + str(flow['sport']) + ', '
              + str(flow['dst_ip']) + ', ' + str(flow['dport']) + ')')

        print('The throughput for this flow totalled out to ' +
              str((flow['size']/(flow['finish_time']-flow['start_time']))/1000000) + " Mbps")

        print('The number of duplicate ack retransmissions was ' + str(flow['trip_dup_acks']))
        print('The number of timeout retransmissions was ' + str(flow['timeouts']))

        print('The first transaction had sender seq '
              + str(flow['first_send_seq']) + ', ack number ' + str(flow['first_send_ack'])
              + ', and a receive window size of ' + str(flow['first_send_win']))
        print('It also had receiver seq '
              + str(flow['first_rec_seq']) + ', ack number ' + str(flow['first_rec_ack'])
              + ', and a receive window size of ' + str(flow['first_rec_win']))

        print('The second transaction had sender seq '
              + str(flow['second_send_seq']) + ', ack number ' + str(flow['second_send_ack'])
              + ', and a receive window size of ' + str(flow['second_send_win']))
        print('It also had receiver seq '
              + str(flow['second_rec_seq']) + ', ack number ' + str(flow['second_rec_ack'])
              + ', and a receive window size of ' + str(flow['second_rec_win']))
        print('The congestion window sizes went as follows:')
        for x in flow['congestion_windows']:
            print('A window of size ' + str(x))


if __name__ == '__main__':
    parse_packet()
