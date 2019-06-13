import pyshark
cap = pyshark.FileCapture('test.pcapng') # File capture object


# Finding the number of packets in cap
i = 0
for p in cap:
	i = i + 1
print ("Total packets in this capture:", i)

tx_rate_array = []
RSSI_array = []

j = 0
for j in range(i):
	packet = cap[j]
	# print(packet.number)
	try:
		wlan_info = packet.wlan_radio
	except AttributeError:
		print("No wlan_radio found, moving to next packet")
		print("Skipped packet is:", packet.number)
		print("==================================")
		continue
	tx_rate = wlan_info.data_rate #Transmission rate of the packet
	RSSI = wlan_info.signal_dbm #RSSI
	try:
		channel = wlan_info.channel #channel
	except AttributeError:
		print ("Can't get channel")
	wlan = packet.wlan
	try:
		source = wlan.sa # Source MAC address
		source_res = wlan.sa_resolved
		destination = wlan.da #Destination MAC address
		destination_res = wlan.da_resolved
	except AttributeError:
		print("can't find source and destination")
	receiver = wlan.ra # Receiver MAC address
	receiver_res = wlan.ra_resolved
	transmitter = wlan.ta # Transmitter MAC address
	transmitter_res = wlan.ta_resolved
	protocol = packet.transport_layer # Find out if the protocol is TCP or not
	packet_length = packet.length # Total length of the packet
	highest_layer = packet.highest_layer # Highest layer in the packet
	if protocol == 'TCP': # If it is a TCP packet
		IP_length = packet.ip.len # length of packet
		source_IP = packet.ip.src # source IP address
		destination_IP = packet.ip.dst # destination IP address
		source_port = packet.tcp.srcport # source port in TCP layer
		destination_port = packet.tcp.dstport # Destination port TCP layer

# print (packet)