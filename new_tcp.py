import pyshark
cap = pyshark.FileCapture('with_cam_new.pcapng') # File capture object
import numpy as np
import matplotlib.pyplot as plt
import matplotlib


# Finding the number of packets in cap
i = 0
for p in cap:
	i = i + 1
print ("Total packets in this capture:", i)

tx_rate_array = []
RSSI_array = []
tcp_num = 0
j = 0
payload_size = 0
csv_array = ['TX_IP', 'RX_IP', 'SRC_MA', 'DST_MA', 'Payload Size', 'Time_sniff']
for j in range(i):
	packet = cap[j]
	protocol = packet.transport_layer # Find out if the protocol is TCP or not
	if protocol == 'TCP': # If it is a TCP packet
		tcp_num = tcp_num + 1
		# try:
		payload_size = (int)(packet.ip.len) - (int)(packet.ip.hdr_len)
		tx_ip = (str)(packet.ip.src)
		rx_ip = (str)(packet.ip.dst) 
		time_packet = packet.sniff_time
		# time_packet = time_packet.strftime('%H')
		#tx_ma = (str)(packet.wlan.ta) 
		# rx_ma = (str)(packet.wlan.ra) 
		src_ma = (str)(packet.eth.src)  
		dst_ma = (str)(packet.eth.dst)
		# rssi = (int)(packet.wlan_radio.signal_dbm)
		# tx_rate = (float)(packet.wlan_radio.data_rate)
		data_array = [tx_ip, rx_ip, src_ma, dst_ma, payload_size, time_packet]  
		csv_array = np.vstack([csv_array, data_array])
		# except AttributeError:
		# 	print("Error, skipping this packet:", packet.number)
		# 	continue
		# print(packet.number)
		
print('TCP packets in this capture', tcp_num)
csv_array = np.asarray(csv_array)
print('Final shape', csv_array.shape)
np.savetxt("TCP.csv", csv_array, delimiter=",",fmt='%s')

i = 0
done = []
rx_array = []
tx_array = []
for i in range(1,len(csv_array)):
	total_bits = (int)(csv_array[i,4])
	if i not in done:
		current = csv_array[i,0]
		done.append(i)
	else:
		continue
	for j in range(len(csv_array)):
		if j not in done:
			if csv_array[j,0] == current:
				total_bits = total_bits + (int)(csv_array[j,4])
				done.append(j)
	tx_a = [current, total_bits]
	if len(tx_array) == 0:
		tx_array = tx_a
	else:
		tx_array = np.vstack([tx_array, tx_a])

done1 = []
for i in range(1,len(csv_array)):
	total_bits = (int)(csv_array[i,4])
	if i not in done1:
		current = csv_array[i,1]
		done1.append(i)
	else:
		continue
	for j in range(len(csv_array)):
		if j not in done1:
			if csv_array[j,1] == current:
				total_bits = total_bits + (int)(csv_array[j,4])
				done1.append(j)
	rx_a = [current, (int)(total_bits)]
	if len(rx_array) == 0:
		rx_array = rx_a
	else:
		rx_array = np.vstack([rx_array, rx_a])

print(tx_array)
print("==================")
print(rx_array)

IP = input("Input IP address of the device you want to monitor: ")
x = []
y = []
for i in range(len(csv_array)):
	if IP == csv_array[i,0]:
		x.append(csv_array[i,5])
		y.append(csv_array[i,4])

dates = matplotlib.dates.date2num(x)
plt.plot(dates,y)
plt.xlabel('Datetime')
plt.ylabel('Payload in bits')
plt.show()

Mac = input("Input MAC address of the device you want to monitor: ")
tx_rx = input("Input 1 for Tx and 2 for RX: ")
va = 1
if tx_rx == 1:
	va = 2
elif tx_rx == 2:
	va = 3
x1 = []
y1 = []
for i in range(len(csv_array)):
	if IP == csv_array[i,va]:
		x1.append(csv_array[i,5])
		y1.append(csv_array[i,4])

dates = matplotlib.dates.date2num(x1)
plt.plot(dates,y1)
plt.xlabel('Datetime')
plt.ylabel('Payload in bytes')
plt.show()

# print (packet)