require 'packetfu'

SDDR = 0
DATETIME = 1
PAYLOAD =2 
STATUS = 3
CONTENT = 4


# Check if all flags in the packet are unset. If so, it is a NULL scan. 
def is_null_scan?(tcp_packet)
	if tcp_packet.tcp_flags.to_i==0
		return true
	else
		return false
	end
end


# Check if the packet sets the FIN, PSH and URG flags. If so, it is a Xmas Scan 
def is_Xmas_scan?(tcp_packet)
	if tcp_packet.tcp_flags.fin==1 && tcp_packet.tcp_flags.psh==1 && tcp_packet.tcp_flags.urg==1
		return true
	else
		return false
	end
end


# Credit card number leak check. Since it is difficult to enumerate all credit card number patterns in 
# the world, here I only give the most widely used ones from the four major credit card issuing networks. 
def is_creditCard_num_leak?(tcp_packet)
	payload = tcp_packet.payload()
	amex_num = payload.scan(/3[47]\d{3}(\s|-)?\d{6}(\s|-)?\d{5}/)
	other_num = payload.scan(/[4-6]\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/)
	if (amex_num.length+other_num.length) > 0
		return true
	else
		return false
	end
end


# Analyze a server log record, fetch the source ip address, datetime, payload and status from it.
def analyze_server_log(log_record)
	log_arr = Array.new(5)
	log_arr[SDDR] = log_record.slice!(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)
	mtch = log_record.match(/(\[.*\])\s(\"[^"]*\")\s(\d{3})\s(\d*|-)\s(\"[^"]*\")\s(\"[^"]*\")/)
	log_arr[DATETIME] = mtch[1]
	log_arr[PAYLOAD] = mtch[2]
	log_arr[STATUS] = mtch[3]
	log_arr[CONTENT] = mtch[6]
	return log_arr
end


def print_alert(incident_number, attack, packet)
	print "#{incident_number}. ALERT: #{attack} is detected from #{packet.ip_saddr} (#{packet.protocol.last}) (#{packet.payload})!\n"
end


def print_alert_log_analyzing(incident_number, attack, ip_addr, protocol, payload)
    print "#{incident_number}. ALERT: #{attack} is detected from #{ip_addr} (#{protocol}) (#{payload})!\n"
end


#
# Analyzing Web server log when the user input log file name in the command line
#
#
arr = ARGF.argv
if arr!=nil

	filename = arr[1]

	incident_number = 0
	if filename!=nil
		text = File.open(filename).read
		text.each_line do |line|
			log_arr = analyze_server_log(line)
			# if there is "nmap" keyword in the content, it is a Nmap scan
			if log_arr[CONTENT].include?"Nmap"
				incident_number = incident_number +1
				print_alert_log_analyzing(incident_number, "Nmap Scan", log_arr[SDDR], "HTTP", log_arr[PAYLOAD])
				print "#{log_arr[CONTENT]}\n"
			end
			# if there is binary codes in the payload, it is a shellcode attack
			if log_arr[PAYLOAD].match(/(\\x[0-9a-fA-F]+){3,}/)!=nil
				incident_number = incident_number +1
				print_alert_log_analyzing(incident_number, "Shell Code Attack", log_arr[SDDR], "HTTP", log_arr[PAYLOAD])
			end
			# if status is 404, it is a HTTP error
			if log_arr[STATUS] == "404"
				incident_number = incident_number +1
				print_alert_log_analyzing(incident_number, "HTTP Errors", log_arr[SDDR], "HTTP", log_arr[PAYLOAD])
			end
		end
	end
end


#
# Analying live stream of network packets
#
#
stream = PacketFu::Capture.new(:start => true, :iface => 'eth0', :promisc => true)
#stream.show_live()

while 1 do 
	stream.stream.each do |p|
		pkt = PacketFu::Packet.parse(p)
		if pkt.is_tcp?
			if is_null_scan?(pkt)
				incident_number = incident_number+1
				print_alert(incident_number, "Null Scan", pkt)
			end
			if is_Xmas_scan?(pkt)
				incident_number = incident_number+1
				print_alert(incident_number, "Xmas Scan", pkt)
			end
			if is_creditCard_num_leak?(pkt)
				incident_number = incident_number+1
				print_alert(incident_number, "Credit Card Number Leak in the clear", pkt)
			end
		end
	end
end

