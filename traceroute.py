import socket
import sys
import re

icmp = socket.getprotobyname('icmp')
udp = socket.getprotobyname('udp')


# receiving icmp messages
receive_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
# sending udp messages
send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)

destination_address = sys.argv[1]
is_ip = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", destination_address) is not None
if not is_ip:
  destination_address = socket.gethostbyname(destination_address)

# the traceroute port, apparently
traceroute_port = 33434

send_address = (destination_address, traceroute_port)
receive_address = ("0.0.0.0", traceroute_port)

receive_socket.bind(receive_address)
ttl = 1

while True:
  curr_name = None
  send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

  send_socket.sendto("", send_address)
  try:
    _, curr_addr = receive_socket.recvfrom(1024)
    curr_name = curr_addr[0]
  except socket.error:
      print "*"
      continue

  curr_hostname = None
  try:
    curr_hostname = socket.gethostbyaddr(curr_name)
  except socket.herror:
    pass

  if curr_hostname is not None:
    print "%s | %s (%s)" % (ttl, curr_hostname, curr_name)
  else:
    print "%s | %s" % (ttl, curr_name)

  if curr_name == destination_address:
    break

  ttl += 1
