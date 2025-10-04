from dnslib import DNSRecord, DNSHeader, DNSBuffer, DNSQuestion, RR, QTYPE, RCODE
from socket import socket, SOCK_DGRAM, AF_INET

class QueryFailedError(Exception):
	def __init__(self, message):
		super().__init__(message)

"""
There are 13 root servers defined at https://www.iana.org/domains/root/servers
"""

ROOT_SERVER = "199.7.83.42"    # ICANN Root Server
DNS_PORT = 53

cache = []

def name_resolver(udp_socket, domain_name: str, original_name=""):
	domain_substrs = get_domain_substrings(domain_name) # List of substrings of the original domain, separated by .
	#print(f"DOMAIN SUBSTR: {domain_substrs}")
	dns_response = []
	current_domain_substr_index: int = 0
	has_answer: bool = False
	#print(f"CACHE: {cache}")

	# Check if domain (or part of the domain) is already in the cache
	if is_in_cache(domain_name):
		print("Received answer from cache:")
		return get_cached_ip_by_domain(domain_name)
	else:
		was_found_in_cache = False
		
		# Check if the parts of the domain might be in the cache
		for server in cache:
			#print(f"Check cache condition: {list(server.values())[0][1]} //  {domain_substrs[1]}")
			if len(domain_substrs) > 1 and list(server.values())[0][1] == domain_substrs[1]:
				print(f"Consulting server {list(server.keys())[0]} (cached) to get {domain_substrs[1]}")
				dns_response = [list(server.values())[0][0]]
				current_domain_substr_index = 2
				was_found_in_cache = True
				break
		
		if not was_found_in_cache:
			for server in cache:
				if list(server.values())[0][1] == domain_substrs[0]:
					print(f"Consulting server {list(server.keys())[0]} (cached) to get {domain_substrs[0]}")
					dns_response = [list(server.values())[0][0]]
					current_domain_substr_index = 1
					break

	while not has_answer:
		record_type = "A" if current_domain_substr_index == len(domain_substrs) - 1 else "NS"
		#print("########### RECORD TYPE: " + record_type + f" DOMAIN SUBSTRING INDEX: {current_domain_substr_index} ###############")
	
		if current_domain_substr_index == 0:
			try:
				print("Consulting root server")
				dns_response = get_dns_record(udp_socket, domain_substrs[0], ROOT_SERVER, record_type)
			except QueryFailedError as e:
				print(f"Error contacting server - {e}")
				return

			# print("--------------------------- DNS RESPONSE -------------------")
			# print(dns_response)
			# print("------------------------------------------------------------")

			if type(dns_response) != list or current_domain_substr_index + 1 == len(domain_substrs):
				print("Error: unable to find answer")
				return dns_response
			else:
				current_domain_substr_index += 1
		else:
			temp_dns_response = None
			# if current_domain_substr_index + 1 < len(domain_substrs):
			# 	current_domain_substr_index += 1
			
			#print("/////////// ASKED SERVER: " + dns_response[0] + " /////////////////")
			print(f"Consulting server {dns_response[0]} (uncached)")

			try:
				temp_dns_response = get_dns_record(udp_socket, domain_substrs[current_domain_substr_index], dns_response[0], record_type)
			except TimeoutError:
				pass
				#print(f"################################\nBREAKING TO NEW SERVER\nServer just asked: {dns_response[0]}\n####################################")
			except QueryFailedError as e:
				print(f"Error contacting server - {e}")
				return
			
			#print("TEMP DNS REPONSE: " + str(temp_dns_response))
			#print(f"TYPE OF TEMP DNS RESPONSE: {type(temp_dns_response)}")

			if type(temp_dns_response) != list:
				if type(temp_dns_response) is tuple:
					#print("RECEIVED CNAME, GOING TO NEW SERVER")
					print(f"Discovered alias {str(temp_dns_response[0])[:-1]}, returning to root server")
					return name_resolver(udp_socket, str(temp_dns_response[0])[:-1], domain_name)
				else:
					print("Received Answer:")
					domain_name = original_name if original_name != "" else domain_name
					cache_server(domain_name, str(temp_dns_response), domain_name)
					return temp_dns_response

			if len(temp_dns_response) > 0:
				dns_response = None
				dns_response = temp_dns_response[:]
				current_domain_substr_index += 1

def get_domain_substrings(domain_name: str):
	substring_list = domain_name.rsplit('.')
	substring_list_rev = substring_list[::-1]

	domain_substrings = []
	domain_substrings.append(substring_list_rev[0])

	if len(substring_list_rev) > 1:
		domain_substrings.append(substring_list_rev[1] + "." + substring_list_rev[0])
		domain_substrings.append(domain_name)
  
	return domain_substrings

def print_cache():
	print("----------\nCache: ")
	for i in range(len(cache)):
		print(f"{i + 1}: {list(cache[i].keys())[0]} has IPv4 {list(cache[i].values())[0][0]}")
  
	print("----------")

def remove_cache_item(id: int):
	cache.pop(id - 1)
	print(f"Removed record {id}")

def cache_server(name: str, ipv4: str, is_ns_for: str):
	if not is_in_cache(name):
		cache.append({ name: [ipv4, is_ns_for]})

def is_in_cache(domain: str):
	for server in cache:
		if domain in server.keys():
			return True
  
	return False

def get_cached_ip_by_domain(domain: str):
	for i in range(len(cache)):
		if domain in cache[i].keys():
			return str(list(cache[i].values())[0][0])
  
	return None

def get_dns_record(udp_socket, domain:str, parent_server: str, record_type):
	q = DNSRecord.question(domain, qtype = record_type)
	q.header.rd = 0   # Recursion Desired?  NO
	#print("DNS query", repr(q))
	udp_socket.sendto(q.pack(), (parent_server, DNS_PORT))
	pkt, _ = udp_socket.recvfrom(8192)
	buff = DNSBuffer(pkt)

	answer = None
	authoritative_resp = [] # A list of the authoritative data
	additional_resp = [] # A list of the additional data

	"""
	RFC1035 Section 4.1 Format

	The top level format of DNS message is divided into five sections:
	1. Header
	2. Question
	3. Answer
	4. Authority
	5. Additional
	"""

	header = DNSHeader.parse(buff)
	#print("DNS header", repr(header))
	if q.header.id != header.id:
		raise QueryFailedError("Unable to find domain\nUnmatched transaction, query header ID != response header ID")
	if header.rcode != RCODE.NOERROR:
		raise QueryFailedError(f"Unable to find domain\nQuery failed; RCODE={header.rcode}")

	# Parse the question section #2
	for k in range(header.q):
		q = DNSQuestion.parse(buff)
		#print(f"Question-{k} {repr(q)}")
	
	# Parse the answer section #3
	for k in range(header.a):
		a = RR.parse(buff)
		#print(f"Answer-{k} {repr(a)}")
		if a.rtype == QTYPE.A:
			#print("IP address")
			answer = a.rdata
		elif a.rtype == QTYPE.CNAME and answer == None:
			#print("CNAME")
			answer = (a.rdata, a.rtype)
	  
  # Parse the authority section #4
	for k in range(header.auth):
		auth = RR.parse(buff)
		#print(f"Authority-{k} {repr(auth)}")
		authoritative_resp.append(auth)
	  
  # Parse the additional section #5
	for k in range(header.ar):
		adr = RR.parse(buff)
		#print(f"Additional-{k} {repr(adr)} Name: {adr.rname}")
		additional_resp.append(adr)

		if adr.rtype == 1:
			cache_server(str(adr.rname)[:-1], str(adr.rdata), domain)
			#print(f"CACHING {str(adr.rname)[:-1]} FOR DOMAIN {domain}")
	
	valid_servers = []

	# If there is an IPv4 answer, then return that, otherwise return list of valid servers to check
	if answer != None or header.auth == 0:
		#print("ANSWER AND TYPE")
		#print(answer)
		#print(type(answer) == list)
		return answer
	else:
		for server in authoritative_resp:
			valid_servers.append(str(server.rdata))
	
	#print(f"VALID SERVERS TO SEND: {valid_servers}")
	return valid_servers

  
if __name__ == '__main__':
	# Create a UDP socket
	sock = socket(AF_INET, SOCK_DGRAM)
	sock.settimeout(2)

	while True:
		domain_name = input("Enter a domain name or .exit > ")

		if domain_name == '.exit':
			break
		elif domain_name == '.list':
			print_cache()
		elif domain_name == '.clear':
			cache.clear()
			print("Cleared the cache")
		elif domain_name[:7] == '.remove':
			try:
				index = int(domain_name[8:])
				remove_cache_item(index)
			except Exception as e:
				print("Error: Enter valid index")
		else:
			output = name_resolver(sock, domain_name)
			if output is not None:
				print(str(output))
			else:
				print("Timed out")
  
	sock.close()