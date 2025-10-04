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

'''
Returns the corresponding IPv4 of the given domain.
'''
def name_resolver(udp_socket, domain_name: str, original_name=""):
	domain_substrs = get_domain_substrings(domain_name) # List of substrings of the original domain, separated by .
	dns_response = []
	current_domain_substr_index: int = 0
	has_answer: bool = False

	# Check if domain (or part of the domain) is already in the cache
	if is_in_cache(domain_name):
		print("Received answer from cache:")
		return get_cached_ip_by_domain(domain_name)
	else:
		was_found_in_cache = False
		
		# Check if the parts of the domain might be in the cache
		for server in cache:
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
	
		if current_domain_substr_index == 0:
			try:
				print("Consulting root server")
				dns_response = get_dns_record(udp_socket, domain_substrs[0], ROOT_SERVER, record_type)
			except QueryFailedError as e:
				print(f"Error contacting server - {e}")
				return

			if type(dns_response) != list or current_domain_substr_index + 1 == len(domain_substrs):
				print("Error: unable to find answer")
				return dns_response
			else:
				current_domain_substr_index += 1
		else:
			temp_dns_response = None

			for i in range(len(dns_response)):
				print(f"Consulting server {dns_response[i][:-1] if dns_response[0][-1] == "." else dns_response[i]} (uncached)")

				# Loop through servers until one doesn't time out
				try:
					temp_dns_response = get_dns_record(udp_socket, domain_substrs[current_domain_substr_index], dns_response[i], record_type)
					break
				except TimeoutError:
					print(f"Server {dns_response[i][:-1] if dns_response[0][-1] == "." else dns_response[i]} timed out, moving to new server")
					break
				except QueryFailedError as e:
					print(f"Error contacting server - {e}")
					return
			else:
				print("Received no response from contacted servers")
				return

			if type(temp_dns_response) != list:
				if type(temp_dns_response) is tuple: # If response is a tuple, it's a CNAME and we restart the process with the new name
					print(f"Discovered alias {str(temp_dns_response[0])[:-1]}, returning to root server")
					domain_to_save = domain_name if original_name == "" else original_name
					return name_resolver(udp_socket, str(temp_dns_response[0])[:-1], domain_to_save)
				else: # The response is an Answer if this is true, so we return that
					domain_name = original_name if original_name != "" else domain_name
					print(f"Received Answer for {domain_name}:")
					cache_server(domain_name, str(temp_dns_response), domain_name)
					return temp_dns_response

			# Answer/CNAME not received, so continue with new response
			if len(temp_dns_response) > 0:
				dns_response = None
				dns_response = temp_dns_response[:]
				if current_domain_substr_index + 1 < len(domain_substrs):
					current_domain_substr_index += 1

'''
Split the domain into a list of substrings.
'''
def get_domain_substrings(domain_name: str):
	substring_list = domain_name.rsplit('.')
	substring_list_rev = substring_list[::-1]

	domain_substrings = []
	domain_substrings.append(substring_list_rev[0])

	if len(substring_list_rev) > 1:
		domain_substrings.append(substring_list_rev[1] + "." + substring_list_rev[0])
		domain_substrings.append(domain_name)
  
	return domain_substrings

'''
Print the cache in an easily-readable format.
'''
def print_cache():
	print("----------\nCache: ")
	for i in range(len(cache)):
		print(f"{i + 1}: {list(cache[i].keys())[0]} has IPv4 {list(cache[i].values())[0][0]}")
  
	print("----------")

'''
Remove a cached server based on the specified index.
'''
def remove_cache_item(id: int):
	cache.pop(id - 1)
	print(f"Removed record {id}")

'''
Cache the given server by providing the name, IPv4, and what it was used to resolve for (should be the same as the name if is the answer to a query)
'''
def cache_server(name: str, ipv4: str, is_ns_for: str):
	if not is_in_cache(name):
		cache.append({ name: [ipv4, is_ns_for]})

'''
Return whether or not the specified server is in the cache.
'''
def is_in_cache(domain: str):
	for server in cache:
		if domain in server.keys():
			return True
  
	return False


'''
Return the corresponding IPv4 to the given domain.
'''
def get_cached_ip_by_domain(domain: str):
	for i in range(len(cache)):
		if domain in cache[i].keys():
			return str(list(cache[i].values())[0][0])
  
	return None

'''
Get the DNS record by providing a socket, the domain, a server the ask, and the DNS record type.
'''
def get_dns_record(udp_socket, domain:str, parent_server: str, record_type):
	q = DNSRecord.question(domain, qtype = record_type)
	q.header.rd = 0   # Recursion Desired?  NO
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
	if q.header.id != header.id:
		raise QueryFailedError("Unable to find domain\nUnmatched transaction, query header ID != response header ID")
	if header.rcode != RCODE.NOERROR:
		raise QueryFailedError(f"Unable to find domain\nQuery failed; RCODE={header.rcode}")

	# Parse the question section #2
	for k in range(header.q):
		q = DNSQuestion.parse(buff)
	
	# Parse the answer section #3
	for k in range(header.a):
		a = RR.parse(buff)
		if a.rtype == QTYPE.A:
			answer = a.rdata
		elif a.rtype == QTYPE.CNAME and answer == None:
			answer = (a.rdata, a.rtype)
	  
  # Parse the authority section #4
	for k in range(header.auth):
		auth = RR.parse(buff)
		authoritative_resp.append(auth)
	  
  # Parse the additional section #5
	for k in range(header.ar):
		adr = RR.parse(buff)
		additional_resp.append(adr)

		if adr.rtype == 1:
			cache_server(str(adr.rname)[:-1], str(adr.rdata), domain)
	
	valid_servers = []

	# If there is an IPv4 answer, then return that, otherwise return list of valid servers to check
	if answer != None or header.auth == 0:
		return answer
	else:
		for server in authoritative_resp:
			valid_servers.append(str(server.rdata))
	
	return valid_servers

  
if __name__ == '__main__':
	# Create a UDP socket
	sock = socket(AF_INET, SOCK_DGRAM)
	sock.settimeout(2)

	# The main program loop
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