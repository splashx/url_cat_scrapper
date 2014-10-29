from threading import Thread
from Queue import Queue
import argparse
import urllib
import urllib2
import sys
import multiprocessing

parser = argparse.ArgumentParser(description="This script receives a list of Unknown URLs from Palo Alto DB,\nsearches for the categories on Fortinet database and generates a bulk-formatted list to be submitted to PA\n")
parser.add_argument("-p", "--proxy-list", dest="proxyList", help="proxy list file. Get one at your preferred free public proxy list e.g. www.gatherproxy.com. Format: proxy:port, one per line", metavar="FILE", required=True)

TIMEOUT = 5
args = parser.parse_args()
prxyList = list()
workingProxies_filename = args.proxyList + "_working"


"""" func """
def check_proxy(q, working_set):
	proxy_addr = q
	print "Spawning process for: " + proxy_addr
	proxy_handler = urllib2.ProxyHandler({'http': 'http://' + proxy_addr})
	opener = urllib2.build_opener(proxy_handler)
	#user_agent = random.choice(open(user_agent_file).readlines()).strip()
	#opener.addheaders = [(random.choice(open('user-agent_list.txt').readlines()))]
	#opener.addheaders = [('User-agent', user_agent)]
		
	try:
		req = opener.open("http://www.google.com", None, timeout=TIMEOUT)
	except:
		sys.exc_clear()
	else:
		working_set.append(proxy_addr)
		print "working_set = " + str(len(working_set))
		print "Sucess for " + proxy_addr
	
#	q.task_done()
"""" app """

try:
	g = open(args.proxyList, 'rb')
except:
	print "\nError opening " + str(args.proxyList) + ". Exiting..."
	exit()
	
for line in g:
    li=line.strip()
    if not li.startswith("#"):
    	prxyList.append(li)

manager = multiprocessing.Manager()
workingProxies = manager.list()

queue = Queue()

for line in prxyList:
	queue.put(line)   #enqueuing every proxy entry to be processed later

pool = multiprocessing.Pool(multiprocessing.cpu_count()*10)
while not queue.empty():
	pool.apply_async(check_proxy, args=(queue.get(),workingProxies,))
	queue.task_done()
pool.close()
pool.join()	

file = open(workingProxies_filename, "w")

for i in workingProxies:
	file.write(i + "\n")
file.close()

try:
	num_lines = sum(1 for line in open(args.proxyList))
except:
	pass
else:
	print str(len(workingProxies)) + "\t Works\n" + str(num_lines) + "\t Total"  

sys.exit()