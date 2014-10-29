"""
This script receives a list of Unknown URLs from Palo Alto DB, 
searches for the categories on Fortinet database and generates a bulk-formatted list to be submitted to PA

URLs should be entered one per line.

Test a site website: https://urlfiltering.paloaltonetworks.com/TestASite.aspx
"""

import re
import argparse
from Queue import Queue
import argparse
import urllib
import urllib2
import sys
import multiprocessing
import cookielib
import random

parser = argparse.ArgumentParser(description="This script receives a list of Unknown URLs from Palo Alto DB,\nsearches for the categories on Fortinet database and generates a bulk-formatted list to be submitted to PA\n")
parser.add_argument("-f", "--url-list", dest="urlList", help="plain text file containing URLs, one URL per line", metavar="FILE", required=True)
parser.add_argument("-p", "--proxy-list", dest="proxyList", help="proxy list file. Get one at your preferred free public proxy list e.g. www.gatherproxy.com. Format: proxy:port, one per line", metavar="FILE", required=True)
parser.add_argument("-c", "--captcha", dest="captchaCode", help="The value of CaptchaCode", required=False)
parser.add_argument("-s", "--session-id", dest="sessionID", help="The value of LBD_VCID_LoginCaptcha", required=False)

args = parser.parse_args()

TIMEOUT = 10
USER_AGENT_FILE = 'user-agent_list.txt'

"""" func """
def fetchCategory(proxy, urllist):
	print "Entered fetchCategory for " + proxy
	cj = cookielib.CookieJar()
	proxy_handler = urllib2.ProxyHandler({'http': 'http://' + proxy})
	opener = urllib2.build_opener(proxy_handler, urllib2.HTTPCookieProcessor(cj))
	user_agent = random.choice(open(USER_AGENT_FILE).readlines()).strip()
	opener.addheaders = [('User-agent', user_agent)]

	for n in range(0, 3):
		url = urllist.pop()
		
		try:
				req = opener.open("http://www.fortiguard.com/ip_rep.php?data=" + url, None, timeout=TIMEOUT)
				html_response = req.read()
								
				if html_response:		
					if "Category: " in html_response:
						regex = '<h3 style="float: left">Category: ([a-zA-Z ]+)</h3>'
						message = list(set(re.findall(regex, html_response, re.MULTILINE)))
						print "["  +  str(n) + "] proxy = " + proxy + "\t url = " + url  + "\tmessage = " + str(message)
						
		except Exception, err:
				print "exception["  +  str(n) + "] proxy = " + proxy + "\t url = " + url  + "\tmessage = " + str(err)
				continue
"""
					else:
						# find "msgerr1"
						regex = '<td>Lookup(.*)</td>'
						error_message = list(set(re.findall(regex, html_response, re.MULTILINE)))
						if error_message: 
							output = "SMS=FAILED; Proxy=" + proxy_addr + "; Cookie=" + cj._cookies['www.telekom.sk']['/']['PHPSESSID'].value + "; Error=" + str(error_message)
						else:
							output = "SMS=FAILED; Proxy=" + proxy_addr + "; Cookie=" + cj._cookies['www.telekom.sk']['/']['PHPSESSID'].value + "; script error=UNABLE to parse html response"
							#output = "\n" + output + "\n---------------------*/*-------------------------\n" + html_response + "\n---------------------*/*-------------------------"
			except Exception, err:
				if "urlopen error timed out" in str(err):
					output = "SMS=MAYBE; Proxy=" + str(proxy_addr) + "; ;Error=" + str(err)
				else:
					output = "SMS=FAILED; Proxy=" + str(proxy_addr) + "; ;Error=" + str(err)
				#print "Unexpected error:", sys.exc_info()[0]    # debug only
"""

manager = multiprocessing.Manager()
urlList = manager.list()
proxyQueue = Queue()


try:
	g = open(args.proxyList, 'rb')
except:
	print "\nError opening " + str(args.proxyList) + ". Exiting..."
	exit()
	
for line in g:
    li=line.strip()
    if not li.startswith("#"):
    	proxyQueue.put(li)

try:
	h = open(args.urlList, 'rb')
except:
	print "\nError opening " + str(args.urlList) + ". Exiting..."
	exit()
	
for line in h:
    li=line.strip()
    if not li.startswith("#"):
    	urlList.append(li)
    	
pool = multiprocessing.Pool(multiprocessing.cpu_count()*10)
while not proxyQueue.empty():
	proxy_candidate = proxyQueue.get()
	pool.apply_async(fetchCategory, args=(proxy_candidate, urlList,))
pool.close()
pool.join()	