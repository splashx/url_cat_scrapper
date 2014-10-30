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
import pickle

parser = argparse.ArgumentParser(description="This script receives a list of Unknown URLs from Palo Alto DB,\nsearches for the categories on Fortinet database and generates a bulk-formatted list to be submitted to PA\n")
parser.add_argument("-f", "--url-list", dest="urlList", help="plain text file containing URLs, one URL per line", metavar="FILE", required=True)
parser.add_argument("-p", "--proxy-list", dest="proxyList", help="proxy list file. Get one at your preferred free public proxy list e.g. www.gatherproxy.com. Format: proxy:port, one per line", metavar="FILE", required=True)
parser.add_argument("-c", "--captcha", dest="captchaCode", help="The value of CaptchaCode", required=False)
parser.add_argument("-s", "--session-id", dest="sessionID", help="The value of LBD_VCID_LoginCaptcha", required=False)

args = parser.parse_args()
pickled_file = args.urlList + ".pickled"

TIMEOUT = 10
USER_AGENT_FILE = 'user-agent_list.txt'

"""" func """
def fetchCategory(proxy, urllist, urlscategorized):
	print "Entered fetchCategory1 for " + proxy
	cj = cookielib.CookieJar()
	proxy_handler = urllib2.ProxyHandler({'http': 'http://' + proxy})
	opener = urllib2.build_opener(proxy_handler, urllib2.HTTPCookieProcessor(cj))
	user_agent = random.choice(open(USER_AGENT_FILE).readlines()).strip()
	opener.addheaders = [('User-agent', user_agent)]

	for n in range(0,3):
		url = urllist.pop()
		
		if not url:
			break;
		else:
			try:
					req = opener.open("http://www.fortiguard.com/ip_rep.php?data=" + url, None, timeout=TIMEOUT)
					html_response = req.read()
					
					regex = '<h3 style="float: left">Category: ([a-zA-Z ]+)</h3>'
					reg_match = re.search(regex, html_response, re.MULTILINE)
					if reg_match:
						category = reg_match.group(1)
						urlscategorized[url] = category
					else:   #couldn't match, assuming proxy issue
						print "Appending url"
						urllist.append(url)
						return
					
					print "["  +  str(n) + "] proxy = " + proxy + "\t url = " + url  + "\tmessage = " + category
						
			except Exception, err:
					urllist.append(url)
					print "exception["  +  str(n) + "] proxy = " + proxy + "\t url = " + url  + "\tmessage = " + str(err)
					return
				
manager = multiprocessing.Manager()
urlList = manager.list()
proxyQueue = Queue()
restoredDict = dict()

try:
	f=open(pickled_file, 'rb')
	while 1:
		try:
			temp_dict= pickle.load(f)[0]
			print "loaded: ",
			print temp_dict
			restoredDict.update(temp_dict)
			print "In the while.."
		except EOFError:
			print "EOFerror"
			break
		except Exception, err:
			print "General Except" + str(err)
			break
	f.close()
	urlsCategorized = manager.dict(restoredDict)
except:
	print "[*] Unable to load " + pickled_file + ". That's okay if it's your first run.."
	urlsCategorized = manager.dict()

try:
	with open( args.proxyList, "rb") as g:
		for line in g:
		    li=line.strip()
		    if not li.startswith("#"):
		    	proxyQueue.put(li)

except:
	print "\nError on processing " + str(args.proxyList) + ". Exiting..."
	exit()
try:
	with open( args.urlList, 'rb') as h:
		for line in h:
		    li=line.strip()
		    if not li.startswith("#"):
		    	urlList.append(li)

except:
	print "\nError on processing " + str(args.urlList) + ". Exiting..."
	exit()
    	
pool = multiprocessing.Pool(multiprocessing.cpu_count()*10)
while not proxyQueue.empty() or not urlList:
	proxy_candidate = proxyQueue.get()
	pool.apply_async(fetchCategory, args=(proxy_candidate, urlList, urlsCategorized,))
pool.close()
pool.join()	

backupDict = dict(urlsCategorized)

# pickle urlsCategorized
try:
		pickledData = [backupDict]
		with open( pickled_file, "ab" ) as f:
    			pickle.dump( pickledData, f)
		print "[*] Successfully pickled to " + pickled_file
except:
		print "[*] Bummer - couldn't pickle. Resume won't be possible (this is weird..)"

try:
		with open(args.urlList, 'w') as f:
			for s in urlList:
				f.write(s + "\n")
		print "[*] Successfully updated " + str(args.urlList)
except:
		print "[*] Error while updating " + str(args.urlList)
		
print backupDict

manager.shutdown()
del manager



