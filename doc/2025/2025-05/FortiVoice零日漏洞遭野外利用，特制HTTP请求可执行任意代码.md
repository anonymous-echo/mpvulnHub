#  FortiVoice零日漏洞遭野外利用，特制HTTP请求可执行任意代码   
 FreeBuf   2025-05-14 11:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38xyNIp0kYIkmaicicgibRRp3oVz8l7hcOYbUtLD7WSlibj8nNqjhTX532sn0icccN1Q3mQ4vme9bVuYuw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
Fortinet公司近日披露了一个关键级基于栈的缓冲区溢出漏洞（CVE-2025-32756），该漏洞影响其安全产品线中的多款产品，且已确认有攻击者针对FortiVoice系统实施野外利用。  
  
  
这个CVSS评分为9.6的漏洞允许远程未认证攻击者通过特制HTTP请求执行任意代码或命令，可能使攻击者完全控制受影响设备。该安全漏洞被归类为基于栈的缓冲区溢出，影响FortiVoice、FortiMail、FortiNDR、FortiRecorder和FortiCamera产品的多个版本。  
  
  
Fortinet安全研究人员在观察到针对FortiVoice部署的主动利用尝试后发现该漏洞。2025年5月13日官方披露漏洞后，Fortinet立即为所有受影响产品发布安全补丁。  
  
### Part01  
### 漏洞详情  
  
  
Fortinet安全公告指出："FortiVoice、FortiMail、FortiNDR、FortiRecorder和FortiCamera产品中存在的基于栈的溢出漏洞[CWE-121]，可能允许远程未认证攻击者通过构造的HTTP请求执行任意代码或命令。"此类漏洞尤其危险，因为它无需认证即可远程利用，使攻击者能完全掌控被入侵系统。  
  
  
在至少一起已确认的事件中，威胁行为者利用该漏洞入侵FortiVoice系统实施以下恶意操作：  
- 扫描内网资产  
  
- 启用FCGI调试功能窃取凭证  
  
- 清除崩溃日志以销毁证据  
  
### Part02  
### 已观测的攻击模式  
  
  
Fortinet记录了威胁行为者利用该漏洞攻击FortiVoice部署的具体活动。观测到的攻击模式包括网络侦察、故意删除系统崩溃日志以隐藏恶意活动，以及启用FCGI调试功能以捕获系统凭证或记录SSH登录尝试。  
  
  
安全研究人员已识别出与这些攻击相关的多个入侵指标（IoCs），包括httpd跟踪日志中的可疑条目、对系统文件的未授权修改，以及设计用于外泄敏感信息的恶意cron任务。已确认6个IP地址与攻击活动相关，包括 198.105.127.124 和 218.187.69.244。  
  
  
**FortiVoice零日漏洞(CVE-2025-32756)入侵指标**  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR38xyNIp0kYIkmaicicgibRRp3oMJL4FOBTN5t1iaiaq7Kurcd15kibrNSaY3qzgavffYD5r8Zj6GOibdldYQ/640?wx_fmt=png&from=appmsg "")  
  
  
### Part03  
### 受影响版本与缓解措施  
  
  
该漏洞影响Fortinet产品线中的多个版本。FortiVoice 6.4.0至6.4.10、7.0.0至7.0.6以及7.2.0版本均存在风险，需立即更新。同样，FortiMail（最高7.6.2）、FortiNDR（所有1.x版本和7.6.1之前的7.x版本）、FortiRecorder（最高7.2.3）和FortiCamera（最高2.1.3）的多个版本也受影响。  
  
  
Fortinet强烈建议客户尽快更新至最新修补版本。  
可以通过以下命令检测FCGI调试是否被恶意启用：  
```
diag debug application fcgi
```  
  
  
若返回结果包含：  
```
general to-file ENABLED
```  
  
则表明系统可能已遭入侵。  
  
  
若无法立即安装补丁，Fortinet建议采取以下临时措施：  
- 禁用HTTP/HTTPS管理接口  
  
- 将管理访问限制在可信内网范围  
  
- 监控受影响设备是否存在已知入侵指标  
  
此次事件延续了近年来Fortinet产品频现安全漏洞的模式。2025年初，Fortinet修补了另一个同样被野外利用的关键漏洞（CVE-2024-55591）。2022年底，Fortinet曾修复一个被中俄网络间谍组织积极利用的身份验证绕过漏洞（CVE-2022-40684）。  
  
  
安全专家强调，像FortiVoice这样的网络安全设备因其在企业网络中的特权地位和对敏感通信的访问权限，成为攻击者的高价值目标。使用任何受影响Fortinet产品的组织应优先处理此安全公告，立即实施建议的缓解措施。  
  
  
**参考来源：**  
  
**FortiVoice 0-day Vulnerability Exploited in the Wild to Execute Arbitrary Code**https://cybersecuritynews.com/fortivoice-0-day-vulnerability/  
  
  
###   
###   
###   
### 推荐阅读  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651320343&idx=1&sn=4092a85b3c9cd6eea8dc0dcb48620652&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
