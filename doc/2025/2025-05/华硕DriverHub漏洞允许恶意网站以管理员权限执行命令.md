#  华硕DriverHub漏洞允许恶意网站以管理员权限执行命令   
 FreeBuf   2025-05-13 10:16  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ibOLMac5XMiaCZbZsyz6bOticUrUTg6Kn77X3waVTdSPSNLlFjRes640ibiaCKUdh4AysebNVZsHWhekw/640?wx_fmt=png&from=appmsg "")  
  
  
  
华硕DriverHub驱动程序管理工具存在一个严重的远程代码执行漏洞，可使恶意网站在安装该软件的设备上执行任意命令。  
  
### Part01  
### 漏洞发现与技术细节  
  
  
该漏洞由新西兰独立网络安全研究员Paul（化名"MrBruh"）发现。研究发现该软件对发送至DriverHub后台服务的命令验证机制存在缺陷。  
  
  
研究员利用编号为CVE-2025-3462和CVE-2025-3463的两个漏洞构建攻击链，组合后可绕过来源验证并在目标设备上触发远程代码执行。  
  
### Part02  
### DriverHub工作机制分析  
  
  
DriverHub是华硕官方驱动程序管理工具，在使用特定华硕主板时会在首次系统启动时自动安装。  
  
  
该软件在后台持续运行，自动检测主板型号及芯片组并获取最新驱动程序版本。安装后，该工具通过本地53000端口服务保持活动状态，持续检查重要驱动更新。  
  
  
值得注意的是，多数用户并不知晓该系统上常驻运行着此类服务。  
  
### Part03  
### 漏洞成因剖析  
  
  
该服务通过检查HTTP请求的Origin Header来拦截非'driverhub.asus.com'来源的请求。但验证机制存在缺陷——任何包含该字符串的网站都会被放行，即使与华硕官方门户不完全匹配。  
  
  
第二个问题在于UpdateApp端点允许DriverHub从".asus.com"域名下载并运行.exe文件，且无需用户确认。  
  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibOLMac5XMiaCZbZsyz6bOtickS6yzic2aROXf9sVZpsA3iajsXNpYPMU5iaF2opxWQaS99IwFSsty2qGQ/640?wx_fmt=jpeg&from=appmsg "")  
  
BIOS中关于DriverHub的设置（默认启用）来源：MrBruh  
  
### Part04  
### 攻击流程详解  
  
  
攻击者可针对任何运行DriverHub的用户，诱使其访问恶意网站。该网站会向本地服务'http://127.0.0.1:53000'发送"UpdateApp请求"。  
  
  
通过伪造类似'driverhub.asus.com.mrbruh.com'的Origin Header即可绕过薄弱验证，使DriverHub接受恶意指令。  
  
  
在研究员演示中，攻击指令会从华硕下载门户获取合法的华硕签名安装程序'AsusSetup.exe'，同时下载恶意.ini文件和.exe载荷。华硕签名安装程序会以管理员权限静默运行，并根据.ini文件配置启动恶意可执行文件。  
  
  
该攻击得以实现还因为工具未删除签名验证失败的文件（如.ini和载荷），这些文件下载后会保留在主机上。  
  
### Part05  
### 厂商响应与用户建议  
  
  
华硕于2025年4月8日收到漏洞报告，4月18日发布修复补丁（前一日与MrBruh完成验证）。该硬件巨头未向研究员支付漏洞披露奖金。  
  
  
厂商提交的CVE描述中淡化了问题影响："该问题仅影响主板，不涉及笔记本、台式机或其他终端设备"。此表述存在误导，因为受影响CVEs实际上涉及所有安装DriverHub的设备。  
  
  
华硕安全公告则明确建议用户立即更新："本次更新包含重要安全补丁，强烈建议用户将DriverHub升级至最新版本。用户可打开DriverHub点击'立即更新'按钮获取更新。"  
  
  
MrBruh通过证书透明度监控发现，未发现其他包含"driverhub.asus.com"字符串的TLS证书，表明该漏洞尚未被野外利用。  
  
  
若用户担忧后台服务自动下载潜在危险文件，可通过BIOS设置禁用DriverHub功能。  
  
  
**参考来源：**  
  
**ASUS DriverHub flaw let malicious sites run commands with admin rights**https://www.bleepingcomputer.com/news/security/asus-driverhub-flaw-let-malicious-sites-run-commands-with-admin-rights/  
  
  
###   
###   
###   
### 推荐阅读  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651320016&idx=1&sn=8488591c0f5d5cf6414cef9bfa60bf62&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
****  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
