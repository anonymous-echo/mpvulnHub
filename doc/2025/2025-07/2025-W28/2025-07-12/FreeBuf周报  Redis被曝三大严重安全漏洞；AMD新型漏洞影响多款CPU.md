> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651324804&idx=3&sn=859f6647543d5b23c0064c147c9cec34

#  FreeBuf周报 | Redis被曝三大严重安全漏洞；AMD新型漏洞影响多款CPU  
 FreeBuf   2025-07-12 10:31  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
各位 Buffer 周末好，以下是本周「FreeBuf周报」，我们总结推荐了本周的热点资讯、一周好文，保证大家不错过本周的每一个重点！  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icJ1UiaObonmWJbuLyoLXdutZ6T0GL6AXwFA0IHVJ9Tl93JicaeTmN55VJBw0JKrJg4sQXdypbdzqibg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**🛜Redis被曝三大严重安全漏洞，PoC代码已公开**  
  
**💽AMD新型漏洞影响多款CPU，计时攻击可导致数据泄露**  
  
**🖥️Linux内核NFT子系统曝高危"双重释放"漏洞可致本地提权**  
  
**📫微软Exchange Online全球大范围宕机，数百万用户无法访问邮箱**  
  
**🍔麦当劳AI招聘工具McHire漏洞导致6400万求职者数据泄露**  
  
🔗蓝牙协议栈高危漏洞曝光，攻击可入侵奔驰、大众和斯柯达车载娱乐系统  
### 💻微软远程桌面客户端漏洞可导致攻击者远程执行代码  
### 🍎原子级 macOS 信息窃取程序升级：新增后门实现持久化控制  
### 🗃️Git项目修复三大漏洞：远程代码执行、任意文件写入与缓冲区溢出  
### 🔐Linux 启动漏洞可绕过现代 Linux 系统的安全启动保护  
###   
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icFibibPIGEfXsibI0C3or4BS5NY7KgXpwrAo5WHiaX2SOibeoicce3vxyZozGALjYSLtYPrDiceL0UV2D3A/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
###   
  
  
Redis被曝三大严重安全漏洞，PoC代码已公开  
###   
  
Redis曝三大高危漏洞：CVE-2024-51741可致服务拒绝，CVE-2024-46981允许代码执行，CVE-2025-48367引发DoS。建议升级至7.2.7/7.4.2等修复版本，并加强访问控制。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ibB6c57w7TYCsC97JxXoqaKibHlvJMlpI7RC9lNYuoIq6NGNxnibnb7r1t3yvyUU7ruTZKhJuExa6xg/640?wx_fmt=png&from=appmsg "")  
  
  
AMD新型漏洞影响多款CPU，计时攻击可导致数据泄露  
###   
###   
  
### AMD芯片组曝新型"瞬态调度攻击"漏洞，涉及多款处理器，可能导致跨特权边界信息泄露。漏洞源于CPU微架构缺陷，需恶意访问才能利用。AMD已发布微码更新修复。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibB6c57w7TYCsC97JxXoqaK6b28bIAeyGBSqplrpiaODPwCgUtxq9ob2richTZ2RkaMxUmWSFKqwrbQ/640?wx_fmt=jpeg&from=appmsg "")  
###   
  
  
Linux内核NFT子系统曝高危"双重释放"漏洞可致本地提权  
###   
###   
  
###   
  
Linux内核NFT子系统存在双重释放漏洞（5.6-rc1至6.13-rc3），攻击者通过特制netlink消息触发未初始化栈变量，导致本地提权。启用CONFIG_INIT_STACK_ALL_ZERO或应用补丁可缓解。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibB6c57w7TYCsC97JxXoqaKM8vEQx04zY5wdDF32x8atw2GAqKhCLsCSLW2JlmK6gEDBLmrbujbMQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
微软Exchange Online全球大范围宕机，数百万用户无法访问邮箱  
###   
###   
  
###   
  
2025年7月10日，微软Exchange Online全球故障持续11小时，影响数百万用户访问邮箱，主要因身份验证组件问题。微软迅速响应并部署修复，其他Microsoft 365服务未受影响。此为2025年微软系列宕机中较严重的一次。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibB6c57w7TYCsC97JxXoqaKtF0MNzP9bnyUvfYbG6wgk7PRILZvLKV0H9PoUVWYn2EZDPJiabkiaTPA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
麦当劳AI招聘工具McHire漏洞导致6400万求职者数据泄露  
  
麦当劳AI招聘工具McHire因IDOR漏洞和弱默认凭证暴露6400万求职者敏感数据，包括联系方式等。开发方Paradox.ai迅速修复漏洞，专家警示AI应用需强化安全防护与治理机制。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibB6c57w7TYCsC97JxXoqaK05zDYB8nRxA63geeQcQKN22nwHy8tub1ITl4ws9o7h5XSxp2SAlFicw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
蓝牙协议栈高危漏洞曝光，攻击可入侵奔驰、大众和斯柯达车载娱乐系统  
  
OpenSynergy BlueSDK蓝牙协议栈存在"完美蓝"漏洞，可远程入侵数百万辆汽车系统，实现代码执行、数据窃取及关键功能操控。梅赛德斯、大众等品牌受影响，用户需更新系统或禁用蓝牙。漏洞含4个CVE，最高8.0分。厂商已修复，但供应链延迟导致近期公开披露。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ibB6c57w7TYCsC97JxXoqaKYGDs6SBb3fst1lptrboicvI37Bezia0xsCKgf5HjIp7Lu9D8GPL1icePw/640?wx_fmt=png&from=appmsg "")  
  
  
微软远程桌面客户端漏洞可导致攻击者远程执行代码  
###   
  
###   
  
###   
  
###   
  
微软远程桌面客户端存在高危漏洞CVE-2025-48817（CVSS 8.8），攻击者可通过恶意RDP服务器在客户端执行任意代码，影响Windows 7至11 24H2所有版本。微软已发布补丁，建议立即更新。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibB6c57w7TYCsC97JxXoqaKWjZj9icNaicibqN0Rd1WzUkygrPeFpI9YrDibbsZ7x3ammOqV9pwhmWLhg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
原子级 macOS 信息窃取程序升级：新增后门实现持久化控制  
  
###   
  
###   
  
###   
  
###   
  
AMOS恶意软件升级植入后门，可长期控制Mac设备，已渗透120多国。通过盗版软件和钓鱼攻击传播，模仿朝鲜黑客模式但更隐蔽。专家建议安装防护软件、警惕社交工程，全球安全团队正监控威胁。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibB6c57w7TYCsC97JxXoqaKA3dJicf2vaoAvYemde6f55Sm37MNic1vAG6ib0tQYia29sYAic9u2tB5icjA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
Git项目修复三大漏洞：远程代码执行、任意文件写入与缓冲区溢出  
  
###   
  
###   
###   
  
###   
  
###   
  
Git修复三个高危漏洞：克隆时可远程执行代码（CVE-2025-48384）、Bundle-URI注入任意文件写入（CVE-2025-48385）和Windows凭据缓冲区溢出（CVE-2025-48386）。建议立即升级至v2.50.1或长期支持版本。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibB6c57w7TYCsC97JxXoqaK5t0349FYxnLIjA457cC9aG7ibFLlZ2leKYBRkAHmTPHWTAIVrzhO5uQ/640?wx_fmt=other&from=appmsg "")  
  
  
  
Linux 启动漏洞可绕过现代 Linux 系统的安全启动保护  
  
###   
  
###   
###   
  
###   
  
###   
  
现代Linux发行版存在initramfs漏洞，攻击者通过物理接触利用调试shell绕过安全启动，注入持久性恶意软件。Ubuntu、Debian、Fedora等受影响，OpenSUSE免疫。建议修改内核参数禁用调试shell或启用高级加密方案防护。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibB6c57w7TYCsC97JxXoqaKSJIKEo4Kd0e4ic3KmgvRXStFffeMAruaCBvxUlTbZIsrA8ADeUVxkOQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icFibibPIGEfXsibI0C3or4BS5Ce9OricKgAogLRlHYat9jaelbVESLOylPBnQQrU63TlHEs2zCbdNrKg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**本周好文推荐指数**  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icFibibPIGEfXsibI0C3or4BS59ZQ6EsSUehyHWzxq6tIFG5b5TmautNPF3E0YDL2xav0dFmmibp2oT0w/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icFibibPIGEfXsibI0C3or4BS59ZQ6EsSUehyHWzxq6tIFG5b5TmautNPF3E0YDL2xav0dFmmibp2oT0w/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icFibibPIGEfXsibI0C3or4BS59ZQ6EsSUehyHWzxq6tIFG5b5TmautNPF3E0YDL2xav0dFmmibp2oT0w/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icFibibPIGEfXsibI0C3or4BS59ZQ6EsSUehyHWzxq6tIFG5b5TmautNPF3E0YDL2xav0dFmmibp2oT0w/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icFibibPIGEfXsibI0C3or4BS59ZQ6EsSUehyHWzxq6tIFG5b5TmautNPF3E0YDL2xav0dFmmibp2oT0w/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
###   
  
  
EarthWorm隧道代理  
###   
###   
  
### 实验通过EarthWorm隧道代理在Windows和Linux服务器上建立反向代理，横向扫描内网并爆破口令，成功获取域账户密码，验证了隧道代理在内网渗透中的有效性。  
  
![隧道代理技术：加密通信和绕过防火墙的利器-zh-hans](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ibB6c57w7TYCsC97JxXoqaKNavaicNW1MFibXMqup92kLrPDXWeVLnnVnfVcibQtY9y3iaeF0rfX5aqQg/640?wx_fmt=png&from=appmsg "")  
  
  
破 WAF | 寻新迹象  
###   
###   
  
### 帆软报表工具/view/ReportServer接口存在模板注入漏洞，可执行SQL写入Webshell。研究发现WAF拦截逻辑缺陷，通过${($a(任意))}绕过检测，利用SQL函数执行恶意代码。同时发现TOIMAGE函数存在SSRF漏洞，需结合SSTI利用。总结WAF绕过可从应用层或底层逻辑入手。  
  
![什么是WAF（Web应用程序防火墙）？ - 知乎](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibB6c57w7TYCsC97JxXoqaKvsCuYHCzv3fp7icvibEb65ibrjia99ciaicEYWGb9CCBepxV8wibt4zDwIIzw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
Apache中间件安全加固实验  
###   
###   
  
###   
  
### 实验指导对Apache进行安全加固，包括隐藏版本信息、禁止目录列表、自定义错误页面、删除无用文件、禁用TRACE方法、修改监听端口、限制客户端IP、启用日志功能及严格文件权限设置，以提升服务器安全性。  
###   
###   
  
  
###   
###   
###   
### 推荐阅读  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651324737&idx=1&sn=8f0843cf1d51ac50bd1eae4a5f0e4c87&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
