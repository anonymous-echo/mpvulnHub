#  多个僵尸网络利用一年前的 TP-Link 漏洞进行路由器攻击   
 网络安全应急技术国家工程中心   2024-04-22 15:53  
  
目前发现至少有六种不同的僵尸网络恶意软件正在利用去年命令注入安全问题影响的 TP-Link Archer AX21 (AX1800) 路由器。该缺陷编号为 CVE-2023-1389，是可通过 TP-Link Archer AX21 Web 管理界面访问的区域设置 API 中的高严重性未经身份验证的命令注入问题。  
  
研究人员于 2023 年 1 月发现了该问题，并通过零日计划 (ZDI) 向供应商报告。TP-Link 于 2023 年 3 月通过发布固件安全更新解决了该问题，在安全公告公开后不久，概念验证漏洞利用代码就出现了。  
  
随后，网络安全团队就多个僵尸网络发出警告，包括三个 Mirai 变体（1、2、3）和一个名为“ Condi ”的僵尸网络，其目标是未打补丁的设备。  
  
本周，Fortinet 再次发出警告，称其观察到利用该漏洞的恶意活动激增，并指出该漏洞源自六次僵尸网络操作。  
  
Fortinet 的遥测数据显示，从 2024 年 3 月开始，利用 CVE-2023-1389 的每日感染尝试通常超过 40000 次，最高可达 50000 次。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/wpkib3J60o2ibgz4n38cwMFudY16uP5iaVT8WoccQjqBBrhObwfP1kZPBT2Xhw3WDlzNYS36V9IS6b5vzE13YTuNw/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
有关 CVE-2023-1389的活动图  
  
针对这个漏洞的多起攻击，重点关注 Moobot、Miori、基于 Golang 的代理AGoent和 Gafgyt 变体等僵尸网络。每个僵尸网络都利用不同的方法和脚本来利用漏洞，建立对受感染设备的控制，并命令它们参与分布式拒绝服务 (DDoS) 攻击等恶意活动。  
  
AGoent：下载并执行从远程服务器获取并运行 ELF 文件的脚本，然后擦除文件以隐藏痕迹。  
  
Gafgyt变体：通过下载脚本来执行 Linux 二进制文件并维护与 C&C 服务器的持久连接，专门从事 DDoS 攻击。  
  
Moobot：以发起 DDoS 攻击而闻名，它获取并执行脚本来下载 ELF 文件，根据架构执行它们，然后删除痕迹。  
  
Miori：利用 HTTP 和 TFTP 下载 ELF 文件，执行它们，并使用硬编码凭据进行暴力攻击。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/wpkib3J60o2ibgz4n38cwMFudY16uP5iaVTsEaTJoC6QCsklLdAjnic9LMNoF6TUbzHCNfBVL1H2Qltia1icKD9A95lg/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
Miori 用于暴力破解帐户的凭据列表  
  
Mirai变体：下载一个脚本，随后获取使用 UPX 压缩的 ELF 文件 ，监视和终止数据包分析工具以避免检测。  
  
Condi：使用下载程序脚本来提高感染率，防止设备重新启动以保持持久性，并扫描并终止特定进程以避免检测。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibgz4n38cwMFudY16uP5iaVTYVYkWKP2bC96mTTgR2bfiaRd21trRghlVuEvPhjQnk4Zg4EZOqufuJQ/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
Fortinet 表示，尽管供应商去年发布了安全更新，但仍有大量用户在继续使用过时的固件。建议 TP-Link Archer AX21 (AX1800) 路由器用户遵循供应商的固件升级说明进行安全更新，并将默认的管理员密码更改为较长的密码，并在不需要时禁用对管理面板的网络访问。  
  
**参考及来源：**  
  
https://www.bleepingcomputer.com/news/security/multiple-botnets-exploiting-one-year-old-tp-link-flaw-to-hack-routers/  
  
  
  
原文来源  
：嘶吼专业版  
  
“投稿联系方式：010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176n1NvL0JsVSB8lNDX2FCGZjW0HGfDVnFao65ic4fx6Rv4qylYEAbia4AU3V2Zz801UlicBcLeZ6gS6tg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
