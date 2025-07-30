#  【高危安全通告】关于curl/libcurl的SOCKS5堆缓冲区溢出漏洞   
 海青安全研究实验室   2023-10-12 16:57  
  
↑ 点击上方  
   
关注我们  
  
近日，安全狗应急响应中心监测到  
curl/libcurl被披露出存在SOCKS5堆缓冲区溢出漏洞，可导致应用功能组件、RPM依赖及大多数集成了libcurl的操作系统受到影响。  
  
**漏洞描述**  
  
  
  
curl  
是一个命令行工具和库，用于传输数据，特别是通过各种网络协议，如  
HTTP、HTTPS、FTP等。它允许用户从终端或脚本中发送网络请求并获取响应，通常用于与Web服务器进行数据交互，下载文件，测试API，以及执行各种与网络通信相关的任务。  
  
于  
UTC10月11日06:00，  
curl  
命令行工具的作者  
Stenberg发布了8.4.0版本的  
curl  
。这个版本修复了两个漏洞，分别是  
CVE-2023-38545和CVE-2023-38546。由于这两个漏洞是基于  
libcurl  
存在的，因此可能对广泛范围内的系统和应用产生影响。其中  
CVE-2023-38545具有较高的危害性。  
  
根据  
curl  
发布的公告，这次漏洞主要是由于  
SOCKS5协议的缓冲区溢出引起的。当应用程序通过  
curl  
库设置了较小的缓冲区大小或由于服务器响应延迟等原因，都有可能触发这个漏洞。  
  
就漏洞利用可能性与危害进行分析，做出以下研判。首先，该漏洞所涉软件版本范围有限（  
7.69.0 <= libcurl < 8.4.0），大多数的系统不会受到影响，如CentOS7.9默认curl版本为7.29并未受到影响；其次，该漏洞的触发需由libcurl通过 socks 代理的情况下，访问攻击者可控制的地址，直接进行远程利用难度较大；并且，在黑盒场景难以利用该漏洞，虽然造成拒绝服务比较容易，但还需要根据具体的应用、操作系统平台进行构造才能造成远程代码执行。综上所述，该漏洞危害程度并没有那么高，不过受影响的用户还是需要关注。  
  
  
  
**安全通告信息**  
  
  
<table><tbody><tr><td width="231" valign="top" style="word-break: break-all;"><p><strong><span style="font-family: 宋体;font-size: 10.5pt;">漏洞名称</span></strong></p></td><td width="285" valign="top" style="word-break: break-all;"><p><strong><span style="font-family: 宋体;font-size: 10.5pt;">SOCKS5堆缓冲区溢出漏洞</span></strong></p></td></tr><tr><td width="231" valign="top" style="word-break: break-all;"><p><span style="mso-spacerun:&#39;yes&#39;;font-family:宋体;font-size:10.5000pt;mso-font-kerning:0.0000pt;">漏洞影响</span><span style="mso-spacerun:&#39;yes&#39;;font-family:宋体;font-size:10.5000pt;mso-font-kerning:0.0000pt;">版本</span></p></td><td width="285" valign="top" style="word-break: break-all;"><p><span style="mso-spacerun:&#39;yes&#39;;font-family:宋体;font-size:10.5000pt;mso-font-kerning:0.0000pt;">7.69.0 &lt;= libcurl &lt; 8.4.0</span></p></td></tr><tr><td width="231" valign="top" style="word-break: break-all;"><p><span style="mso-spacerun:&#39;yes&#39;;font-family:宋体;font-size:10.5000pt;mso-font-kerning:0.0000pt;">漏洞危害等级</span></p></td><td width="285" valign="top" style="word-break: break-all;"><p><span style="mso-spacerun:&#39;yes&#39;;font-family:宋体;font-size:10.5000pt;mso-font-kerning:0.0000pt;">高危</span></p></td></tr><tr><td width="231" valign="top" style="word-break: break-all;"><p><span style="mso-spacerun:&#39;yes&#39;;font-family:宋体;font-size:10.5000pt;mso-font-kerning:0.0000pt;">厂商是否已发布</span><span style="mso-spacerun:&#39;yes&#39;;font-family:宋体;font-size:10.5000pt;mso-font-kerning:0.0000pt;">漏洞补</span><span style="mso-spacerun:&#39;yes&#39;;font-family:宋体;font-size:10.5000pt;mso-font-kerning:0.0000pt;">丁</span></p></td><td width="285" valign="top" style="word-break: break-all;"><p><span style="mso-spacerun:&#39;yes&#39;;font-family:宋体;font-size:10.5000pt;mso-font-kerning:0.0000pt;">是</span></p></td></tr><tr><td width="231" valign="top" style="word-break: break-all;"><p><span style="mso-spacerun:&#39;yes&#39;;font-family:宋体;font-size:10.5000pt;mso-font-kerning:0.0000pt;">版本更新地址</span></p></td><td width="285" valign="top" style="word-break: break-all;"><p style="word-break: break-all;"><span style="font-family: 宋体;font-size: 10.5pt;">https://github.com/curl/curl</span></p></td></tr><tr><td width="231" valign="top" style="word-break: break-all;"><p><span style="mso-spacerun:&#39;yes&#39;;font-family:宋体;font-size:10.5000pt;mso-font-kerning:0.0000pt;">安全狗总预警期数</span></p></td><td width="285" valign="top" style="word-break: break-all;"><p><span style="mso-spacerun:&#39;yes&#39;;font-family:宋体;font-size:10.5000pt;mso-font-kerning:0.0000pt;">266</span></p></td></tr><tr><td width="231" valign="top" style="word-break: break-all;"><p><span style="mso-spacerun:&#39;yes&#39;;font-family:宋体;font-size:10.5000pt;mso-font-kerning:0.0000pt;">安全狗发布预警日期</span></p></td><td width="285" valign="top" style="word-break: break-all;"><p><span style="mso-spacerun:&#39;yes&#39;;font-family:宋体;font-size:10.5000pt;mso-font-kerning:0.0000pt;">2023年10月12日</span></p></td></tr><tr><td width="231" valign="top" style="word-break: break-all;"><p><span style="mso-spacerun:&#39;yes&#39;;font-family:宋体;font-size:10.5000pt;mso-font-kerning:0.0000pt;">安全狗更新预警日期</span></p></td><td width="285" valign="top" style="word-break: break-all;"><p><span style="mso-spacerun:&#39;yes&#39;;font-family:宋体;font-size:10.5000pt;mso-font-kerning:0.0000pt;">2023年10月12日</span></p></td></tr><tr><td width="231" valign="top" style="word-break: break-all;"><p><span style="mso-spacerun:&#39;yes&#39;;font-family:宋体;font-size:10.5000pt;mso-font-kerning:0.0000pt;">发布者</span></p></td><td width="285" valign="top" style="word-break: break-all;"><p><span style="mso-spacerun:&#39;yes&#39;;font-family:宋体;font-size:10.5000pt;mso-font-kerning:0.0000pt;">安全狗海青实验室</span></p></td></tr></tbody></table>  
  
**安全建议**  
  
  
  
1、  
Linux/MacOS用户可通过以下命令可查看curl是否为安全版本：  
```
find / -name curl 2>/dev/null -exec echo "Found: {}" \; -exec {} --version \;
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/tLPRyPAiapwLMSEQibEiamCF0g94b8GOszlE6YRYcC6bOGPiaiaCeVFrAa48Bc6nibB1gy7qtEZsNdmwJXvntFwibMFicA/640?wx_fmt=png "")  
  
Windows用户可通过以下命令可查看curl是否为安全版本：  
```
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue -Filter curl.exe | ForEach-Object { Write-Host "Found: $($_.FullName)"; & $_.FullName --version }
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/tLPRyPAiapwLMSEQibEiamCF0g94b8GOszlwfNibZ6YCxicib1r9aZ4B0zxlQxoYNWxrHL0iap7Rdsfda1zUeNvDcKjCw/640?wx_fmt=png "")  
## 2、软件更新  
  
curl官方已经发布了解决此漏洞的软件更新，建议受影响用户尽快前往以下地址升级到  
安全版本。  
(https://github.com/curl/curl)  
  
3、其他  
  
避免将   
CURLPROXY_SOCKS5_HOSTNAME 代理与 curl 一起使用  
  
避免将代理环境变量设置为   
socks5h://  
  
  
**安全狗产品解决方案**  
  
  
  
若想了解更多  
安全狗  
产品信息或有相关业务需求，可  
前往安全狗官网了解：  
https://www.safedog.cn/  
  
  
**0****1**  
  
  
**云眼·新一代（云）主机入侵检测及安全管理系统**  
  
安全狗云眼采用Gartner提出的CWPP理念，提出了以工作负载为中心，以自动化、细粒度资产采集为基础，提供多种风险排查和漏洞发现手段，依托反杀伤链和实时入侵检测响应能力支撑企业安全防护二道防线，解决现代混合云、多云数据中心基础架构中服务器工作负载的安全需求，最终达到对已知威胁的自动响应以及对潜在威胁的检测识别。  
  
**0****2**  
  
  
**云御·新一代混合式web应用防护系统**  
  
云御是一款新一代混合式Web防火墙产品，通过网络层过滤和主机应用层自保护（RASP）相结合的技术，既能够过滤传统常见的攻击又可以对异常变形和未知漏洞的高级攻击进行识别，达到双层纵深防御的效果。  
  
**0****3**  
  
  
**云网·（云）主机漏洞发现及补丁修复系统**  
  
安全狗  
云网·发现及补丁修复系统可以为用户构建属于自己的补丁大数据仓库，用于修补可能导致安全薄弱、破坏关键系统数据或导致系统不可用的漏洞。云网不仅可以进行补丁部署，还可扫描网络漏洞、识别缺失的安全补丁和修补程序，并立即部署以降低网络空间风险。  
  
  
**参考链接**  
  
  
  
https://curl.se/docs/CVE-2023-38545.html  
  
https://www.intruder.io/blog/curl-high-rated-cve-2023-38545  
  
  
  
