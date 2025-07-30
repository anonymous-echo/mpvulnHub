#  SploitScan帮你发现最新漏洞   
原创 黑客驰HackerChi  黑客驰   2024-05-06 18:36  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/Tw5YEdrIeWbUhPCTr1TRIGc1WxPicGOgOGtNPf8AD6WcpPfJHYgBrVKbpmrJ8NfniaTbibNgrl1K2YXJyWXAAsFZw/640?wx_fmt=gif&from=appmsg "")  
> ❝  
> 欢迎访问我们的网站和关注我们的公众号，获取最新的  
免费资源、安全知识、信息流。                    
  
网站：**https://hackerchi.top**  
                                                       
  
信息流：**https://hackerchi.top/Feeds.html**  
  
公众号：  
黑客驰          
  
> ❞  
  
  
  
  
💡  
免责声明  
：本文章中的信息和观点仅代表引用网站或者原作者，本网站只是引用其观点、内容，不代表本网站、公众号、黑客驰本人的观点或立场。本文章论述内容仅作为教育参考使用，如有违法行为与本网站和黑客驰无关，国法无情，自行负责。  
  
🗣  
关注我们的公众号"  
黑客驰  
"，  
收藏  
我们的文章，  
转发  
给你的朋友们，让更多的人了解到这些有用的知识！网站  
实时更新  
，请访问**官网[1]**  
，给个免费的赞！  
打赏  
点咖啡钱更好！  
  
📢  
将我们的  
公众号内容加星  
获得  
隐藏内容。  
> ❝  
> SploitScan 是一款功能强大且用户友好的工具，旨在简化识别已知漏洞的利用及其各自的利用概率的过程。使网络安全专业人员能够快速识别和应用已知的漏洞并进行测试。对于寻求增强安全措施或针对新兴威胁制定强大的检测策略的专业人士来说，它尤其有价值。  
  
> ❞  
  
# SploitScan  
  
 描述  
  
SploitScan 是一款功能强大且用户友好的工具，旨在简化识别已知漏洞的利用及其各自的利用概率的过程。使网络安全专业人员能够快速识别和应用已知的漏洞并进行测试。对于寻求增强安全措施或针对新兴威胁制定强大的检测策略的专业人士来说，它尤其有价值。  
  
特点  
- CVE 信息检索  
  
- EPSS 集成  
  
- 公共漏洞聚合  
  
- CISA KEV  
  
- 修补优先级系统  
  
- 多 CVE 支持和导出选项  
  
- 漏洞扫描程序导入  
  
- 用户友好的界面  
  
- 全面的安全工具  
  
 支持的漏洞利用数据库  
- **GitHub[2]**  
  
- **利用数据库[3]**  
  
- **VulnCheck[4]**  
免费的（需要VulnCheck API 密钥）  
  
 支持漏洞扫描仪导入  
- **Nessus[5]**  
 (.nessus)  
  
- **Nexpose[6]**  
 (.xml)  
  
- **OpenVAS[7]**  
 (.xml)  
  
## 用法  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Tw5YEdrIeWbUhPCTr1TRIGc1WxPicGOgOfkxCVQ1u0yrVH367puHbosicAQJSzqPsJY3eyq7pMG4Nx4c0eepCjzQ/640?wx_fmt=png&from=appmsg "")  
  
常规的：  
```
```  
  
输入一个或多个 CVE ID 以获取数据。用空格分隔多个 CVE ID。  
```
```  
  
可选：导入功能。指定类型：“nessus”、“nexpose”或“openvas”并导入文件。  
```
```  
  
可选：将结果导出到 JSON 或 CSV 文件。指定格式：“json”或“csv”。  
```
```  
  
Docker使用  
```
```  
  
 补丁优先级系统  
  
SploitScan 中的补丁优先级系统提供了一种根据漏洞的严重性和可利用性对安全补丁进行优先级排序的战略方法。它受到**CVE Prioritizer[8]**模型的影响，并增强了处理公开可用漏洞的功能。它的工作原理如下：  
- A+ 优先级：分配给 CISA 的 KEV 中列出的 CVE 或具有公开可用漏洞的 CVE。这反映了修补的最高风险和紧迫性。  
  
- A 到 D 优先级：基于 CVSS 分数和 EPSS 概率百分比的组合。决策矩阵如下：  
  
- 答：CVSS 分数 >= 6.0，EPSS 分数 >= 0.2。严重性高，被利用的可能性很大。  
  
- B：CVSS 分数 >= 6.0，但 EPSS 分数 < 0.2。严重性高，但被利用的可能性较低。  
  
- C：CVSS 分数 < 6.0 且 EPSS 分数 >= 0.2。严重程度较低，但被利用的可能性较高。  
  
- D：CVSS 评分 < 6.0，EPSS 评分 < 0.2。严重程度较低，被利用的可能性也较低。  
  
该系统可帮助用户在考虑其潜在影响和被利用的可能性的情况下，就首先修补哪些漏洞做出明智的决定。可以根据您的业务需求更改阈值。  
### 参考资料  
  
[1]  
官网: https://hackerchi.top/  
  
[2]  
GitHub: https://poc-in-github.motikan2010.net/  
  
[3]  
利用数据库: https://www.exploit-db.com/  
  
[4]  
VulnCheck: https://vulncheck.com/  
  
[5]  
Nessus: https://www.tenable.com/products/nessus  
  
[6]  
Nexpose: https://www.rapid7.com/products/nexpose/  
  
[7]  
OpenVAS: https://www.openvas.org/  
  
[8]  
CVE Prioritizer: https://github.com/TURROKS/CVE_Prioritizer  
  
  
