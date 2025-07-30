> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkzNDIzNDUxOQ==&mid=2247500027&idx=2&sn=53f5863b82d57df201da83c7c6919937

#  WinRAR 存在目录遍历远程代码执行漏洞  
 独眼情报   2025-06-24 04:20  
  
WinRAR 开发者修补了 Windows 版本中的一个安全漏洞，该漏洞允许攻击者执行恶意代码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnS7xKYB0KyXoI7ePvtakia78EA1iat8ibc3vD3OIYEpM5NF0ibhedmoxKDlNceJib47LHsl2bKBzE21vAg/640?wx_fmt=png&from=appmsg "")  
  
在 WinRAR 的 Windows 版本中，攻击者可以利用一个安全漏洞来执行注入的恶意代码。一个修复该漏洞的测试版更新已经发布。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnS7xKYB0KyXoI7ePvtakia78iatky6Ay799CibErAakBUUGRl9ibyG4wKAGP284BMmPSGV5MX7sATvpEA/640?wx_fmt=png&from=appmsg "")  
  
在 Beta 版本 7.12b1 的公告中（目前是新闻概览页面上的第一条记录 ，直接链接稍后会指向错误的条目），WinRAR 开发者对该漏洞的描述非常简略：“在解压文件时，WinRAR、RAR、UnRAR、便携版 UnRAR 以及 UnRAR.dll 可能被迫使用一个在被篡改的压缩包中指定的路径，而非用户指定的路径。”而安全漏洞的发现者 Trend Micro 零日计划则描述得更为准确：“该特殊错误存在于处理压缩文件内路径时。一个精心构造的文件路径可能导致进程跳转到非预期目录（遍历）。攻击者可以利用此漏洞，在当前用户的上下文中执行恶意代码”（CVE-2025-6218 / 尚无 EUVD，CVSS **7.8**  
，风险等级为“ **高**  
 ”）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnS7xKYB0KyXoI7ePvtakia78Bguevg4KicZ7t7OMbC0Yh1ulGpFPxicdISWk7GB7GvOSrWBKHpvYiaFwA/640?wx_fmt=png&from=appmsg "")  
  
### WinRAR：更新版本修补安全漏洞  
  
WinRAR 开发者强调，该漏洞影响的是 Windows 版本的软件。“Unix 版本的 RAR、UnRAR、便携式 UnRAR 源码和 UnRAR 库以及 Android 版 RAR 不受影响”。该测试版还修补了其他安全漏洞。例如，在生成报告时，文件名未经过滤直接写入报告的 HTML 文件，允许注入不安全的 HTML 标签。通过将标签中的“< >”符号替换为对应的符号字符串，解决了该问题。  
  
在 WinRAR 下载页面 ，测试版较为低调地排在带有搜索过滤器的文件列表上方。可以在此直接下载 。不过，一旦开发者发布 WinRAR 7.12 的正式版本，测试版将立即下架。  
  
早在 WinRAR 7.11 版本就修复了一个安全漏洞。一个特制的符号链接可能导致 “网络标记”（Mark-of-the-Web，MotW）机制失效，从而在执行和打开来自互联网的潜在危险的解压文件时，Windows 不会弹出警告提示。  
  
  
