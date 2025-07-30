#  Mirai 僵尸网络变体利用四信路由器漏洞进行 DDoS 攻击   
 信息安全大事件   2025-01-08 12:11  
  
自   
2024 年 11 月初以来，已发现一个 Mirai 僵尸网络变体利用新披露的安全漏洞影响四信工业路由器，目的是进行分布式拒绝服务 （DDoS） 攻击。  
  
该僵尸网络每天维护大约   
15,000 个活跃 IP 地址，感染主要分布在中国、伊朗、俄罗斯、土耳其和美国。  
  
该恶意软件利用   
20 多个已知的安全漏洞和薄弱的 Telnet 凭据进行初始访问，已知自 2024 年 2 月以来一直活跃。该僵尸网络被称为“gayfemboy”，指的是源代码中存在的冒犯性术语。  
  
奇安信   
XLab 表示，它观察到该恶意软件利用中国四信制造的工业路由器中的零日漏洞，最早在 2024 年 11 月 9 日就分发了这些工件。  
  
有问题的漏洞是   
CVE-2024-12856（CVSS 评分：7.2），它指的是一个操作系统 （OS） 命令注入错误，通过利用未更改的默认凭据影响路由器型号 F3x24 和 F3x36。  
  
上个月末，VulnCheck 告诉 The Hacker News，该漏洞已被广泛利用，在受感染的设备上投放反向 shell 和类似 Mirai 的有效载荷。  
  
僵尸网络利用其他一些安全漏洞来扩展其覆盖范围和规模，包括   
CVE-2013-3307、CVE-2013-7471、CVE-2014-8361、CVE-2016-20016、CVE-2017-17215、CVE-2017-5259、CVE-2020-25499、CVE-2020-9054、CVE-2021-35394、CVE-2023-26801、CVE-2024-8956 和 CVE-2024-8957。  
  
一旦启动，恶意软件就会尝试隐藏恶意进程并实施基于   
Mirai 的命令格式来扫描易受攻击的设备、自我更新并针对感兴趣的目标发起 DDoS 攻击。  
  
利用僵尸网络的   
DDoS 攻击每天以数百个不同的实体为目标，活动在 2024 年 10 月和 11 月达到新的高峰。这些攻击虽然持续 10 到 30 秒，但产生的流量约为 100 Gbps。  
  
在披露该消息的几周前，瞻博网络警告说，具有默认密码的   
Session Smart 路由器 （SSR） 产品正成为恶意行为者的目标，以丢弃 Mirai 僵尸网络恶意软件。Akamai 还揭示了 Mirai 恶意软件感染，这些感染将 DigiEver DVR 中的远程代码执行漏洞武器化。  
  
“DDoS 已成为最常见和最具破坏性的网络攻击形式之一，”XLab 研究人员表示。“它的攻击模式多样，攻击路径高度隐蔽，可以采用不断发展的策略和技术，对各种行业和系统进行精准打击，对企业、政府组织和个人用户构成重大威胁。”  
  
这一发展还发生在威胁行为者利用易受攻击和配置错误的   
PHP 服务器（例如 CVE-2024-4577）来部署名为 PacketCrypt 的加密货币矿工之际。  
  
<table><tbody style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><tr class="ue-table-interlace-color-single js_darkmode__0" data-style="-webkit-tap-highlight-color: transparent; outline: 0px; background-color: rgb(28, 28, 28); visibility: visible; color: rgb(205, 205, 205) !important;" style="-webkit-tap-highlight-color: transparent;outline: 0px;background-color: rgb(28, 28, 28);visibility: visible;color: rgb(205, 205, 205) !important;"><td width="557" valign="top" data-style="-webkit-tap-highlight-color: transparent; outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76); background-color: rgb(255, 218, 169); visibility: visible; color: rgb(25, 25, 25) !important;" class="js_darkmode__1" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);background-color: rgb(255, 218, 169);visibility: visible;color: rgb(25, 25, 25) !important;"><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 12px;visibility: visible;color: rgb(0, 0, 0);">尊敬的读者：<br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>感谢您花时间阅读我们提供的这篇文章。我们非常重视您的时间和精力，并深知信息对您的重要性。<br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>我们希望了解您对这篇文章的看法和感受。我们真诚地想知道您是否认为这篇文章为您带来了有价值的资讯和启示，是否有助于您的个人或职业发展。<br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>如果您认为这篇文章对您非常有价值，并且希望获得更多的相关资讯和服务，我们愿意为您提供进一步的定制化服务。请通过填写我们提供的在线表单，与我们联系并提供您的邮箱地址或其他联系方式。我们将定期向您发送相关资讯和更新，以帮助您更好地了解我们的服务和文章内容。</span></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;visibility: visible;"><br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;text-indent: 0em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(0, 0, 0);">                   </span><img class="rich_pages wxw-img" data-backh="106" data-backw="106" data-cropselx1="0" data-cropselx2="119" data-cropsely1="0" data-cropsely2="119" data-galleryid="" data-imgfileid="100006521" data-ratio="1" data-s="300,640" data-type="png" data-w="1000" data-src="https://mmbiz.qpic.cn/sz_mmbiz_png/JqliagemfTA5N8G6ZVujodYTTD7NSaxFG5suXlkibicfoGRzCk6vHhCUBx7ST8b4AxdsFVNNAH4ltePBWX4AxKY0A/640?wx_fmt=other&amp;wxfrom=5&amp;wx_lazy=1&amp;wx_co=1&amp;tp=webp" style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 宋体;font-size: 14px;letter-spacing: 0.578px;text-align: center;visibility: visible !important;width: 119px !important;"/></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;text-indent: 0em;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 宋体;font-size: 12px;letter-spacing: 0.578px;text-align: center;color: rgb(0, 0, 0);">                               扫描二维码，参与调查</span></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;"><br style="-webkit-tap-highlight-color: transparent;outline: 0px;letter-spacing: 0.544px;"/></section></td></tr></tbody></table>  
  
  
**END**  
  
  
  
点击下方，关注公众号  
  
获取免费咨询和安全服务  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JqliagemfTA5OxIlGh6IbpxrTJHkcY5DZ4O80nevX4Ev7IHvjZfPZDDMxibSVWk4IdYfaYpuhBgz2iaWS5tzXZLJw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
安全咨询/安全集成/安全运营  
  
专业可信的信息安全应用服务商！  
  
http://www.jsgjxx.com  
  
  
