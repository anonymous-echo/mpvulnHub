#  美网军司令部官宣：伊朗黑客利用Zoho、Fortinet漏洞侵入美国航空组织   
 网络安全应急技术国家工程中心   2023-09-08 15:07  
  
美国CISA、FBI和网络司令部(USCYBERCOM)当地时间9月7日（周四）发布的一份联合报告显示，国家支持的黑客组织利用针对Zoho和Fortinet关键漏洞的漏洞攻击了美国一家航空组织。此次网络攻击事件背后的威胁组织尚未被命名，但虽然联合通报没有将攻击者与特定国家联系起来，但美国网络司令部的新闻稿将恶意行为者与伊朗的利用活动联系起来。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0KRmt3K30icUhGXF6BjKFj0hMtoPC77eddkoACia7Mn6HP3jrwwPk4r11oE2Mb5qvYkTtmOzFgVmX5W6za8qx2zQ/640?wx_fmt=png&wxfrom=13&tp=wxpic "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0KRmt3K30icUhGXF6BjKFj0hMtoPC77ediaFTTbR4YoME07fh9AoaTodTFHNzibzOEAyb0AYgC4NZyTcyZV0ThpDg/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
CISA参与了2月至4月期间的事件响应，并表示黑客组织至少从1月起就已经进入了受感染的航空组织的网络，此前黑客组织入侵了运行Zoho ManageEngine ServiceDesk Plus和Fortinet防火墙的暴露于互联网的服务器。  
  
“CISA、FBI和CNMF确认，民族国家高级持续威胁(APT)攻击者利用CVE-2022-47966未经授权访问面向公众的应用程序 (Zoho ManageEngine ServiceDesk Plus)、建立持久性并通过网络”，公告中写道。  
  
“此漏洞允许在ManageEngine应用程序上远程执行代码。还观察到其他APT攻击者利用CVE-2022-42475在组织的防火墙设备上建立存在。”  
  
正如这三个美国机构所警告的那样，这些威胁组织经常扫描面向互联网的设备上未修补的漏洞，以查找关键且易于利用的安全漏洞。  
  
渗透到目标网络后，攻击者将持续保留被黑客攻击的网络基础设施组件。这些网络设备可能会被用作受害者网络内横向移动的垫脚石、恶意基础设施或两者的组合。  
  
建议网络防御者应用今天的咨询和NSA推荐的最佳实践中共享的缓解措施来保护基础设施。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0KRmt3K30icUhGXF6BjKFj0hMtoPC77ed4azP5hD1HG4HPbicuAGNUyELSjEQNPsbskoXI5HOJDiaeJS3ibxBO9cew/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
它们包括但不限于保护所有系统免受所有已知被利用的漏洞的影响、监视远程访问软件的未经授权的使用以及删除不必要的（禁用的）帐户和组（尤其是特权帐户）。  
  
此前美国CISA、FBI针对类似攻击的预警已多次发布。  
  
今年1月份，CISA下令联邦机构确保其系统免受CVE-2022-47966漏洞的攻击，在概念验证(PoC)漏洞利用代码在线发布的几天前，威胁行为者开始瞄准在线暴露的未修补的ManageEngine实例，以打开反向shell。   
  
在CISA发出警告几个月后，朝鲜Lazarus黑客组织也开始利用Zoho漏洞，成功入侵了医疗机构和互联网骨干基础设施提供商。  
  
FBI和CISA发布了多个其他警报，涉及国家支持的组织利用ManageEngine缺陷来攻击关键基础设施，包括金融服务和医疗保健。  
  
正如Fortinet在1月份披露的那样，FortiOS SSL-VPN漏洞（CVE-2022-42475 ）也被用作针对政府组织和相关目标的零日攻击。  
  
Fortinet还警告说，在攻击期间，额外的恶意有效负载被下载到受感染的设备上，这些有效负载无法检索进行分析。  
  
Fortinet于2022年11月28日悄然修复了该漏洞，但没有发布该漏洞已被广泛利用的信息，随后，12月中旬，客户首次被敦促修补其设备以抵御持续的攻击。  
  
**参考资源：**  
  
1.https://www.bleepingcomputer.com/news/security/iranian-hackers-breach-us-aviation-org-via-zoho-fortinet-bugs/  
  
2.https://www.cisa.gov/news-events/alerts/2023/09/07/cisa-fbi-and-cnmf-release-advisory-multiple-nation-state-threat-actors-exploit-cve-2022-47966-and  
  
3.https://www.cybercom.mil/Media/News/Article/3518476/cnmf-and-partners-illuminate-iranian-exploitation-efforts/  
  
4.https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-250a  
  
  
  
原文来源：网空闲话plus  
  
“投稿联系方式：010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176n1NvL0JsVSB8lNDX2FCGZjW0HGfDVnFao65ic4fx6Rv4qylYEAbia4AU3V2Zz801UlicBcLeZ6gS6tg/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
