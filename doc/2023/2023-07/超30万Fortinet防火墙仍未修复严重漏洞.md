#  超30万Fortinet防火墙仍未修复严重漏洞   
 网络安全应急技术国家工程中心   2023-07-05 15:22  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GoUrACT176lqz2ia7icXfPp9k6yp7NoUrrlZiap8IdjsPIrQGsjamXiaMND5ICpncBVbIQiar9ibpKiaaxn0ohQibzKf5A/640?wx_fmt=png "")  
  
根据攻击性安全公司Bishop Fox的最新报告，虽然Fortinet已经发布安全更新一个多月，但仍有数十万个FortiGate防火墙的严重漏洞（CVE-2023-27997）未得到修补。  
  
该漏洞是一个远程代码执行漏洞，严重性评分高达9.8分，是由FortiOS中堆栈缓冲区溢出问题造成的。  
FortiOS是连接所有Fortinet网络组件并将其集成到Security Fabric平台中的操作系统。  
  
漏洞CVE-2023-27997可被利用，允许未经身份验证的攻击者通过在网络上公开的SSL VPN接口在易受攻击的设备上远程执行代码。  
在6月中旬的一份公告中，Fortinet曾警告称，该漏洞可能已在攻击中被利用。  
  
Fortinet于6月11日解决了该漏洞，然后公开披露，并发布了FortiOS固件版本6.0.17、6.2.15、6.4.13、7.0.12和7.2.5。  
  
Bishop Fox上周五报告称，尽管安全专家呼吁尽快修复漏洞，但仍有超过30万台FortiGate防火墙设备容易受到攻击，并且可以通过公共互联网进行访问。  
  
Bishop Fox研究人员使用Shodan搜索引擎通过搜索返回的特定HTTP响应标头来查找SSL VPN接口暴露的设备。  
  
研究人员查询了489,337个设备，发现并非所有设备都容易受到CVE-2023-27997漏洞（也称为Xortigate）的攻击。  
经过进一步调查，研究人员发现，所发现的设备中有153,414台已更新为安全的FortiOS版本。  
  
Bishop Fox研究人员表示，这意味着可通过网络访问的FortiGate防火墙中约有33.6万台容易受到攻击，这一数字明显高于此前的查询统计（约25万个）。  
  
Bishop Fox研究人员还发现，许多暴露的FortiGate设备在过去八年里都没有收到更新，其中一些运行的是FortiOS 6，该版本已于去年9月29日终止技术支持。  
  
这些设备容易受到多个严重漏洞的影响，且这些漏洞的PoC都已经公开。  
  
  
  
原文来源：GoUpSec  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176n1NvL0JsVSB8lNDX2FCGZjW0HGfDVnFao65ic4fx6Rv4qylYEAbia4AU3V2Zz801UlicBcLeZ6gS6tg/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
