#  潜伏二十多年漏洞曝光，几乎所有VPN都中招！   
 网络安全应急技术国家工程中心   2023-08-17 14:28  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176lZr87drOyJMNpjiaEN0KwMmyPaTtWx3Dy2psPvVOfETs7VWRREkAnOG2GJKDsLA33hyR9k1bPMw7w/640?wx_fmt=jpeg "")  
  
近日，纽约大学和鲁汶大学的研究人员发现大多数VPN产品中都存在长达二十多年的多个漏洞，攻击者可利用这些漏洞读取用户流量、窃取用户信息，甚至攻击用户设备。  
  
“我们的攻击所需的计算资源并不昂贵，这意味着任何具有适当网络访问权限的人都可以实施这些攻击，且不受VPN安全协议限制。换而言之，无论VPN使用何种安全协议，所发现的漏洞都可能被滥用。即使是声称使用“军用级加密”或使用自行开发的加密协议的VPN（包括微软和苹果操作系统的内置VPN）也可能受到攻击。”纽约大学的Nian Xu声称：  
  
“即使受害者使用了HTTPS加密，我们的攻击也会泄露用户正在访问哪些网站，这可能会带来重大的隐私风险。”  
  
**四大数据泄露漏洞危及全球VPN客户端**  
  
研究者发现的四个普遍存在的VPN漏洞的CVE编号分别是：CVE-2023-36672、CVE-2023-35838、CVE-2023-36673和CVE-2023-36671。  
- CVE-2023-36672：LocalNet攻击导致明文流量泄漏。参考CVSS分数为6.8。  
  
- CVE-2023-35838：LocalNet攻击导致流量阻塞。参考CVSS分数为3.1。  
  
- CVE-2023-36673：ServerIP攻击与DNS欺骗相结合，可以将流量泄漏到任意IP地址。参考CVSS分数为7.4。  
  
- CVE-2023-36671：ServerIP攻击，只有VPN服务器真实IP地址的流量才会被泄露。参考CVSS分数为3.1。  
  
第一对漏洞可在LocalNet攻击中被利用，即当用户连接到攻击者设置的Wi-Fi或以太网时（下图）：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176lZr87drOyJMNpjiaEN0KwMmDrrRG3KOmktV9HgzAQhQ8OAUUwcEO1bkKXcChX8GIDexGGJCpgiaHPg/640?wx_fmt=jpeg "")  
  
LocalNet攻击示意图  
  
后一对漏洞可被攻击者或恶意互联网服务提供商(ISP)所利用，通过不受信任的Wi-Fi/以太网发动ServerIP攻击。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/INYsicz2qhvbJp9PK6GCiaSGQTlunPbNV7yqasKqmIOwrFw6ensyjyy7k8lKF2ibpkEppKOMVuKH4gC7POPfGdqrg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
ServerIP攻击示意图  
  
研究人员表示：“这两种攻击都会操纵受害者的路由表，诱骗受害者将流量发送到受保护的VPN隧道之外，从而使对手能够读取和拦截传输的流量。”  
  
除了数据泄露，此类攻击还产生另外一个风险：VPN通常用于保护较旧或不安全的协议，VPN防护失效意味着攻击者随后可以攻击较旧或不安全的协议，例如RDP、POP、FTP、telnet等。  
  
研究者公布了多种攻击的视频演示  
  
（https://www.youtube.com/watch?v=vOawEz39yNY&t=52s），还发布了可用于检查VPN客户端是否易受攻击的脚本（https://github.com/vanhoefm/vpnleaks）。  
  
研究人员补充说：“一旦足够多的VPN设备修补了有关漏洞，如果有必要和/或有益，攻击脚本也将被公开发布。”  
  
苹果设备VPN客户端几乎“全军覆没”  
  
在测试了许多消费者和企业级VPN解决方案后，研究人员发现苹果设备上的VPN客户端几乎全军覆没（无论是Mac电脑、iPhone或iPad），Windows和Linux设备的VPN也很容易受到上述一种或两种攻击。在Android设备上，只有四分之一左右的VPN应用程序容易受到攻击——这可能与Android“精心设计”的API有关。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/INYsicz2qhvbJp9PK6GCiaSGQTlunPbNV7eHosCBz1hFWmxQnQVFzUJdLnSYMWoJMicOiaVDrAwZUtALBXJWEhWFIQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
如上图所示，大多数Windows、macOS和iOS的内置VPN客户端都容易受到攻击，超过三分之一的Linux上的VPN客户端也是如此。  
  
研究人员表示，他们并不知道这些漏洞是否在野外被利用，如果有的话，也很难发现。  
  
据悉，研究人员已经向一些VPN供应商通报了他们发现的漏洞，其中一些供应商已经修复了漏洞，但却没有在更新说明中提及（以遵守研究人员在其研究发表之前的保密要求）。  
  
研究人员在论文的末尾提供了各种设备上经过测试的VPN应用程序的完整列表，可供用户检查自己的VPN应用/客户端是否容易受到攻击。  
  
**缓解建议**  
  
研究人员指出：“一些VPN产品已经修复漏洞，包括Mozilla VPN、Surfshark、Malwarebytes、Windscribe（可以导入OpenVPN配置文件）和Cloudflare的WARP。”  
  
思科已确认其适用于Linux、macOS和Windows的思科安全客户端和AnyConnect安全移动客户端容易受到CVE-2023-36672的影响，但仅限于特定的非默认配置。Mulvad则表示只有其iOS应用程序容易受到LocalNet攻击。  
  
如果用户的VPN安全更新不可用，研究人员给出的建议是通过禁用本地网络访问来缓解LocalNet攻击。用户还可以通过确保网站使用HTTPS来缓解攻击，现在大多数网站都支持HTTPS。  
  
论文地址：https://papers.mathyvanhoef.com/usenix2023-tunnelcrack.pdf  
  
  
  
原文来源：GoUpSec  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176n1NvL0JsVSB8lNDX2FCGZjW0HGfDVnFao65ic4fx6Rv4qylYEAbia4AU3V2Zz801UlicBcLeZ6gS6tg/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
