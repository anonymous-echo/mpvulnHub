#  【安全圈】几乎所有VPN都中招！这个漏洞潜伏了二十年终于被发现   
 安全圈   2023-08-16 19:01  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgSxa9I02IBd3bgLEhwfJCeRibw3LEjMujeAhD2CvyiaVCZJVHGHODbkPx3pViaX0sAibZsDun6sicUzdQ/640?wx_fmt=jpeg "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/INYsicz2qhvbJp9PK6GCiaSGQTlunPbNV7dCXzYCG1vVz4uuicjKKCJDrGgxVN6sp1N7LE9K3SAOVoHgh8XJ4yHwg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
LocalNet攻击示意图  
  
  
后一对漏洞可被攻击者或恶意互联网服务提供商(ISP)所利用，通过不受信任的Wi-Fi/以太网发动ServerIP攻击。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/INYsicz2qhvbJp9PK6GCiaSGQTlunPbNV7yqasKqmIOwrFw6ensyjyy7k8lKF2ibpkEppKOMVuKH4gC7POPfGdqrg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
ServerIP攻击示意图  
  
  
研究人员表示：“这两种攻击都会操纵受害者的路由表，诱骗受害者将流量发送到受保护的VPN隧道之外，从而使对手能够读取和拦截传输的流量。”  
  
  
除了数据泄露，此类攻击还产生另外一个风险：VPN通常用于保护较旧或不安全的协议，VPN防护失效意味着攻击者随后可以攻击较旧或不安全的协议，例如RDP、POP、FTP、telnet等。  
  
  
研究者公布了多种攻击的视频演示  
  
（https://www.youtube.com/watch?v=vOawEz39yNY&t=52s），还发布了可用于检查VPN客户端是否易受攻击的脚本（https://github.com/vanhoefm/vpnleaks）。  
  
  
研究人员补充说：“一旦足够多的VPN设备修补了有关漏洞，如果有必要和/或有益，攻击脚本也将被公开发布。”  
  
  
**苹果设备VPN客户端几乎“全军覆没”**  
  
  
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
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgdKibeDibwor3bmBFGNEhOS6hcmM4AlbkhRQql8JAib6tJhgfrAwHVA3QmU0EbbkFwjt2w78b0g7NDQ/640?wx_fmt=jpeg "")  
[【安全圈】福特被曝WiFi出现安全漏洞，官方回应仍可安全驾驶](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652042010&idx=1&sn=58f9a157c83a3a6800c908a5ad8c57bd&chksm=f36fdf5ac418564c13d708db922cf8c810dead3ca95ec792e9a62aa33923c1582ccb4d14fded&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgdKibeDibwor3bmBFGNEhOS6JlfeRCvqzq6hu0ayFyEzsZjEBkx0qmkX0g2GpsCibUIsyOdOt0wfzBg/640?wx_fmt=png "")  
[【安全圈】大量用户反映被扣双倍月租！电信客服：系统升级所致](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652042010&idx=2&sn=035f4b2e898307fb5520f9699387dd0f&chksm=f36fdf5ac418564ce1437d649bbf5f27a215f06f76c2abb533c3237ed8b61d63bf08aab610a8&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgdKibeDibwor3bmBFGNEhOS6H4e4t6No0ytn0DiaFs25lAPBHFEjH7ZTnH3IYxamRWFenNpxmzy0OQA/640?wx_fmt=png "")  
[【安全圈】退休干部网络招募“敢死队”，目前涉案人员已抓捕归案](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652042010&idx=3&sn=9f1e26ffb7d72277353c553d7153bd2c&chksm=f36fdf5ac418564c999a76cbb9d0befed46af31cb8392a4e0f34992a710cc555448e21953d3f&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgdKibeDibwor3bmBFGNEhOS6ZAsok5BtzTkCNIicicmIgX5YtKRHfnwpwGf3icboy3z6G2iaNsdSzotOTQ/640?wx_fmt=png "")  
[【安全圈】微软曝欧德神思软件出现15个漏洞，可被利用窃取数据、关停电厂](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652042010&idx=4&sn=548f202952486fef79828e0ab511b217&chksm=f36fdf5ac418564cf43af7405fefd393fa7813420c0cf75c823d57bbe9362f33a2ea9b826277&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
