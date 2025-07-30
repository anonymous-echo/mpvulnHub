#  【安全圈】Atlas VPN 曝出漏洞：允许查看用户真实 IP 地址，官方：修复程序正在开发   
 安全圈   2023-09-09 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgKPaicOxW94xorwzm2NadXIIJ42j3tuFxiccoU5suStY1aEZGIGk0EVasWO3l4ly0zgHJ3FA28lmFw/640?wx_fmt=jpeg "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
     
  
Atlas VPN 已确认存在一个零日漏洞，该漏洞允许网站所有者查看 Linux 用户的真实 IP 地址。不久前，发现该漏洞的人在Reddit上公开发布了有关该零日漏洞的详细信息以及漏洞利用代码。  
### 关于 Atlas VPN 零日漏洞  
  
Atlas VPN提供 “免费 “和付费的 “高级 “VPN解决方案，可以改变用户的IP地址，以及与网站和在线服务的连接进行加密。该公司为 Windows、macOS、Linux、Android、iOS、Android TV 和 Amazon Fire TV 提供应用程序。  
  
此次发现的漏洞仅影响Lunux版AtlasVPN客户端v1.0.3（即最新版本）。  
  
发帖者解释了漏洞的根本原因，首先，AtlasVPN Linux 客户端由两部分组成，守护进程（atlasvpnd）由管理连接，客户端（atlasvpn）由用户控制连接、断开连接和列出服务。当客户端不通过本地套接或任何其他安全手段进行连接，而是在 8076 端口的 localhost 上打开一个 API时，它没有任何身份验证。计算机上运行的任何程序，包括浏览器，都可以访问这个端口。  
  
简而言之，通过恶意脚本，任何网站都可以向 8076 端口提出断开 VPN 连接的请求，然后运行另一个请求，泄露用户的 IP 地址。  
  
成功 “攻击 “的前提条件是访问者使用 Linux，并在访问网站时主动使用 AtlasVPN Linux 客户端 v1.0.3。当然，这也限制了潜在受害者的数量。  
### 修复程序正在开发中  
  
Atlas VPN 的通信主管 Rūta Čižinauskaitė 说：我们正在修复这个漏洞。该漏洞影响 Atlas VPN Linux 客户端 1.0.3 版本。正如研究人员所说，由于该漏洞，恶意行为者可能会断开应用程序，从而断开用户与 VPN 网关之间的加密流量。这可能导致用户的 IP 地址泄露。  
  
目前，该公司正在努力尽快修复这个容易被利用的漏洞，一旦问题得到解决，就会提示用户将其 Linux 应用程序更新到最新版本。  
  
Čižinauskaitė还表示，他们将在开发过程中实施更多的安全检查，以避免未来出现此类漏洞。  
  
   
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljPLBxQ2GAOL7r9nCmUiaXCGZ1IC49cR0rRItkP3gzJGlvDdbkTYFZXPYrZCcITCMcHLO7bicrv8XKQ/640?wx_fmt=png "")  
[【安全圈】违法！男子因破解无人机禁飞限高程序被抓](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652043909&idx=1&sn=cda6057da60954faa02af916a1a94aef&chksm=f36fd6c5c4185fd348bd8d34b291814d6df5e0c9d5c8eed4a2c436431108ba39502647e9ef46&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljPLBxQ2GAOL7r9nCmUiaXCGY3qttbAhWPrBqzqj9RC4PSsMaiaU8SdwUDSb3aDg3E2Uj0WEZx39Eog/640?wx_fmt=png "")  
[【安全圈】黑客窃取香港数码港400G数据，扬言需花30万美元购买](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652043909&idx=2&sn=06f9e2444747a5cecf0520d035f830c1&chksm=f36fd6c5c4185fd30d5825e4641a324a35d37fe33c21541113939c94801af3f2fe938364f74f&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljPLBxQ2GAOL7r9nCmUiaXCG5sVicZJyeYEQLjWrJ3ueNDnOsApibnqSOTY3jHu4earcMuAdyNHoUmCQ/640?wx_fmt=png "")  
[【安全圈】思科BroadWorks平台现严重漏洞，用户需尽快迁移到固定版本](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652043909&idx=3&sn=f2234bed711169d9c6c662239378aa38&chksm=f36fd6c5c4185fd3512750046f4af718e98e7d472b1cdd3b05a7ba889f95092c45981ff08043&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljPLBxQ2GAOL7r9nCmUiaXCG2bavw7WVHHKytIj75iaztma7PXZMlDgHLicgMGoxuyNL6gic60uwUNbTw/640?wx_fmt=png "")  
[【安全圈】荷兰芯片制造商恩智浦半导体遭到网络攻击，导致用户信息泄露](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652043909&idx=4&sn=0179fefa7e710eb891731c8e07ba2f21&chksm=f36fd6c5c4185fd362eb59903a5d415f537066fb3ea170457bef314196c160f9959626e4f662&scene=21#wechat_redirect)  
  
  
  
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
  
  
