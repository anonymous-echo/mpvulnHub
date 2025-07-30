#  【安全圈】TunnelVision 漏洞曝光，几乎可监听所有VPN   
 安全圈   2024-05-10 19:03  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljBs3TAHagAhdoTXC0SmS0icVh9ibTOg1icnVXQfnIN2twr2GThKiciasY5XTkmEqU4Cibp5RmaHcH8X4gA/640?wx_fmt=jpeg&from=appmsg "")  
  
近日，安全企业Leviathan Security Group披露了一个名为TunnelVision的安全漏洞，它可将用户的VPN流量外泄给位于同一局域网络上的黑客，该漏洞被追踪为CVE-2024-3661。  
  
根据研究人员的说明，TunnelVision是一种可绕过VPN封装的新型网络技术，借由操作系统所内置的、用来自动分配IP地址的动态主机配置协议（Dynamic Host Configuration Protocol，DHCP），就可迫使目标用户的流量离开VPN信道，进而让黑客可窥探其流量，由于该手法并未破坏VPN所控制的信道，因而不会触发VPN的网络自动断开（Kill Switch）机制，而让用户误以为自己的流量仍受到VPN保护。  
  
如果用户连接的对象是个HTTP网站，那么传输内容将会被一览无遗，若是访问加密的HTTPS网站，黑客就只能查看用户所连接的对象。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljBs3TAHagAhdoTXC0SmS0icSFtusz18sf1SzI1W8VrxRfPKibBnGV7uJWxjIeyiarQiasqlaI4EnYAjQ/640?wx_fmt=jpeg&from=appmsg "")  
  
开发过程，图源：利维坦  
  
安全研究人员指出，至少从 2002 年开始这个漏洞就已经出现，但目前还没有已知的恶意利用案例。  
  
但Leviathan已通过电子前线基金会（EFF）及CISA通知了全球超过50个VPN供应商，另也提醒VPN企业不应夸大VPN的安全性，因为它们并无法保证用户在不受信任网络上的流量可被保护，例如公共Wi-Fi。  
## 缓解 "隧道视像 "攻击  
  
Leviathan 表示，大多数 VPN 客户端通常都有这种情况，它们使用系统级路由规则，没有防泄漏保护措施。TunnelVision CVE-2024-3661 漏洞影响 Windows、Linux、macOS 和 iOS。由于 Android 不支持 DHCP 选项 121，它是唯一不受 TunnelVision 攻击影响的主要操作系统。  
  
攻击者可以通过多种方式增加恶意服务器访问的机会，包括针对合法服务器的 DHCP 攻击和 ARP 欺骗。  
  
Leviathan 建议 VPN 用户采取以下缓解措施：  
- 在 Linux 上使用网络命名空间，将网络接口和路由表与系统其他部分隔离，防止恶意 DHCP 配置影响 VPN 流量。  
  
- 配置 VPN 客户端，拒绝所有不使用 VPN 接口的入站和出站流量。例外情况应仅限于必要的 DHCP 和 VPN 服务器通信。  
  
- 配置系统在连接 VPN 时忽略 DHCP 选项 121。这可以防止应用恶意路由选择指令，但在某些配置下可能会中断网络连接。  
  
- 通过个人热点或虚拟机（VM）内进行连接。这样可以将 DHCP 交互与主机系统的主网络接口隔离，降低恶意 DHCP 配置的风险。  
  
- 避免连接到不受信任的网络，尤其是在处理敏感数据时，因为这些网络是此类攻击的主要环境。  
  
Leviathan已找到在Linux系统上防范TunnelVision攻击的缓解措施，但该措施存在一个侧信道，可被用来执行针对性的拒绝服务攻击，或是借由流量分析将流量目的去匿名化。  
  
同时，他们鼓励VPN 提供商增强客户端软件，并实施自己的 DHCP 处理程序，或集成额外的安全检查，以阻止应用有风险的 DHCP 配置。  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljBs3TAHagAhdoTXC0SmS0icwfiaPnPWXKkZq7giaeicrbLV93X90AFpwQkXxLx2jtR0icAaDmcty5DliaA/640?wx_fmt=jpeg "")  
[【安全圈】出售“翻墙”VPN软件，非法牟利被批捕](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652059518&idx=1&sn=8dd1369cbc9d3b8bfa4539b46162f16b&chksm=f36e1b3ec4199228eeab6fa4bf12e7718898ac8cf6e34d584b9209297e8c5d089c42271ccb42&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljBs3TAHagAhdoTXC0SmS0icxfRtefvUiaYjVd5uP8icwibOzSFOMzXtmU9jwevj4tHGLPX3cwRwyPVHA/640?wx_fmt=jpeg "")  
[【安全圈】F5管理器现漏洞，能让攻击者开设账户并长期潜伏](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652059518&idx=2&sn=6c7ac8b61d0e8277c4eb32634b2763c6&chksm=f36e1b3ec41992284b143dba553e29b21f4c05f160869d65080643d216b532e0a18089cc7212&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljBs3TAHagAhdoTXC0SmS0ictwZrBuh5E6VSiaa9L9psuEChUdhmugSgOoofXtJAQAVDftVKt9dzp7g/640?wx_fmt=jpeg "")  
[【安全圈】微软为美国情报部门提供“物理隔离版”ChatGPT](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652059518&idx=3&sn=2a606990dafdc2363fcfd742f8bc7617&chksm=f36e1b3ec4199228ae832c663a2fc2eecd7e023d343dce10a70c750717d0238e41cab42e5654&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljBs3TAHagAhdoTXC0SmS0icicr8cOqrxvcJb9xa3ZglFCGE21tQq8gKWO3PhuLIkVN8lY63n83rKFw/640?wx_fmt=jpeg "")  
[【安全圈】MediExcel 泄露了 50 万份患者文件](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652059518&idx=4&sn=346f5001fbbe933642f065bc621852ab&chksm=f36e1b3ec4199228b7872ddf2cb2cec807ad7bedf463cb459b3c17cd8792c376621e861a7272&scene=21#wechat_redirect)  
  
  
  
  
  
  
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
  
