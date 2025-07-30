#  【安全圈】Mirai 僵尸网络发现新漏洞，能同时被攻守双方利用   
 安全圈   2024-08-27 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
僵尸网络  
  
  
Mirai 僵尸网络在全球 DDoS 攻击中发挥了重要作用，特别是针对 IoT 设备和服务器的攻击。最近，Mirai的命令和控制服务器中发现了一个新漏洞，该漏洞允许攻击者执行DDoS攻击，但同时也能被安全人员用来进行反制。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljjSpP53aQcBEzuvYlWdnLxEL3gW8C5vc7dqO0r0qfRFFdnBxXKib75jVicVgG37VibNe88SsWxln97w/640?wx_fmt=jpeg&from=appmsg "")  
  
僵尸网络的核心基础设施完全依赖于 C2 服务器，其中可以控制数千台受感染的僵尸计算机。一位名叫“Jacob Masse”的研究人员发现表明，这种DDoS 攻击的存在是由于 CNC 服务器上的会话管理不当造成的。  
  
研究人员表示，发起此攻击不需要身份验证，从而很容易被利用。执法部门或安全研究人员也可以使用这种攻击场景来使 CNC 服务器无法运行，从而导致僵尸网络被拆除。具体原理基于此漏洞会压垮服务器的会话缓冲区，当同时建立多个连接时，无法正确处理该缓冲区。此外，这种攻击还存在于预验证阶段，即验证打开后的多个同时连接尝试未得到正确处理。  
  
在此情况下，攻击者可以使用根用户名发送验证请求，从而在 CNC 服务器上打开多个连接。服务器无法管理这些连接尝试，从而导致资源耗尽和服务器崩溃。  
  
因此，对于安全人员而言，利用此漏洞可以破坏僵尸网络活动，从而随后消除与僵尸网络相关的威胁。但从攻击者角度出发，该漏洞导致的恶意网络压力也会破坏数据并造成业务中断。  
  
Mirai 僵尸网络被发现于2016年8月，因其潜在的DDoS攻击和庞大网络而多次成为头条新闻，特别是针对 IoT 设备和服务器的攻击。Mirai 拥有数千台遭到入侵的设备，并通过利用弱默认密码和已知漏洞来瞄准 IP 摄像头和家用路由器等消费类设备，其他几个变体的源代码与 Mirai相似。  
  
  
END  
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/78XNpK3Wmsc6iavNSdvObuJKxloJnAMLA18cpuj6JibPUd6icftkrl6CdKtvw5sBX1asLjP0LpAegNDYLTXSHBIXg/640?wx_fmt=other "")  
[【安全圈】社交媒体“电报”创始人在法国被捕](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063868&idx=1&sn=751ec0f140427c77e7d21f9134652532&chksm=f36e643cc419ed2ae5e313835b73031ef67065e8aded0d5242fd873b1896cc1c677d14dd8d6a&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljjSpP53aQcBEzuvYlWdnLxKb7Eibej2mrVCEX1rblRwzbOfnzBM3JwJap6boxSe3n8pzfMtgnDDug/640?wx_fmt=jpeg "")  
[【安全圈】网络身份证是强制，会影响正常上网？公安部详细回应](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063868&idx=2&sn=e0e51cc3262a54328e4fee1482c882f1&chksm=f36e643cc419ed2a36eb00a524a91605bcd28b782d15ab7fb662c206140dca0df3a38bac1c1a&scene=21#wechat_redirect)  
  
  
【安全圈】网络身份证是强制，会影响正常上网？公安部详细回应  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliayCUW1gpZNIJwcvP62FicibwMbkUfquibHtHOgV66Ee7padQYEzoQeRoBBtVOhMPSx9sytmicCNMSBQw/640?wx_fmt=jpeg "")  
[【安全圈】又一全新恶意软件曝光！专门针对Windows、Linux 和 macOS 用户](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063868&idx=3&sn=49fcaba0be0679106cf8d489b525753c&chksm=f36e643cc419ed2ade897b23b9fba16e6ab1d7e4167ffcbfd90b6edb469943c52ac0c971a570&scene=21#wechat_redirect)  
                 
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljZ1jGTpY6rXdUMmVLxZZbEXdxmAa2uOQDt7ZaIlnjC2uLqSYK2w0lGtT44wd9ZuFdvnRD0RPfaxg/640?wx_fmt=jpeg&from=appmsg "")  
[【安全圈】新型 Linux 恶意软件 “sedexp ”利用 Udev 规则隐藏信用卡盗刷器](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063868&idx=4&sn=a18540bc0e59a8eabff6f3f9f433c306&chksm=f36e643cc419ed2ad6053bcd8bed5e40dc4b7237e79f9eb369052531aee4088ce718f5f7ec7e&scene=21#wechat_redirect)  
                            
  
  
  
  
  
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
  
