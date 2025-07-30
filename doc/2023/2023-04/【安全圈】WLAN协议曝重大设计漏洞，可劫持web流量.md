#  【安全圈】WLAN协议曝重大设计漏洞，可劫持web流量   
 安全圈   2023-04-02 19:01  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgSxa9I02IBd3bgLEhwfJCeRibw3LEjMujeAhD2CvyiaVCZJVHGHODbkPx3pViaX0sAibZsDun6sicUzdQ/640?wx_fmt=jpeg "")  
  
  
**关键词**  
  
  
  
漏洞  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylj24icxjcfXGgnAuAVaSDEEODPKGJiaZ8AtgbLRXYQQhSc7Xe7aL2JicqCEoFuaF6skvmN9OZBggQ8ZQ/640?wx_fmt=jpeg "")  
  
东北大学的网络安全研究人员在IEEE 802.11无线局域网协议标准中发现了一个设计漏洞，攻击者可欺骗接入点以明文形式泄漏网络帧。  
  
WLAN帧是由标头、数据有效负载和尾部组成的数据容器，其中包括源和目标MAC地址、控制和管理数据等信息。这些帧按队列排序受控传输，以避免碰撞冲突，并通过监视接收点的忙/闲状态来最大化数据交换性能。  
  
研究人员发现，排队/缓冲的帧缺乏安全保护机制，攻击者可以操纵数据传输、客户端欺骗、帧重定向和捕获。  
  
“该缺陷可以用来劫持TCP连接或拦截客户端Web流量，影响范围极大，包括各种设备和操作系统（Linux，FreeBSD，iOS和Android）”东北大学的Domien Schepers和Aanjhan Ranganathan以及imec-DistriNet的Mathy Vanhoef在昨天发表的技术论文中写道。  
  
省电不省心  
  
IEEE 802.11标准包括节能机制，允许WiFi设备将发往休眠设备的帧进行缓冲或排队，以此来节省电力。  
  
当客户端站（接收设备）进入休眠模式时，它会向接入点发送一个带有包含节能标头的帧，此后所有发往它的帧都将排队。客户端站唤醒后，接入点会取消缓冲帧的排队，对其加密后传输到目标。  
  
但是，该标准没有提供有关管理这些排队帧的明确安全规范，也没有设置限制，例如缓冲帧可以在此状态下停留多长时间。  
  
攻击者可以假冒联网设备的MAC地址，并将节能帧发送到接入点，将发往目标的帧排入队列。然后，攻击者发送唤醒帧以获取排队帧堆栈。  
  
传输的帧通常使用组寻址加密密钥（在WiFi网络中的所有设备之间共享）或成对加密密钥进行加密，该密钥对于每个设备是唯一的，用于加密两个设备之间交换的帧。  
  
但是，攻击者可以通过向接入点发送身份验证和关联帧来更改帧的安全上下文，从而强制其以明文形式传输帧或使用攻击者提供的密钥对其进行加密。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylj24icxjcfXGgnAuAVaSDEEO1bByvKJF0h4F1MQEkmS56lOPut7VVhIlVxwoZFBxtqMyicYlPxH8ygQ/640?wx_fmt=png "")  
  
实施该攻击需要使用研究人员开发的名为MacStealer的自定义工具，该工具可以测试WiFi网络的客户端隔离绕过，并在MAC层拦截发往其他客户端的流量。  
  
研究人员报告说，Lancom、Aruba、思科、华硕和D-Link的以下网络设备产品受到这些攻击的影响，完整列表如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylj24icxjcfXGgnAuAVaSDEEOCrPeLsx3TQKNcVGjPs3SrmibaH7mw6LfmhiaA5fdPFvVWyGBw1giatrkg/640?wx_fmt=png "")  
  
研究人员警告说，该攻击可被用来将JavaScript等恶意内容注入TCP数据包。  
  
“攻击者可以使用自己的互联网连接服务器，通过假冒发件人IP地址的路径外TCP数据包将数据注入TCP连接，”研究人员警告说：“这可以被滥用，以明文HTTP连接向受害者发送恶意JavaScript代码，目的是利用客户端浏览器中的漏洞。”  
  
虽然这种攻击也可以用来窥探流量，但由于大多数网络流量都是使用TLS加密的，因此影响有限。  
  
该攻击的技术细节可在USENIX Security 2023论文中找到（链接在文末），该论文将在今年五月份的BlackHat Asia大会上发表。  
  
思科承认中招  
  
首个承认受WLAN协议漏洞影响的厂商是思科，它承认论文中的攻击可能适用于思科无线接入点产品和具有无线功能的Meraki产品。  
  
但思科认为，检索到的帧不太可能危及安全防护得当的网络的整体安全性。  
  
“这种攻击被视为机会主义攻击，攻击者获得的信息在安全配置的网络中价值不是很高。”  
  
话虽如此，但思科仍建议采取缓解措施，例如通过思科身份服务引擎（ISE）等系统使用策略执行机制，该系统可以通过实施思科TrustSec或软件定义访问（SDA）技术来限制网络访问。  
  
思科还建议“实施传输层安全性，以尽可能加密传输中的数据，因为这会使攻击者无法使用获取的数据。”思科安全公告中写道。  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGyljc4LjBvfGyWL0PIpKw67dlicEQu2XYYadwPXu2uSnEG1QSJXIZpVSicGibGPS5osUg3Ko3ZUlBUZ0rw/640?wx_fmt=png "")  
[【安全圈】网络安全审查办公室：对美光公司在华销售产品实施网络安全审查](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652032029&idx=1&sn=1e2baf879cbadc37620d308340882cfa&chksm=f36fe05dc418694b922fbf2712cee7168fc7d99acaaf920e524425c37f71d03b8e110ee09f6e&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGyljc4LjBvfGyWL0PIpKw67dle6ibJwns94gvvzuoIxYzkCpp6oa1rvxJgDq7eOPgksbwVtjSDAibibC5A/640?wx_fmt=png "")  
[【安全圈】刚刚！马斯克开源Twitter算法，GitHub Star数已破万](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652032029&idx=2&sn=ce4eb9e257fb278a077fa4460419d4ad&chksm=f36fe05dc418694b76b44ad435edd873892c79a27841ac70ad2376a836b48c36e4f20ff5d679&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGyljc4LjBvfGyWL0PIpKw67dlHPy2Xsve5pEtCLtyET1KIy1ocEMdCaia8VYmfWQmqwlE0U2ziac9O8Lw/640?wx_fmt=jpeg "")  
[【安全圈】泄露用户信息长达一年半，丰田被服务商坑惨了](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652032029&idx=3&sn=5ff68bc90b6a63fea3fabc45e80c1827&chksm=f36fe05dc418694b480e75a16f740d853bb1dda224c3d162d6f40c4307f68442fae4674e1bdf&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGyljc4LjBvfGyWL0PIpKw67dl3zE3vD6cLk7uSfpwHkVtELwUDvoO3aYlj9YxI8G1XXd0OwkCUzHqjw/640?wx_fmt=jpeg "")  
[【安全圈】黑客利用零日漏洞监控 iPhone、Android 用户](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652032029&idx=4&sn=c11bb8d82e07c8dd0027364a5211ce1f&chksm=f36fe05dc418694b2da61584eaab85afeb7bbf9d8efc6b97ed3b320efd8080869b5da0d9b318&scene=21#wechat_redirect)  
  
  
  
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
  
  
  
  
  
  
  
