#  【安全圈】Windows和MacOS平台上发现多个Zoom漏洞，已发布补丁   
 安全圈   2023-06-14 19:00  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgSxa9I02IBd3bgLEhwfJCeRibw3LEjMujeAhD2CvyiaVCZJVHGHODbkPx3pViaX0sAibZsDun6sicUzdQ/640?wx_fmt=jpeg "")  
  
**关键词**  
  
漏洞  
  
  
  
最新的Zoom漏洞列表已经出来了，其中几个漏洞的严重程度非常高。此次发布的补丁针对六个漏洞。  
  
  
这些漏洞几乎影响了所有的Windows客户端，而有两个是在MacOS平台发现的。它们的严重程度各不相同，有可能被攻击者利用，以获得未经授权的访问、提升权限或破坏数据完整性。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljtVmM2OtjV6ZgjQDoiasKxj8gdwBn9JibTT6FeEJAkkvYXUYZnLJhnPhp6HhH2cn9kRSia6E3IuAdibg/640?wx_fmt=jpeg "")  
####   
#### Zoom漏洞：高严重性  
  
  
CVE-2023-34113 (CVSS 8) 数据真实性验证不充分：该漏洞被评为高危，影响到5.14.0版本之前的Zoom Windows版本。  
  
它涉及对数据真实性的验证不足，使有网络访问权的认证用户有可能提升权限。通过利用这一漏洞，攻击者可以操纵数据，对系统的完整性构成重大威胁。  
  
CVE-2023-34114 (CVSS 8.3) 将资源暴露在错误的领域：这个高危漏洞分别影响到5.14.10和5.14.0版本之前的Windows和 MacOS版本。  
  
具有网络访问权限的认证用户有可能利用此漏洞实现信息泄露。该漏洞将信息暴露于错误的领域，这可能导致对敏感信息的未授权访问。  
  
CVE-2023-28603 (CVSS 7.7) Zoom VDI 客户端安装程序中不当的访问控制：版本5.14.0之前的Zoom VDI客户端安装程序包含一个高严重性漏洞。  
  
利用这一漏洞，恶意用户可能会在没有权限的情况下删除本地文件。这个漏洞损害了系统的完整性，也强调了的访问控制的必要性。  
  
#### Zoom漏洞：中等严重性  
  
  
CVE-2023-28600 (CVSS 6.6) ，Zoom 客户端中不当的访问控制：该漏洞被评为中等严重程度的漏洞，该漏洞影响到MacOS客户端5.14.0版本之前的Zoom。  
  
它涉及不当的访问控制，可能允许恶意用户删除或替换Zoom客户端文件。利用该漏洞可能导致Zoom客户端的完整性和可用性丧失。  
  
#### Zoom 漏洞：低严重性  
  
  
CVE-2023-28601 (CVSS 8.3) ，在Zoom客户端中对内存缓冲区范围内的操作进行不当的限制：这个低严重性的漏洞影响到5.14.0版本之前的Zoom Windows版。  
  
它涉及对内存缓冲区范围内操作的不当限制，可能导致Zoom客户端内的完整性问题。虽然严重程度较低，但它仍然对受影响的系统构成风险。  
  
CVE-2023-28602 (CVSS 2.8) ，在Zoom客户端中对加密签名的验证不当：该漏洞也被评为低严重性，它影响到5.13.5版本之前的Zoom Windows版。  
  
它与加密签名的不当验证有关，使恶意用户有可能对Zoom客户端组件进行降级。虽然严重程度相对较低，但它强调了维护加密操作完整性的重要性。  
  
Zoom已经确认了这些漏洞，并发布了补丁和更新来解决这些漏洞。同时强烈建议用户将Zoom软件更新到最新版本，以保护自己避免潜在威胁。  
  
#### 被“盯上”的 Zoom  
  
  
自从新冠病毒大流行和全球封锁之后，Zoom的受欢迎程度激增，同时Zoom也成为了攻击者的目标。  
  
Cyble研究与情报实验室（CRIL）的研究人员最近发现了针对Zoom用户的恶意软件活动，攻击者利用Zoom应用程序的修订版本部署网络钓鱼攻击来传递IcedID恶意软件。  
  
攻击者还被发现通过流行的商业连接软件（包括Zoom、Cisco AnyConnect和Citrix Workspace）的木马安装程序分发Bumblebee恶意软件。  
  
Zoom在商业通信中的广泛应用也促使诈骗者发起复制活动。  
  
最近报道了许多欺诈性网站试图冒充Zoom，使受害者的设备感染恶意软件。  
  
在这种情况下，Zoom主页被一个新的恶意诈骗活动所模仿，它使用相同的设计、用户体验和交互按钮来诱使人们下载该应用程序。  
  
只要用户安装了看似是Zoom应用程序的软件包，Vidar Stealer恶意软件就会被下载到系统中，一旦打开，它就立即开始在系统中传播。  
  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljn4UhE9NA8XutTysvl1X2V1lmmn9HP7iaFnhkFAdRaFwVibmbR7MzedkTGJxlsKIQmsF0Jba32niaKg/640?wx_fmt=jpeg "")  
[【安全圈】制贩黑客工具非法破解手机获利千万 一黑灰产犯罪团伙](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652036779&idx=1&sn=d59f95d5fc6d77b21b26919ef9962a06&chksm=f36ff2ebc4187bfd9ba70403b9e3e1938c4c14a00bc9b8e0a33e2cab216f11d2c15aae69a26e&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljn4UhE9NA8XutTysvl1X2VKopyzS9RFdSplSq1AFVcry2qoo3Uz5h8offql2ChNzc4TFlBicUhAbA/640?wx_fmt=jpeg "")  
[【安全圈】最新报告：美对iPhone手机网络攻击始于2013年](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652036779&idx=2&sn=0c93864d4631e2a2ecc848f9dddb32f8&chksm=f36ff2ebc4187bfdb546ba5c6a41f15661e7a45afc37da60a194391e888844956cf6133d5261&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljDDP5dRyX59bBObmIzCibVdHt9uoCxhDHddcgSFQnOf4cUUGhmlB3FicDSdDpI9180VTic9A2zLKk6w/640?wx_fmt=png "")  
[【安全圈】请尽快卸载这9个流行的恶意Chrome扩展](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652036152&idx=2&sn=93234a58013112f3d3fe1a1356da1b5b&chksm=f36ff078c418796e2e4a25ae7e59d434b58cde16152752745f4b0362599226fc153a0a54b214&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljDDP5dRyX59bBObmIzCibVdsfKNtcKNvI5T1EEQiaAvx4JrSNbCw3L0WMeMtGeAZIPBovElCMshbiaQ/640?wx_fmt=png "")  
[【安全圈】FTC对亚马逊旗下Alexa和Ring的隐私侵权行为处以3080万美元罚款](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652036152&idx=1&sn=fbed0a60eb238b104bd801cec69ab1a7&chksm=f36ff078c418796e59a1e282261e12b35688f108509c06356a8444c4b842a2c29eafe898c1ed&scene=21#wechat_redirect)  
  
  
  
  
  
  
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
  
  
