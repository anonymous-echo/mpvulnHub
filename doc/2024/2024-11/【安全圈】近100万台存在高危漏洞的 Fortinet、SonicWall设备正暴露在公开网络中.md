#  【安全圈】近100万台存在高危漏洞的 Fortinet、SonicWall设备正暴露在公开网络中   
 安全圈   2024-11-04 19:00  
  
[](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652065701&idx=1&sn=a03b2b8222f01674be8fdf329477ccd3&chksm=f36e63e5c419eaf3aac5ccfa1c276e057ed2adae0e3a6751238254e6b57dd1f02985e98babb5&scene=21#wechat_redirect)  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
根据 Cyble 最新发布的漏洞报告，有近100 万台存在被积极利用漏洞的 Fortinet 和 SonicWall 设备正暴露在公开的互联网上。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljUiabwuVLtLldvibUOc2LLS5LabrjFsJVCVLLfYy6QslJlEAOCHic6z8TG3B1yFzmsTsfLibUOXPUtsQ/640?wx_fmt=jpeg&from=appmsg "")  
  
Cyble扫描发现近50万台Fortinet设备和实例暴露于两个被主动利用的漏洞，其中包括6.2万台FortiManager实例和42.7万台面向互联网的Fortinet设备。  
  
涉及FortiManager的漏洞被追踪为CVE-2024-47575，也被称为“FortiJump”，能让攻击者通过特制请求执行任意代码或命令。该漏洞至少从6月份开始就被利用，在CVE被披露前的10多天里，安全研究人员和FortiManager用户一直在报告对该产品中一个未命名的零日漏洞的攻击。  
  
Cyble 报告称，Fortinet 在 CVE 发布前一周通知了客户关于FortiManager漏洞的信息，并提供了一些建议的缓解措施，但一些客户表示他们没有收到相关通知。  
  
另一个关键漏洞被追踪为CVE-2024-23113，涉及FortiOS、FortiProxy、FortiPAM和FortiSwitchManager的多个版本，可能允许未经认证的攻击者进行远程利用。  
  
关于SonicWall设备暴露的漏洞被追踪为于CVE-2024-40766，是一个评分高达9.8的不当访问控制漏洞，存在于管理SonicWall设备和防火墙的SonicOS操作系统管理界面和控件中。Cyble检测到超过48.6万台SonicWall设备受此漏洞影响。托管安全公司 Arctic Wolf 报告称，Fog 和 Akira 勒索软件运营商正在 SSL VPN 环境中利用该漏洞。  
  
另外，由于存在两个评分为10分的漏洞CVE-2024-51567 和 CVE-2024-51568，CyberPanel 实例受到了大量勒索软件和加密程序的攻击。开源虚拟主机控制面板用于简化服务器管理，特别是对于那些使用 LiteSpeed Web 服务器的用户。在 Cyble 检测到的近 33000 个被暴露的 CyberPanel 实例中，有一半以上受到了攻击。  
  
与此同时，Cyble还报告了对 LightSpeed Cache 和 GutenKit WordPress 插件的主动攻击，以及针对工业网络中那些难以更新的设备的攻击，因此较旧的漏洞仍然会受到非常高级别的攻击，包括 Treck TCP/IP 漏洞，该漏洞在最新报告中被攻击了36.1万次。  
  
参考来源：  
Nearly 1 Million Vulnerable Fortinet, SonicWall Devices Exposed to the Web  
  
  
  
  END    
  
  
阅读推荐  
  
[【安全圈】黑客团伙的受害者涉及全国多地，被上海公安局抓了！](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652065701&idx=1&sn=a03b2b8222f01674be8fdf329477ccd3&chksm=f36e63e5c419eaf3aac5ccfa1c276e057ed2adae0e3a6751238254e6b57dd1f02985e98babb5&scene=21#wechat_redirect)  
  
  
[【安全圈】Windows 11任务管理器出Bug了](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652065701&idx=2&sn=285bee2a1e0729e0a0bedcd8d0af5585&chksm=f36e63e5c419eaf3595c6b1d2d6b4d5f62ad53a98b1a76c09412fc71787d326dfa8c9213317e&scene=21#wechat_redirect)  
  
  
  
[【安全圈】“EmeraldWhale”行动：15000个云账户凭证被盗](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652065701&idx=3&sn=c586e5ad23db24223b39fea41e8bb896&chksm=f36e63e5c419eaf3e6d6e19546bb4016047dc5326b80440b656d3671908d9dd81448f160fcfa&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
