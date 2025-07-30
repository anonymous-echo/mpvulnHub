#  【安全圈】影响之前所有版本，TP-Link 路由器曝出满分漏洞   
 安全圈   2024-05-29 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
系统漏洞  
  
  
近日，TP-Link Archer C5400X 游戏路由器被曝存在高危安全漏洞，未经认证的远程威胁攻击者能够通过发送特制请求，在受影响设备上任意执行代码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljLf2ftBSr2vwqoks7W2LJKQB2ibXFkBo7AUMIeu0l9wiaDwubgOHxv5HyBSPDPeFfwcic6Wg5z5cESw/640?wx_fmt=jpeg "")  
  
据悉，安全漏洞被追踪为 CVE-2024-5035，CVSS 评分为 10.0，主要影响包括 1_1.1.6 及之前版本在内的所有版本的 TP-Link Archer C5400X 游戏路由器固件。鉴于 CVE-2024-5035 安全漏洞的影响范围广、危害程度大、可利用性高等特点，TP-Link 方面在 2024 年 5 月 24 日发布的 1_1.1.7 版本中，修补了安全漏洞。  
## CVE-2024-5035 安全漏洞详情  
  
CVE-2024-5035 安全漏洞产生的根源在于一个与射频测试 “rftest ”相关的二进制文件，该文件在启动时暴露了 TCP 端口 8888、8889 和 8890 上的网络监听器，从而允许未经认证威胁攻击者，能够远程轻松执行任意代码。  
  
虽然该网络服务被设计为只接受以 “wl ”或 “nvram get ”开头的命令，但网络安全公司 ONEKEY 发现，只要在 shell 元字符（如 ; 、& 或 |）（如 “wl;id;”）之后注入命令，就可以轻松绕过这一限制。TP-Link 公司在版本 1_1.1.7 Build 20240510 的更新中，通过丢弃任何包含这些特殊字符的命令解决该漏洞。  
  
近段时间，TP-Link 公司频频爆出安全漏洞问题，在 CVE-2024-5035 安全漏洞披露的前几周，TP-Link 公司还披露了台达电子 DVW W02W2 工业以太网路由器和 Ligowave 网络设备中存在的两个安全漏洞，分别被追踪为 CVE-2024-3871 和 CVE-2024-4999，远程威胁攻击者能够利用这些安全漏洞，提升的自身权限，执行任意远程命令。  
  
更糟糕的是，由于 TP-Link 公司不再对上述两个安全漏洞进行积极维护，导致受影响的相关设备仍未打补丁。因此，用户必须采取适当措施限制管理界面的暴露，以最大程度上降低威胁攻击者利用安全漏洞的可能性。  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylguTGqL1Z9Ew4uEfILSDVOicTHabKM5fbEKhfYsPHCEsicSPibEoLU9fjndMicWnUwjMasnR1Q4s9icL6A/640?wx_fmt=jpeg&from=appmsg "")  
[【安全圈】在最近的 MITRE 网络攻击中，黑客创建恶意虚拟机以逃避检测](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652060682&idx=1&sn=49aa32da7966310e02bffb5f5219f26f&chksm=f36e104ac419995c31dcf0cac42b2faaf9598c8c6d1eda161484316e476f07bda4e356805cfd&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylguTGqL1Z9Ew4uEfILSDVOic7kxVPVzSxLMOM4QChBtadfib9gg09Z2tq91RqZrP9bHRPibmyVFQuBIw/640?wx_fmt=jpeg "")  
[【安全圈】Check Point VPN 设备遭遇黑客攻击](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652060682&idx=2&sn=7b8791571bfb1f3ee722304db71cef19&chksm=f36e104ac419995c7c35f640c140d9c72bb50a09970c13270ed9b972988211ca2782a3a7f89d&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljLf2ftBSr2vwqoks7W2LJKWxRFHhtXy29btibsia547OicDytJBgLU512D4SbJXxiaFwGE9pVFFAEwdA/640?wx_fmt=jpeg "")  
[【安全圈】Windows 版 Arc 浏览器“人红是非多”，黑客已经利用其网络钓鱼](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652060682&idx=3&sn=e59ab9b698cb5d629381f9b6a665ad28&chksm=f36e104ac419995c4215057d80ba9aef50a15ac58203bc5426e64b636fb3f2093ecd328d4858&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljLf2ftBSr2vwqoks7W2LJKChYTJtI58bKA2jsicvr9QibfJHZZzRiaX4Tdsibr8A9mSaRGQHVicIO0KEg/640?wx_fmt=jpeg "")  
[【安全圈】新型恶意软件 Gipy 出现，针对人工智能语音生成器应用程序](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652060682&idx=4&sn=7dbec6d413c8ad495b3ebf18bf4c3305&chksm=f36e104ac419995ce7c77db9a2d875de03cbb6fdd99e88b0ab0b3fac400f69bf9cdd81c7bceb&scene=21#wechat_redirect)  
  
  
  
  
  
  
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
  
