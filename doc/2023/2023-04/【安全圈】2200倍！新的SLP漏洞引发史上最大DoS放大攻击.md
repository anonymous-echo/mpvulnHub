#  【安全圈】2200倍！新的SLP漏洞引发史上最大DoS放大攻击   
 安全圈   2023-04-26 19:27  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGyljsJVJHhaCOeUkoze16FrNjE24yjZVib01Tl7diaq0PGm6wazJMuo3K51rsrhdiagwEDicqXQtmMQlIJQ/640?wx_fmt=jpeg "")  
  
**关键词**  
  
  
  
数字风险保护  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylg8vPCzw2pzVlsuEPcaawGmdbxa1fIsaEic6cRVZDnnYH25EnyKzZxRyzJxnhnQXB30PBpUbJBD1YA/640?wx_fmt=jpeg "")  
  
服务定位协议（SLP）的被曝高严重性安全漏洞，该漏洞可被用作武器化，对目标发起体积性拒绝服务（DoS）攻击。  
  
Bitsight和Curesec的研究人员Pedro Umbelino和Marco Lux在一份与《黑客新闻》分享的报告中说：攻击者利用这个漏洞可以发动大规模的拒绝服务（DoS）放大攻击，系数高达2200倍，有可能成为有史以来最大的放大攻击之一。  
  
据称，该漏洞为CVE-2023-29552（CVSS评分：8.6），影响全球2000多家企业和54000多个通过互联网访问的SLP实体。  
  
这其中包括VMWare ESXi管理程序、柯达打印机、Planex路由器、IBM集成管理模块（IMM）、SMC IPMI等其他665种产品。  
  
易受攻击的SLP实体最多的前十个国家分别是美国、英国、日本、德国、加拿大、法国、意大利、巴西、荷兰和西班牙。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylg8vPCzw2pzVlsuEPcaawGmxIialtVydDjcmQdCaYYd2PNOofjWNiaxAY3MqJpXBHibBicdpuyosHSoRQ/640?wx_fmt=jpeg "")  
  
SLP是一个服务发现协议，使计算机和其他设备能够在局域网中找到服务，如打印机、文件服务器和其他网络资源。  
  
攻击者利用受CVE-2023-29552漏洞影响的SLP实体，发起放大攻击，用超大规模虚假流量攻击目标服务器。  
  
要做到这一点，攻击者需要做的就是在UDP 427端口找到一个SLP服务器并注册 ，直到SLP拒绝更多的条目，然后以受害者的IP作为源地址反复对该服务发起请求。  
  
这种攻击可以产生高达2200倍的放大系数，导致大规模的DoS攻击。为了减轻这种威胁，建议用户在直接连接到互联网的系统上禁用SLP，或者过滤UDP和TCP 427端口的流量。  
  
研究人员表示：同样需要注意的是，实施强有力的认证和访问控制，只允许授权用户访问正确的网络资源，并对访问进行密切监控和审计。  
  
网络安全公司Cloudflare在一份公告中说，预计基于SLP的DDoS攻击的普遍性将在未来几周内大幅上升，因为攻击者正在尝试新的DDoS放大载体。  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylj8erE8QzUxvlB3NiaUC3gu5zvufM5tY7M56yRvib1mAJB7WeiaCe8MPUYyXrib8Uv8hBNyZb7TqXg09A/640?wx_fmt=jpeg "")  
[【安全圈】注意！黑客利用“明星塌房”大肆传播病毒](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652032969&idx=1&sn=f5c8ce34c7a4d63c7848780e888c3077&chksm=f36fe389c4186a9fb0967d16903a38c48ea73f165d27e73fb56087ff531849f9bf0f3efa0be0&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylj8erE8QzUxvlB3NiaUC3gu5qQ2ico0XFz3ShYbQibq1LzOPOHES19PjO2yhs5E7axwPWxvcDyNn1liaQ/640?wx_fmt=jpeg "")  
[【安全圈】勒索软件盯上苹果，Mac不再是安全无虞的选择？](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652032892&idx=1&sn=a10c54767d1ac2f66df87c6bd43bc777&chksm=f36fe33cc4186a2a93c57080104b22c08750ba04be5f2bf3263c48bc980d4f16872c6b2b7c65&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylj8erE8QzUxvlB3NiaUC3gu5bzdibrQXxS56ThPNy1JXLE1INhd6cF5868kQDIBaHTw6SricSrk2P9vw/640?wx_fmt=jpeg "")  
[【安全圈】现已修复！阿里云SQL 数据库曝两个关键漏洞](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652032821&idx=1&sn=1c4a278828b2ff1092ac903cd3b4a436&chksm=f36fe375c4186a630be4ae42843ca86ebd932da52439bc4b47724ffa365daeee9a3d233b1b1e&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylj8erE8QzUxvlB3NiaUC3gu5XsbMqm2Xoexz04HWnsDtFjwUicvdK6kKtU6KqoHs2RMPBQvooyyxhHw/640?wx_fmt=jpeg "")  
[【安全圈】全国首例：长沙一男子植入“戒酒芯片”，管用 5 个月](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652032676&idx=1&sn=9a4b287138977c589ba952ff0efb2904&chksm=f36fe2e4c4186bf20204e3cf731bb312cf995dd78926c152b47288323ba1b46ada3ef8adaf2f&scene=21#wechat_redirect)  
  
  
  
[【安全](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652030093&idx=4&sn=e988dc890e595695befbdb177d11b98c&chksm=f36fe8cdc41861dbd78f5270a42fca19c1d45cb375ef4469e8a36bef1f42620f990d03714872&scene=21#wechat_redirect)  
  
  
‍  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
