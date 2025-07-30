#  【安全圈】全球互联网因BGP协议漏洞出现大规模路由震荡   
 安全圈   2025-05-28 11:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
BGP协议  
  
  
2025年5月20日UTC时间7时，一条异常的BGP路由通告在互联网骨干网中传播，触发多个主流BGP实现方案的意外行为，导致全球范围内持续数十分钟的路由不稳定事件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljL8iaJ5AWpCZUDhDbLLbTdx5ceI0GWurgTqV8BiaBFgUfeP9xHuBJw0NrSkwNDNpG3uziaUT6AAydyw/640?wx_fmt=png&from=appmsg "")  
  
该事件的起因是某些自治系统（AS）在网络中传播了携带错误BGP Prefix-SID属性的路由更新。该属性通常仅用于企业内部网络（遵循RFC8669标准），而非全球互联网路由表。正常而言，现代BGP实现应按照RFC7606标准过滤此类异常属性，但此次事件中，Juniper的JunOS系统并未完全拦截该错误通告，反而将其传播至对等网络。当这些数据包到达运行Arista EOS设备的网络时，由于Arista未启用BGP容错机制，直接导致BGP会话中断，进而引发部分网络短暂失去互联网连接。  
  
根据bgp.tools的数据分析，此次事件波及多个知名网络服务提供商，包括SpaceX星链（AS14593）、字节跳动（AS396986）、迪士尼全球服务（AS23344）以及Zscaler（AS62044）等。监测显示，BGP路由更新消息在高峰时段激增至每秒15万条以上，远超正常的2-3万条/秒。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljL8iaJ5AWpCZUDhDbLLbTdxZ0vRZXdeUlfaUJg8FibbScsnIm7zYjQibFSywVLybYqIibY3Z956qxS8g/640?wx_fmt=png&from=appmsg "")  
  
此次事件进一步表明，互联网核心协议的实际运行仍存在重大隐患。2023年曾有专家撰文警告BGP错误处理的缺陷可能引发全球性问题，而此次故障印证了这一预测。  
  
目前尚无明确的证据指向事件源头，但初步分析表明，Starcloud（AS135338）或和记环球电讯（AS9304）可能是异常路由通告的起始点，部分涉及的前缀包括156.230.0.0/16等。由于和记电讯连接了大量互联网交换中心（IX），而IX普遍使用的Bird软件未对BGP Prefix-SID属性进行过滤，导致问题进一步扩散。  
  
此次事件再次突显互联网基础设施的脆弱性。随着越来越多的关键服务（如应急通信、广播电视等）依赖IP网络，BGP协议实现的差异可能引发远超"用户无法访问电子邮件"的严重后果。网络运营商应及时审查设备配置，启用严格的BGP过滤策略，以避免类似事件重现。  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】新斯科舍电力公司遭勒索软件攻击 28万用户数据泄露](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069849&idx=1&sn=af1f386531bd8797fadbd3f226bb77a6&scene=21#wechat_redirect)  
  
  
  
[【安全圈】谷歌最新研究：量子计算机破解比特币难度骤降20倍](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069849&idx=2&sn=5022a5ab81242b01d992d9db38a62b27&scene=21#wechat_redirect)  
  
  
  
[【安全圈】美国Marlboro-Chesterfield病理实验室遭勒索攻击，23.5万人敏感医疗数据泄露](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069849&idx=3&sn=490c6573ca146ab8a1e5c63490a5b736&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Gmail用户转投Proton Mail寻求隐私保护](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069849&idx=4&sn=d0949fdb4c93089c0356215069ac0e8b&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
