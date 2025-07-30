#  【安全圈】本田被曝存在API漏洞，客户数据正处于高风险状态   
 安全圈   2023-06-08 19:01  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgSxa9I02IBd3bgLEhwfJCeRibw3LEjMujeAhD2CvyiaVCZJVHGHODbkPx3pViaX0sAibZsDun6sicUzdQ/640?wx_fmt=jpeg "")  
  
**关键词**  
  
系统漏洞  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylggpfnZic6Ud2X5ncSXaQe5g9gV72c116d2fFYiawceVeobfTZXGb5y5W89E3cVc5jYE0d9v3AvVCTg/640?wx_fmt=jpeg "")  
  
近日，本田被曝存在API漏洞，客户数据正处于高风险状态。由于利用API漏洞可以重置任何帐户的密码，所以本田的电力设备、船舶、草坪和花园电子商务平台等都极易遭到外部人员的入侵。  
  
几个月前，一位化名Eaton Works的安全研究人员发现了本田系统的安全漏洞，他利用该漏洞入侵了本田的供应商门户网站。  
  
Eaton Works利用了一个密码重置API重置了那些本田内部有价值的账户的密码，然后在公司的网络上进行了不受限制的管理级数据访问。  
  
研究人员称：访问控制的破坏或缺失使得访问平台上的所有数据成为可能，即使是以测试帐户登录也是如此。  
  
以下这些信息不仅暴露给了安全研究人员，还极可能暴露给了那些利用相同漏洞入侵的威胁行为者：  
  
- 从2016年8月到2023年3月，所有经销商的21393个客户订单，其中包括客户姓名、地址、电话号码和订购的商品  
  
- 1570个经销商网站(其中1091个是活跃的)，所有站点均可被修改  
  
- 3588个经销商用户/账户(包括姓名、电子邮件地址)，任意用户密码均可被修改  
  
- 1090封经销商电子邮件(包括姓名)  
  
- 11034封客户邮件(包括名字和姓氏)  
  
- Stripe、PayPal和Authorize.net提供的私钥。  
  
- 内部财务报告  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylggpfnZic6Ud2X5ncSXaQe5go1W75CATmLOHqxyM7H9m601rn2qdMMN6AzCXTYYKZZduoia4qYHYOFw/640?wx_fmt=jpeg "")  
  
曝光的客户邮件(eaton-works.com)  
  
上述数据可能被用于发起网络钓鱼活动、社会工程攻击，或直接被人在黑客论坛和暗网市场上出售。此外，通过访问经销商网站，攻击者还可以植入信用卡刷卡程序或其他恶意JavaScript代码片段。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylggpfnZic6Ud2X5ncSXaQe5gx1zO26HKSo9US0QofIwVH2DdVjyh5Pay0oVibvFKY9Kiaavohsw6bibuw/640?wx_fmt=jpeg "")  
  
能够编辑页面内容(eaton-works.com)  
  
## 访问管理面板  
  
EatonWorks解释说，API漏洞存在于本田的电子商务平台，该平台将“powerdealer.honda.com”子域名分配给注册经销商/经销商。  
  
研究人员发现，本田有一个网站的电力设备技术快车(PETE)密码重置API在处理重置请求时不需要令牌或之前的密码，只需要有效的电子邮件即可。  
  
虽然在电子商务子域登录门户上不存在此漏洞，但通过PETE站点切换的凭据仍然可以对它们起作用，因此任何人都可以通过这种简单的攻击访问内部经销商数据。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylggpfnZic6Ud2X5ncSXaQe5grV1DibPEz1eOXOaiakYLsYWvasuKB6VCaWacJguQzUXwsPBID7O08Jgw/640?wx_fmt=jpeg "")  
  
密码重置API请求发送到PETE (eaton-works.com)  
  
唯一缺失的部分是拥有一个属于经销商的有效电子邮件地址，研究人员从YouTube视频中获取了该电子邮件地址，该视频展示了使用测试帐户的经销商面板。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylggpfnZic6Ud2X5ncSXaQe5gddkU3VWAnHMHcs8kwU0DPMFY7XMca2tzdHrmwSyZ2gRpFPibhx8Q6og/640?wx_fmt=jpeg "")  
  
YouTube视频曝光测试账号邮箱  
  
除了测试账户，下一步就是从真正的交易商那里获取信息。但最好是在不中断操作的情况进行，这样就不必重新设置数百个帐户的密码。  
  
研究人员发现的解决方案是利用第二个漏洞，即平台中用户id的顺序分配和缺乏访问保护。  
  
这使得任意访问所有本田经销商的数据面板成为可能，具体方法就是将用户ID增加1，直到没有任何其他结果。  
  
研究人员称：只要增加ID就可以访问每个经销商的数据。底层JavaScript代码接受该ID，并在API调用中使用它来获取数据并在页面上显示。而值得庆幸的是，这个操作能让重新设置密码变得没什么实际效用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylggpfnZic6Ud2X5ncSXaQe5g9ko5Elkdiafztp0P0gMa0MXTAJkb3iaicot8aLicCopkgfs9Vm67m8zsCQ/640?wx_fmt=jpeg "")  
  
增加用户ID号码以访问所有经销商面板(eaton-works.com)  
  
值得注意的是，本田的注册经销商可能会利用上述漏洞访问其他经销商的面板，进而访问他们的订单、客户详细信息等。最后一步就是访问本田的管理面板，因为这是该公司电子商务平台的中央控制点。  
  
研究人员通过修改HTTP响应假扮管理员访问该面板，从而实现无限制地访问本田经销商网站平台。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylggpfnZic6Ud2X5ncSXaQe5gYQOB6mxnnjOqsCDoxFKGHomq1dx68ygibNHGF9xlR8Q870fkxJqkVhQ/640?wx_fmt=jpeg "")  
  
本田经销商网站管理面板(eaton-works.com)  
  
有关上述这个漏洞的相关问题是在今年3月16日报告给了本田，到今年4月3日，所有问题都已得到妥善解决。  
  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljDDP5dRyX59bBObmIzCibVdYxslpAOBD0j4hWjtYXdhyvMph7WEmlyndF5WsiaNaIVKGqrCPP7BZsQ/640?wx_fmt=jpeg "")  
[【安全圈】宕机故障损失亿元，影响客户达800多万！唯品会开除基础平台部负责人](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652036218&idx=1&sn=7204f0f14782906ee62ac205723073f7&chksm=f36ff03ac418792c705aed8a410d48eb0e6dee36b2d02bda88366fb21d0770bbcf57f2ecf466&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljDDP5dRyX59bBObmIzCibVdesic8yxS2ttjOl3YFcSx2XicOasgHE4jNJFVtiab8857fcWOgDrauA2gg/640?wx_fmt=png "")  
[【安全圈】因拼写错误，17个数据库被删除！微软Azure DevOps罢工十小时](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652036218&idx=2&sn=0ea344af544be75e305c82e5be9236ff&chksm=f36ff03ac418792c64c7f8b63f5399656be929b8dcb5d9749b7cc1d02d4f15dd2f95214713ba&scene=21#wechat_redirect)  
  
  
  
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
  
  
