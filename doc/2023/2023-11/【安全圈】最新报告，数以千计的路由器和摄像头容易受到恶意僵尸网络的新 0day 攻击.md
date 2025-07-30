#  【安全圈】最新报告，数以千计的路由器和摄像头容易受到恶意僵尸网络的新 0day 攻击   
 安全圈   2023-11-24 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgFfnDr5Z6QNE2aw6InKANaFgRrFzSzccicVRjiadmt7UE6Ec3BF3eOqdp0OXQM2SABrZEiaSkAKnAyQ/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
零日攻击  
  
  
网络公司Akamai的研究人员发现不法分子正在利用两个新的0day漏洞，将路由器和录像机引入恶意僵尸网络，用于分布式拒绝服务攻击。  
  
  
**0day漏洞利用：** 不法分子利用两个新的0day漏洞，这些漏洞之前对设备制造商和安全研究社区都是未知的。当受影响的设备使用默认管理凭据时，这两个漏洞允许远程执行恶意代码。  
  
  
**目标设备：** 受攻击的0day漏洞中，一个存在于某些网络录像机型号中，另一个存在于为酒店和住宅应用构建的基于插座的无线LAN路由器中。受影响的路由器由一家日本制造商销售，其被利用的功能是一种非常常见的特性。  
  
  
**攻击手段：** 未知攻击者一直在利用这些0day漏洞来破坏设备，以便将其感染为Mirai僵尸网络的一部分。Mirai是一款强大的开源软件，使路由器、摄像头和其他物联网设备成为能够发起攻击的僵尸网络的一部分。  
  
  
**潜在影响：** Mirai僵尸网络发起的DDoS攻击规模以前很难想象，因此这些新的0day漏洞可能会导致更广泛的网络威胁。  
  
  
**安全响应：** Akamai已向两家制造商报告了这些漏洞，其中一家制造商已承诺将在下个月发布安全补丁。在修复措施到位之前，Akamai不会确定具体设备或制造商，以防止0day漏洞被更广泛地利用。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgFfnDr5Z6QNE2aw6InKANap2m6jZrbJPTwUsl2YyFSicRHFoNtdsOJfia12TB8ZsnVdbMzrS91qn3Q/640?wx_fmt=jpeg&from=appmsg "")  
  
  
对于用户和网络管理员来说，面对这样的威胁，及时更新设备的固件和软件、使用强密码、禁用不必要的服务等是提高安全性的关键步骤。此外，密切关注安全研究和制造商的更新，以及及时采取相应的安全措施也是至关重要的。  
  
  
Mirai于2016年首次引起广泛关注，当时通过发动当时创纪录的620 GB每秒的DDoS攻击，摧毁了安全新闻网站KrebsOnSecurity，成为公众关注的焦点。Mirai之所以引人注目，不仅是因为其强大的攻击力量，还因为它征用了路由器、安全摄像头和其他物联网设备，这在此之前基本上是不被察觉的。此外，Mirai的底层源代码很快就能够免费获取，进一步推动了其在网络攻击中的广泛应用。  
  
  
随着时间的推移，Mirai不仅用于攻击安全新闻网站，还用于更大规模的DDoS攻击，针对游戏平台和为其提供服务的ISP。从那时起，Mirai和其他物联网僵尸网络已经成为互联网生活的一部分。  
  
  
最近，Akamai发现的攻击中使用的Mirai僵尸网络恶意软件主要是一种名为JenX的较旧变种，该变种经过修改，使用比平常少得多的域名连接到命令和控制（C2）服务器。一些恶意软件样本还显示出与名为“HailBot”的独立Mirai变体有关。  
  
  
在这次攻击中，使用的代码与一家中国安全公司在五月份观察到的针对俄罗斯新闻网站的DDoS攻击中使用的代码几乎相同，这可能表明了攻击者的相似手法和工具。  
  
  
然而，关于受影响的设备型号和版本的完整报告，研究人员尚未从NVR供应商处获得。据估计，NVR供应商生产了大约100种NVR/DVR/IP监控摄像机产品，因此确切了解哪些受到影响，哪些没有受到影响是相当困难的。  
  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgFfnDr5Z6QNE2aw6InKANaoFTSbkSLJn43P5MribO7uzcMwFS4I6O8FFlRtKYzMZ8TVDvwlC7Fcmg/640?wx_fmt=jpeg "")  
[【安全圈】涉及金额超82亿，黑客入侵浙江省评标专家库勾结职业黄牛串标被抓](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652049138&idx=1&sn=f4778b8f775368f03e4ef2b095c083a2&chksm=f36e22b2c419aba4fd10912a7b6748f1090831718541147e61260f962253e518c6c6e9860e4b&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgFfnDr5Z6QNE2aw6InKANaCNr8gdLeCIbbHfRcbqdtK4t2GGndPPiaVWagqGE5W5mruhsD9KkZwrQ/640?wx_fmt=jpeg "")  
[【安全圈】上海银行涉及多项EAST数据漏报错报等行为，被罚1380万元](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652049138&idx=2&sn=4a1f04e66a7f7bedd9933c64ef016b15&chksm=f36e22b2c419aba45b15883c2df29be5308b75f882adcdf2e91fd598535321fcfd28831abc4a&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgFfnDr5Z6QNE2aw6InKANa8DXIOWuTKNhluWNUD9ibKX7wKlickEwibcvxvk6Rf7aXzOPZZbNk1icFrw/640?wx_fmt=jpeg "")  
[【安全圈】陌生人发来空压缩包文件，结果72万元不翼而飞](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652049138&idx=3&sn=953ed319fde6a73dca63568c76e08de3&chksm=f36e22b2c419aba40f25747773baeaf99ecd8e5c8d8a12eff6eb23513063b19e40767284bb7e&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgFfnDr5Z6QNE2aw6InKANajtoHsd844aeXBAe08IiaSNBWTB1ibAzmv4HdiaBJrLKyE1QwhkvjlK6iag/640?wx_fmt=jpeg "")  
[【安全圈】黑客使用供应链攻击战术，致全球有4个国家受到影响](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652049138&idx=4&sn=d6a01fbcfe2581c7ba3c43da027a3b92&chksm=f36e22b2c419aba43884e2c58a86e0ebc9d11c69583dcbfcc3da9c57efe593306a14f0e91b2e&scene=21#wechat_redirect)  
  
  
  
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
  
  
