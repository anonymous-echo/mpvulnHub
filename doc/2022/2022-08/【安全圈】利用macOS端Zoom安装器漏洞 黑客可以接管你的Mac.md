#  【安全圈】利用macOS端Zoom安装器漏洞 黑客可以接管你的Mac   
 安全圈   2022-08-14 20:22  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgSxa9I02IBd3bgLEhwfJCeRibw3LEjMujeAhD2CvyiaVCZJVHGHODbkPx3pViaX0sAibZsDun6sicUzdQ/640?wx_fmt=jpeg "")  
  
**关键词**  
  
  
  
漏洞  
  
  
  
一名安全专家近日发现利用 macOS 端 Zoom 应用程序，掌控整个系统权限的攻击方式。本周五在拉斯维加斯召开的 Def Con 黑客大会上，Mac 安全专家帕特里克·沃德尔（Patrick Wardle）在演讲中详细介绍了这个漏洞细节。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGyliaqTVvSVDTprM4icy7IYFUicyckABibHhBEGfnUicb6AJJLvhicnwATQcRsc0DaLFakuWWeQtHSf4ZIz4Q/640?wx_fmt=png "")  
  
  
虽然 Zoom 已经修复了演示中的部分 BUG，但是沃德尔还演示了一个尚未修复、依然可以影响 macOS 系统的漏洞。该漏洞通过 Zoom 应用的安装器进行入侵，虽然在首次添加到 macOS 的时候需要用户输入系统密码，不过沃德尔表示可以通过超级用户权限在后台执行自动升级功能。  
  
  
在 Zoom 发布修复更新之后，在安装新的安装包的时候都需要审查是否经过 Zoom 加密签署。不过这种审查方式依然存在缺陷，任意文件只需要修改为和 Zoom 签署认证相同的文件名称就可以通过测试，因此攻击者可以伪装任意恶意程序，并通过提权来掌控系统、  
  
  
其结果是一种权限提升攻击方式，需要攻击者已经获得了对目标系统的初始访问权限，然后利用漏洞来获得更高级别的访问权限。在这种情况下，攻击者从受限用户帐户开始，但升级为最强大的用户类型——称为“superuser”或“root”——允许他们添加、删除或修改机器上的任何文件。  
  
  
![](https://mmbiz.qpic.cn/mmbiz/aBHpjnrGyliaqTVvSVDTprM4icy7IYFUicy6mqEkefGcHXjV9ele6PJQPPO3SiasZz15Zs3a13pevRC53MDfBlgzag/640?wx_fmt=other "")  
  
  
沃德尔在去年 12 月向 Zoom 报告了这个问题。虽然 Zoom 随后发布了一个修复补丁，但是令他沮丧的这个修复补丁包含另一个错误，这意味着该漏洞仍然可以以稍微更迂回的方式利用，因此他向 Zoom 披露了第二个错误，并等待了八个月才发布研究。  
  
  
沃德尔表示：“对我来说，我不仅向 Zoom 报告了错误，还报告了错误以及如何修复代码，所以等了六、七、八个月，知道所有 Mac 版本的 Zoom 都在用户的计算机上仍然易受攻击，真是令人沮丧”。  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGyliaqTVvSVDTprM4icy7IYFUicyjy1CnULbId37SgJchIDTVksibOGf529tphu5ZibEfYS6djRyibgIxBnCg/640?wx_fmt=jpeg "")  
[【安全圈】真刑啊！男子破解博彩网站漏洞，每月“薅羊毛”10多万，凭技术走上歪路](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652013078&idx=1&sn=320de9db673ae308877bb0a4c0e74f6b&chksm=f36fae56c418274037bbadf2590e2c81f782678dc72dbc9bb7ebe28a2b0d13ff9ec8392674fd&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGyliaqTVvSVDTprM4icy7IYFUicytxWjOWfWOicOP5xiazFYEhdBo5e2RyOLK24HbygBo8HiauRkzxtsgrvXg/640?wx_fmt=jpeg "")  
[【安全圈】诱导用户提供隐私数据：谷歌被罚超4亿元](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652013078&idx=2&sn=c452a135e2f58e1fbaafdbea6c0f66d0&chksm=f36fae56c4182740dbf3c6d14f997e7e7d5f3c9edab9f417d73d69cbb50615ca35f09b8ccd35&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGyliaictzlJgTwXYsBE1MaMgH15vGWw4mkL61DfdgB0DcaYmWjs5tOhXn3sMcQ0VJeq08hA408R7zZZzA/640?wx_fmt=jpeg "")  
[【安全圈】银行木马 SOVA 卷土重来，或可发起勒索攻击](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652013078&idx=3&sn=701550632db33ef446026df365db0937&chksm=f36fae56c41827401df5690a677c3a811946d75a80e5be73a493ba89506ceee80d0758148a4e&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGyliaqTVvSVDTprM4icy7IYFUicygsiaZ4PE9V7gFnQL6cF7W4Zxlib5dQazyQkpzf5o2fHfL0DEtLm3AJhg/640?wx_fmt=jpeg "")  
[【安全圈】美国悬赏1000万美元追缉勒索软件组织Conti五名主要成员](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652013078&idx=4&sn=68d6796ceec82c8b916d4c3c014b458b&chksm=f36fae56c418274064ab35ab9007626cec37c415101138504692505b59242a9835daad77c535&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
  
  
