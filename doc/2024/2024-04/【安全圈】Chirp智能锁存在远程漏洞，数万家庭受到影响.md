#  【安全圈】Chirp智能锁存在远程漏洞，数万家庭受到影响   
 安全圈   2024-04-18 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
信息泄露  
  
  
美国网络安全和基础设施安全局（CISA）发布了一则警告，指出 Chirp Systems 智能锁存在一个“低攻击复杂性”的远程漏洞，攻击者可以远程解锁智能锁并物理渗透受保护的位置。  
  
该漏洞是由 Chirp Android 应用程序硬编码密码和私钥造成的。这些数据可用于访问智能锁提供商 August 的 API，从而远程控制锁。据称，Chirp 系统已经拥有超过 50,000 个用户。  
  
Chirp 的软件允许控制与 August 和 Yale 等公司的产品兼容的锁，后者是瑞典公司 Assa Abloy 旗下的产品。  
  
根据 CVSS（通用漏洞评分系统）的评估，该漏洞 ID 为 CVE-2024-2197，严重程度评为 9.1 分（满分 10 分）。CISA 也因此发布了警告，指出 Chirp 尚未采取必要措施修复该漏洞。  
  
这个问题是由 Amazon Web Services 的工程师 Matt Brown 发现的。他在家里安装了这种锁后开始研究 Chirp 应用程序。据他介绍，修复该漏洞并不困难，但由于某种原因，制造公司对此并没有表现出兴趣。  
  
此外，Chirp 还提供 NFC 密钥作为应用程序的替代方案。但由于它以明文形式传输数据，因此无法免受远程攻击。为了能使用这把并不可靠的钥匙，Brown 不得不支付 50 美元。工程师建议拥有通过 Chirp 控制智能锁的人使用额外的机械锁来增强安全性。  
  
最近几个月，与智能锁相关的漏洞变得相当多。例如德国宜必思连锁酒店的锁，在自助服务终端上使用六个破折号就能打开所有门；甚至更早之前，Saflock 锁也出现了漏洞，该锁可以使用廉价的 RFID 读卡器/写卡器轻松打开。  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhqJF96UJcia31NWrxnyhnmSp1EFlFm6Ka0MCLLdBePHSicd2I8Bk6J1RNLZw6W3QLOeD1KB7BtWJ9Q/640?wx_fmt=jpeg "")  
[【安全圈】刘强东AI数字人直播首秀2000万观看，AI技术电商领域进一步应用](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652058230&idx=1&sn=4c089383cc3b84e90566d8ee3a67b871&chksm=f36e1e36c41997204bc470d69ce14ec5d485ee4b05ddea2f29eb783fa20b7fc1e25a5bfe7e2d&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhqJF96UJcia31NWrxnyhnmSpj8DnHNlz3Qq17P9O44RD2UicoBKTxgo3ViawN9uh7ftt9UxPnaib3j6A/640?wx_fmt=jpeg "")  
[【安全圈】光学仪器行业领军企业遭遇勒索攻击，被索要超7000万元巨额赎金](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652058230&idx=2&sn=4e7b8bf04af90989fd184b43117bbcbd&chksm=f36e1e36c4199720e5c2632c3f12996b7dfc99229b1e2b76a19771eb43de4fa8d2009cb318b3&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhqJF96UJcia31NWrxnyhnmSOFBkNYOfwaCAziadaLGCtYAHcibIjXy7B5U6BmAWrXD2OB8gnBXcBr5Q/640?wx_fmt=jpeg "")  
  
[【安全圈】Linux 发行版 Gentoo 宣布禁止 AI 自然语言技术协助下创建的内容](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652058230&idx=3&sn=d47bdc8c6a17a00869d2edf7aa22714c&chksm=f36e1e36c4199720ffc7b37706f456be24048c013ba38ba1bb3785c0a3ed6ea8fe5bd553f766&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhqJF96UJcia31NWrxnyhnmSkkDBXeNzD0zeIq7TiahG9brxia43JftmuQObPGrOmobWbJJLM242pdicQ/640?wx_fmt=jpeg "")  
[【安全圈】乌克兰使用破坏性 ICS 恶意软件“Fuxnet”攻击俄罗斯基础设施](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652058230&idx=4&sn=57bf2bc1def0fa29f8f104ce7d2c54c4&chksm=f36e1e36c419972028acc043314136beab116256765d866b36f3051caf68330dc5643de6c59f&scene=21#wechat_redirect)  
  
  
  
  
  
  
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
  
