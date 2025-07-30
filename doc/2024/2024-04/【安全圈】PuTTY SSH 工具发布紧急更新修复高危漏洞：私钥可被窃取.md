#  【安全圈】PuTTY SSH 工具发布紧急更新修复高危漏洞：私钥可被窃取   
 安全圈   2024-04-26 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
热门 SSH 和 Telnet 工具 PuTTY 被曝安全漏洞，追踪编号为 CVE-2024-31497，影响 0.68-0.80 版本，**攻击者只需使用 60 个签名就能还原私钥。**  
官方目前已经更新发布了 0.81 版本，并推荐用户尽快升级到最新版本中。  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhsiaBBpR8icOa37TByqAZiazWILqZB4wmBicFH6aVkjJhRxFpkiaucetpg4LERur7JKYicO8hgOKOEnIibQ/640?wx_fmt=webp&from=appmsg "")  
  
  
  
该漏洞由波鸿鲁尔大学的 Fabian Bäumer 和 Marcus Brinkmann 发现，存在于 PuTTY 工具的 SSH 身份认证环节。该应用会调用 NIST P-521 曲线生成 ECDSA nonces（临时唯一加密数字），不过这些数字是通过确定性方式生成的，因此存在偏差。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhsiaBBpR8icOa37TByqAZiazW1csAZKMuPvmUVHVr3yGyy6nIE2ibgZLAHou9vGZuJ4knVib0UY2oU5bA/640?wx_fmt=jpeg&from=appmsg "")  
  
攻击者只需要访问几十条已签名消息和公钥，就能从中恢复私钥，后续就可以伪造签名，并在未经授权的情况下访问服务器。  
  
IT之家注：除了 PuTTY 之外，包括 FileZilla、WinSCP 和 TortoiseGit 在内的相关组件也存在该问题。目前官方发布了 PuTTY 0.81、FileZilla 3.67.0、WinSCP 6.3.3 和 TortoiseGit 2.15.0.1，修复了该问题。  
  
官方表示 CVE-2024-31497 漏洞非常严重，敦促用户和管理员立即更新。当前使用 ECDSA NIST-P521 密钥的产品或组件均受影响，应通过从 authorized_keys、GitHub 存储库和任何其他相关平台中删除这些密钥，防止未经授权的访问和潜在的数据泄露。  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhsiaBBpR8icOa37TByqAZiazWXvffs2ib8xDjx1icH5XgDialH9u1HH4djmibwtBsWbBmSjcvWricwya1euA/640?wx_fmt=jpeg "")  
[【安全圈】“翻墙”违法！江门网警抓获涉案嫌疑人4名](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652058881&idx=1&sn=fa4a476547b4a304ea630d0b4fb63ead&chksm=f36e1941c419905715fdf1545d1328413621a22bd6612c2dd11945351a0bd0bb7d3ac855a8e4&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhsiaBBpR8icOa37TByqAZiazWuShzlPgIZVKflXAtx14NMrGe39CcJwibtzcNpfmVScYibsS6zjsDW64Q/640?wx_fmt=jpeg "")  
[【安全圈】警报：思科 ASA 防火墙平台遭遇“ArcaneDoor”0day攻击](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652058881&idx=2&sn=06c71b1369aebba0ff5f1eaf0426bce9&chksm=f36e1941c4199057cfc88a6b2e935e2a034daddd4a18c1d0d62dfddd09ba3e5c037b90e987a9&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhsiaBBpR8icOa37TByqAZiazWNsty1NF9sOahBS7mibyLeZ5hX5jmaLoOT6l7ia7KhAWchPsuG7QG7icTA/640?wx_fmt=jpeg "")  
[【安全圈】GitHub 被曝安全漏洞，可被黑客利用伪装成“微软”分发恶意软件](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652058881&idx=3&sn=0a21f1de27fc8dcacedba41d5e1d4383&chksm=f36e1941c41990575543827a9c6d183443deede552f68a7d779aa5dd7d13a448e1590d086e8c&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhsiaBBpR8icOa37TByqAZiazWQzU0nddPJCK6EApetZJ9RPKmMeUCsAPt2tGd5bmK0I63jIkmCRpqMQ/640?wx_fmt=jpeg "")  
[【安全圈】研究者把 EDR 安全工具改造成超级恶意软件](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652058881&idx=4&sn=157f18e8ab1705c8b860f1cb502b9be9&chksm=f36e1941c4199057638c5785140fbcf522e766f5e2e5891440485323a729d73756efd7b13bfd&scene=21#wechat_redirect)  
  
  
  
  
  
  
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
  
