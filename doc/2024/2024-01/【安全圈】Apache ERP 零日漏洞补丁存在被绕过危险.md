#  【安全圈】Apache ERP 零日漏洞补丁存在被绕过危险   
 安全圈   2024-01-06 19:17  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
漏洞  
  
  
一个未知的组织已经开始调查Apache的OfBiz企业资源规划(ERP)框架中发现的零日漏洞。这个框架正在变得越来越受欢迎，因此对于寻找绕过软件修复方法的策略变得越来越关键。这次的调查引起了广泛的关注，因为零日漏洞可能会对软件系统的安全性构成重大威胁。  
  
  
  
根据网络安全公司SonicWall的分析，最近披露的Apache OFBiz中的0day漏洞(CVE-2023-51467)存在严重威胁，允许黑客访问敏感信息并远程执行代码，特别是对使用ERP框架的应用程序。尽管Apache软件基金会最初发布了CVE-2023-49070漏洞的修复补丁，但很明显这个修复措施无法应对其他变体的攻击。SonicWall的威胁研究执行总监道格拉斯·麦基（Douglas McKee）指出，这次事件凸显了黑客对针对高价值漏洞发布的任何补丁都进行了详细审查的策略，通常这些努力会导致他们找到绕过软件修复的方法。这个情况引发了广泛关注，因为它暴露了软件系统在面对零日漏洞时的脆弱性。  
  
  
“一旦有人完成了工作，说‘哦，这里存在一个漏洞’，现在一大群研究人员或黑客就可以关注这个漏洞，而你就让自己接受了更多的考验，“ 他说。“你已经引起了对该代码区域的注意，如果你的补丁不是坚如磐石或者遗漏了某些内容，那么它更有可能被发现，因为你对它有额外的关注。”  
  
SonicWall 研究人员 Hasib Vhora 分析了 12 月 5 日的补丁，发现了利用该问题的其他方法，该公司于 12 月 14 日向 Apache 软件基金会报告了这一情况。  
> Vhora在问题分析中表示：“在分析 CVE-2023-49070 补丁时，我们对所选择的缓解措施很感兴趣，并怀疑仍然存在身份验证被绕过的情况，因为该补丁只是从应用程序中删除了 XML RPC 代码。” 。“因此，我们决定深入研究代码，找出身份验证绕过问题的根本原因。”  
  
### 补丁存在漏洞  
  
Apache 并不是唯一一家发布了黑客能够绕过的补丁的公司。根据谷歌威胁分析小组 (TAG) 发布的数据，2020 年，使用零日漏洞攻击的 24 个漏洞中有 6 个 (25%) 是之前修补的安全问题的变体。谷歌在更新的分析中表示，到 2022 年，受到零日漏洞攻击的 41 个漏洞中，有 17 个（41%）是先前修补问题的变体。  
  
Google Mandiant 的高级经理 Jared Semrau 表示，公司未能完全修补问题的原因有很多，从不了解问题的根本原因到处理大量积压的软件漏洞，再到优先考虑立即修补而不是全面修复。  
> “对于为什么会发生这种情况，没有简单、单一的答案，”他说。“有几个因素可能会导致补丁不完整，但SonicWall 研究人员是绝对正确的 – 很多时候公司只是修补已知的攻击向量。”  
  
  
谷歌预计，针对未完全修补的漏洞的零日攻击所占比例仍将是一个重要因素。从黑客的角度来看，发现应用程序中的漏洞很困难，因为研究人员和黑客必须查看数十万或数百万行代码。通过专注于可能尚未正确修补的有前途的漏洞，黑客可以继续攻击已知的弱点，而不是从头开始。  
### 解决 OfBiz 问题的方法  
  
在很多方面，这就是 Apache OfBiz 漏洞所发生的情况。原始报告描述了两个问题：需要访问 XML-RPC 接口 (CVE-2023-49070) 的 RCE 缺陷，以及为不受信任的黑客提供此访问权限的身份验证绕过问题。ASF 安全响应团队在回答 Dark Reading 的问题时表示，Apache 软件基金会认为删除 XML-RPC 端点可以防止这两个问题被利用。  
> “不幸的是，我们忽略了相同的身份验证绕过还会影响其他端点，而不仅仅是 XML-RPC 端点，”该团队表示。“一旦我们意识到这一点，第二个补丁就在几个小时内发布了。”  
  
  
Apache 软件基金会成员 Deepak Dixit在 Openwall 邮件列表中表示，该漏洞被 Apache 追踪为 OFBIZ-12873，“允许黑客绕过身份验证以实现简单的服务器端请求伪造 (SSRF)” 。他认为 SonicWall 威胁研究员 Hasib Vhora 和另外两名研究人员（Gao Tian 和 L0ne1y）发现了这个问题。  
  
由于 OfBiz 是一个框架，是软件供应链的一部分，因此该漏洞的影响可能会很广泛。例如，流行的 Atlassian Jira 项目和问题跟踪软件使用 OfBiz 库，但该漏洞能否在该平台上成功执行仍然未知。  
> Sonicwall 的 McKee 表示：“这将取决于每家公司构建网络的方式以及配置软件的方式，”他说。“我想说，典型的基础设施不会面向互联网，它需要某种类型的 VPN 或内部访问。”  
  
  
ASF 安全响应团队表示，无论如何，公司都应该采取措施，将已知使用 OfBiz 的任何应用程序修补到最新版本。  
> “我们对使用 Apache OFBiz 的公司的建议是遵循安全最佳实践，包括仅向需要的用户授予对系统的访问权限，确保定期更新您的软件，并确保您有能力在安全问题发生时做出响应。”  
  
  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhMtKnaFsOIbPt9UE3Vsm6ShzCK0CwPhVM8ibVwHUwscZtt6668OCCv6OgvklmfBnmjQRLhkEYmWtw/640?wx_fmt=jpeg "")  
[【安全圈】宝马子域SAP重定向漏洞曝光：网络钓鱼和恶意软件传播风险](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652051536&idx=1&sn=6eadb8dc4293ab4359a2530aff5012c1&chksm=f36e3410c419bd06ff06d10f69719b1078b7e6f9be5672a2164cbfc73cfdf00c838e21984229&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhMtKnaFsOIbPt9UE3Vsm6S9ye9J89lNiaauZ7Qgn2lwagB7mVEBHKTJpqj2c4Asvl80msnMwIGSpw/640?wx_fmt=jpeg "")  
[【安全圈】农行系统崩上热搜，网友直呼“抢不到啊！”](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652051536&idx=2&sn=c3da3a86f0a360aa48db5ab910879b25&chksm=f36e3410c419bd06d63418c26636d99c3d4812223179d4442feb156177478bba7c5f9d0e0dc1&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhMtKnaFsOIbPt9UE3Vsm6SKjsGSCPEjN7SYGTsSayWokv1dwU45EQz30C96FV2VLH4hTNbjxmp9g/640?wx_fmt=jpeg "")  
[【安全圈】为了打击图像造假问题，尼康、索尼和佳能将采用数字签名技术](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652051536&idx=3&sn=f79b7f8707c1e38b058af27b9c473dc2&chksm=f36e3410c419bd06cdf03f6eb12134374d28af07eb6f32aca2c533dc15f4c3eaf3a2399e0a83&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhMtKnaFsOIbPt9UE3Vsm6SBicZhBTUlZbp3lrv5f0j4QEvKguSkoPicZDNGbQ1W7oXytWIqwwxvbSQ/640?wx_fmt=jpeg "")  
[【安全圈】黑客使用人工智能发动商业电子邮件欺诈！已影响多个国家](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652051536&idx=4&sn=75a9cfe708de1aa2b9ceb5e50f193b90&chksm=f36e3410c419bd065b5c9843923f2014a2969b3900d7ccd9e9b168737f75083d1719b26d9356&scene=21#wechat_redirect)  
  
  
  
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
  
  
