#  Okta被黑溯源：系统设计曝重大漏洞，机器账号未做安全防护   
安全内参编译  安全内参   2023-11-06 17:59  
  
**关注我们**  
  
  
**带你读懂网络安全**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FzZb53e8g7uiaA3eJdGibH8lWvjkRgaicMjzKVNXfBxRlO4qvmMPiavnIsRicnjGiaTzzPBLUgAdsAOqnlysKIQVMm8w/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**Okta业务系统被黑导致客户遭入侵，溯源发现该事件源于一名员工用个人Chrome账号同步了工作电脑上的业务系统服务账号密码，而该服务账号未做任何访问限制、二次验证等安全手段；**  
  
  
**Okta披露文章将入侵责任主要归咎于不守规矩的员工，这掩盖了系统设计漏洞的真正责任所在，如果某个员工有过失就导致网络被入侵，只能说明公司做得不够好。**  
  
前情回顾·**身份供应商攻击兴起**  
- [Okta被黑后市值蒸发逾20亿美元，身份供应商成为攻击焦点](http://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247510109&idx=1&sn=4831a052c626320188d963c5b3eb51ee&chksm=ebfaef7ddc8d666bacc265636b5c3e5bc19936c05bf38e8bbfb8683a42e202ae70822e4ca129&scene=21#wechat_redirect)  
  
  
- [Okta业务系统被黑导致客户遭入侵，公司股价暴跌11%](http://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247510095&idx=1&sn=0c8c8c42c612a4a4b4690ba09514fa71&chksm=ebfaef6fdc8d6679faae3c5f10eaa14cf31ad2cc646d294001a6438b289e176bebea510adabc&scene=21#wechat_redirect)  
  
  
- [（Okta系统被黑导致）凯撒娱乐支付了超过1亿元勒索软件赎金](http://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247509799&idx=1&sn=995f6fba9bd5c442b4e1eef110b64080&chksm=ebfae007dc8d69116422177d29f2ec96b33dbf2435ca28e1d6b15af10fbd4a25c150bd1ec181&scene=21#wechat_redirect)  
  
  
- [Okta 2022年为何被黑？研究发现4大高危害漏洞｜身份攻击溯源](http://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247504520&idx=1&sn=cb049fa04dcc2db31f3380de3f8f0a82&chksm=ebfa95a8dc8d1cbe9b664fc6471fdb891ec3b126ffa19597806b85fafa68df2dac7407833cbe&scene=21#wechat_redirect)  
  
  
  
  
安全内参11月6日消息，国际身份软件巨头Okta日前发布了一份安全溯源公告，对9月28日到10月17日的一起入侵事件进行回顾性梳理，期间实施入侵的黑客获取了134个客户的敏感文件，并进一步劫持了5个客户的Okta账户管理员访问权限。  
  
溯源报告强调，有员工出现操作失误，在工作设备上登录了个人谷歌账户。但是，入侵事件最大的诱因其实是一个配置不当的服务账户，Okta对这一点选择低调处理。  
  
Okta首席安全官David Bradbury发帖表示，威胁行为者发动攻击获取了公司部分客户支持系统的访问权限，这次攻击最可能的路径如下：  
> 威胁行为者先是入侵了一个员工的个人设备或个人谷歌账户，由此获取了一种名为“服务账户”的特殊账户的用户名和密码。服务账户负责连接到Okta网络的支持部分。一旦威胁行为者获取该账户的访问权限，他们就可以获得1Password、BeyondTrust、Cloudflare等Okta客户所持Okta账户的管理凭据。  
‍  
  
  
  
  
**推卸责任**  
  
  
  
David Bradbury写道，“我们对这个账户的可疑使用进行调查期间，Okta安全团队发现一个员工已经在他的公司笔记本电脑上的Chrome浏览器登录个人谷歌账户。这一个人账户保存了服务账户的用户名和密码。员工个人谷歌账户或个人设备遭到入侵，是这些凭据最可能的被泄露路径。”  
  
换而言之，如果员工在已经登录个人谷歌账户的Chrome浏览器上登录工作账户，Chrome内置的密码管理器就会将工作账户的凭据保存到个人谷歌帐户中。然后，威胁行为者通过入侵个人账户或设备，获取了访问Okta账户所需的凭据。  
  
一直以来，像Okta这样的公司坚决禁止登录个人账户。如果之前有人不太清楚对这个禁令，现在应该明白了。这位员工肯定违反了公司政策。如果他因为这个违规行为被解雇，也不足为奇。  
  
然而，如果诱发入侵事件的只是员工的不端行为，只能说明所有人都犯了错。其实，责任在于设计被入侵支持系统的安全人员，特别是被入侵服务账户的配置方式。  
  
服务账户存在于各种操作系统和框架。这种账户与人类访问的标准用户账户不同。服务账户主要用于自动化的机器对机器功能，比如每晚在特定时间执行数据备份或杀毒扫描。因此，它们不能像用户账户那样通过多因素身份验证进行锁定。这也解释了为什么Okta没有设置多因素身份验证。然而，**入侵事件暴露了一些Okta首席安全官的帖子中没有得到应有关注的缺陷**。  
  
  
**根因分析**  
  
  
  
David Bradbury说，Okta在2023年9月29日首次发现公司网络存在潜在可疑活动。  
当时，1Pas  
sword主动向Okta报告，其内部Okta实例已经被入侵。  
起初，怀疑1Password员工设备感染了恶意软件，导致入侵。  
  
然而，10月2日，另一家客户BeyondTrust主动报告，告知Okta他们的账户也被入侵。Okta直到10月16日才确认了入侵来源。如此迟缓的行动让威胁行为者得以在两周多的时间里持续访问服务账户。  
  
David Bradbury写道：“当用户打开并查看与支持案例相关联的文件时，会生成与该文件相关的特定日志事件类型和ID。如果用户选择直接导航到客户支持系统中的“文件”选项卡（就像威胁行为者在这次攻击中所做的那样）。它们将生成一个完全不同的日志事件，具有不同的记录ID。”  
  
“Okta最初将调查重点放在对支持案例的访问上。随后，我们评估了与这些案例相关的日志。10月13日，BeyondTrust向Okta安全团队提供了一个怀疑是威胁行为者的可疑IP地址。基于这一信息，我们确定了与被入侵账户相关的更多文件的访问事件。”  
  
Okta对其网络的可见性不足是另一个失败之处。虽然这并不是入侵的诱因，但它放大了入侵的后果。否则，Okta就能更早发现威胁行为者的访问行为。  
  
  
**写给Okta安全团队的备忘录**  
  
  
首先，Okta应该在简  
单的密码之外制定访问控制措施，限制哪些对象可以登录到服务账户。  
其中一种方法对可以连接的IP地址设置限制或条件。  
另一种方法是定期更换用于对服务账户进行身份验证的访问令牌。  
当然，不得允许员工在工作机器上登录个人账户。  
Okta高级管理人员有责任落实所有相关预防措施。  
  
  
一些长期在敏感云环境中工作的安全专业人员也纷纷发帖给出建议。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FzZb53e8g7tzEmTHssz55ChUGe3F9F8mx9wekmwUicSfJ2dhcXOEfyPpsIAOia1icKygia42XSbJZyxlYRD94AyicxA/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FzZb53e8g7tzEmTHssz55ChUGe3F9F8mNMm8EtwCPfF2LZ4Nia9e7NPwGZ6D6bfd9ib5TyLfnTJ2qFD1jcaw64Uw/640?wx_fmt=png "")  
  
  
虽然零信任安全方法有时被过度使用，但它的大原则是正确的。假设你的网络已经被入侵，希望通过设计防止任何不安全事件。企业应该使用分层设计、纵深防御的方法来预防出现单一故障点，比如防止简单密码或身份验证令牌发生泄露。  
  
David Bradbury在帖子中列出了一些纠正步骤，承认存在一些失误。具体步骤包括：  
  
1. 禁用被入侵的服务账户（已完成）。Okta已经在客户支持系统中禁用了服务账户。  
  
2. 禁止使用个人谷歌账户与谷歌Chrome浏览器（已完成）。Okta已经在Chrome 企业版中选用特定配置选项，防止员工在公司笔记本电脑上使用个人谷歌账户登录Chrome浏览器。  
  
3. 加强对客户支持系统的监控（已完成）。Okta已经为客户支持系统部署了额外的检测和监控规则。  
  
4. 根据网络位置绑定Okta管理员会话令牌（已完成）Okta已经基于网络位置绑定会话令牌，作为一种产品增强措施，防止对Okta管理员会话令牌遭窃取。只要检测到网络变化，Okta管理员将被强制重新进行身份验证。客户可以在Okta管理员门户的早期访问部分启用这个功能。  
  
**Okta能够做出上述改变并提供事件时间表，这些行为值得赞扬。但是，将入侵的责任归咎于某个员工失误，是拿员工当替罪羊，掩盖了真正的责任所在。最严重的失误是高管犯下的。希望他们能收到这个备忘录。**  
  
  
**参考资料：arstechnica.com**  
  
  
**推荐阅读**  
- [网安智库平台长期招聘兼职研究员](http://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247499450&idx=2&sn=2da3ca2e0b4d4f9f56ea7f7579afc378&chksm=ebfab99adc8d308c3ba6e7a74bd41beadf39f1b0e38a39f7235db4c305c06caa49ff63a0cc1d&scene=21#wechat_redirect)  
  
  
- [欢迎加入“安全内参热点讨论群”](https://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247501251&idx=1&sn=8b6ebecbe80c1c72317948494f87b489&chksm=ebfa82e3dc8d0bf595d039e75b446e14ab96bf63cf8ffc5d553b58248dde3424fb18e6947440&token=525430415&lang=zh_CN&scene=21#wechat_redirect)  
  
  
  
  
  
  
  
点击下方卡片关注我们，  
  
带你一起读懂网络安全 ↓  
  
  
  
  
