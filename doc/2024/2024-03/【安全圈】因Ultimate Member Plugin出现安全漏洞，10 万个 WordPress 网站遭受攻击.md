#  【安全圈】因Ultimate Member Plugin出现安全漏洞，10 万个 WordPress 网站遭受攻击   
 安全圈   2024-03-12 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
  
WordPress安全公司Defiant的Wordfence团队最近发布了一个警告，指出Ultimate Member插件存在一个高危漏洞，可被利用进行跨站脚本（XSS）攻击，允许攻击者注入恶意脚本到WordPress网站。  
  
漏洞编号为CVE-2024-2123，影响Ultimate Member 2.8.3及更早版本。该漏洞的利用方式是通过成员目录列表功能，攻击者可在注册时提供恶意脚本作为用户名，导致未经身份验证的攻击者能够注入Web脚本。  
  
Wordfence解释指出，Ultimate Member插件在输入清理和输出转义方面存在不足，导致该漏洞的出现。攻击者成功利用漏洞后，可能获取易受攻击版本插件网站的管理用户访问权限。  
  
插件的开发人员于3月6日发布了补丁，建议用户尽快更新至Ultimate Member 2.8.4版本以修复漏洞。由于漏洞可能导致创建新的管理帐户、重定向到恶意网站或注入后门等恶意行为，用户的及时更新至关重要。  
  
Ultimate Member是一个用于WordPress的用户配置文件和会员插件，拥有超过200,000个活跃安装。根据WordPress统计数据，在过去7天内，该插件被下载了约100,000次，这表明一半用户仍然容易受到CVE-2024-2123的攻击。因此，用户应该密切关注并采取必要的安全措施，确保其WordPress网站不受潜在的安全威胁。  
  
  
以下是一些建议和操作步骤，以帮助用户降低受到该漏洞威胁的风险：  
  
1. **立即更新插件：** 如果您正在使用Ultimate Member插件，请立即更新到最新版本（2.8.4）。这是修复漏洞的官方版本，应该解决问题。  
  
1. **检查其他插件和主题：** 不仅仅是Ultimate Member插件，确保您的WordPress网站上的所有插件和主题都是最新版本。过时的软件可能存在其他安全漏洞。  
  
1. **监控网站活动：** 使用安全插件或服务，如Wordfence或Sucuri，以监控您的WordPress网站活动。这些工具可以帮助您及时察觉潜在的威胁和攻击。  
  
1. **备份网站：** 在进行任何更新之前，务必备份整个WordPress网站。这有助于在更新或修复过程中出现问题时迅速还原网站。  
  
1. **定期审查用户数据：** 定期审查WordPress用户的数据，特别是通过注册或表单提交的数据。确保没有异常或恶意数据。  
  
1. **定期更改管理员密码：** 作为一项基本安全措施，定期更改管理员密码，以防止未经授权的访问。  
  
1. **遵循最佳实践：** 遵循WordPress的最佳安全实践，例如使用强密码，限制登录尝试，以及审查和限制用户权限。  
  
1. **关注厂商通知：** 持续关注Ultimate Member插件和其他使用的插件或主题的开发者通知。他们可能会提供关于安全性的更新和建议。  
  
信息来源：**HackerNews**  
  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljvsdm1yZyeziaBghQIuibAicPY2ux8WehyDss5hgNKWaWjDib96QtZrEQudjhrT25A5V1KKsL3e6OAEQ/640?wx_fmt=png&from=appmsg "")  
[【安全圈】微软称，黑客近日正再次试图入侵其系统](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652055614&idx=1&sn=cccc300143960284a53000ef91e1579d&chksm=f36e047ec4198d687afc060fa1e44129a0b1ed5231d8eb80e848508c5b506de7738d3ab965d1&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljvsdm1yZyeziaBghQIuibAicPmLSjmUDuV5TBS22CjiaLAaqWwvdHqLZqdkkfibN23jTHmb9JKCKgkDog/640?wx_fmt=jpeg "")  
[【安全圈】一天就完成！Magnet Goblin Hacker Group 利用漏洞成功部署 Nerbian RAT](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652055614&idx=2&sn=e085c55917a6e9387a603b5f1b4e3b9e&chksm=f36e047ec4198d68a8312e18ea8ada0aec316b20d3f9c0ad891ecef9a052ebc2968a5f65d9ed&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljvsdm1yZyeziaBghQIuibAicPXfDkzHRWLZLbwfs0NaU0oWfrx2tPah0Wb8HicKwicqyfv9icickMZl3M6Q/640?wx_fmt=jpeg "")  
[【安全圈】出现新的钓鱼网络活动！能利用 Dropbox 基础设施绕过身份验证 ](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652055614&idx=3&sn=3ccd3efbe4c20bcf54a7236e5075ca86&chksm=f36e047ec4198d68f473175ca872a2baa7c7a93d2ec02ef86f77f07ac5067aad3ef06eb9690f&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljvsdm1yZyeziaBghQIuibAicPuWAQ7lRiamY9pm9j2dOTHojeDibDyEdYbv11GlibVvIPs3sGj9xgksMaA/640?wx_fmt=jpeg "")  
[【安全圈】黑客利用Ivanti破坏网络安全，CISA被迫将两个系统下线](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652055614&idx=4&sn=6201aeae4fc282a542cd735eecaf27a3&chksm=f36e047ec4198d68bf5dc91f8a20eae9e5799cdb8a633ef78fce12a1d6e8db0090d3dee41c05&scene=21#wechat_redirect)  
  
  
  
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
  
  
