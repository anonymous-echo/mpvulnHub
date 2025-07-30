#  【安全圈】WordPress爆高危漏洞插件！可被用来创建非法管理员帐户   
 安全圈   2023-07-03 19:01  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgSxa9I02IBd3bgLEhwfJCeRibw3LEjMujeAhD2CvyiaVCZJVHGHODbkPx3pViaX0sAibZsDun6sicUzdQ/640?wx_fmt=jpeg "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylglA4T7xugjRfD3Bic9mV8VAKzlpLBnIOhn42giaic1NEV6GzDduL0rCnaSy0YQatJLh4hrDeibtFprIA/640?wx_fmt=jpeg "")  
  
WordPress网站的终极会员插件中有多达20万个未修补的关键安全漏洞，如今面临着很高的攻击风险。  
  
该漏洞被追踪为CVE-2023-3460 (CVSS得分：9.8)，影响所有版本的Ultimate Member插件，包括2023年6月29日发布的最新版本(2.6.6)。  
  
Ultimate Member是一个比较受欢迎的插件，它有助于在WordPress网站上创建用户配置文件和社区，并可提供帐户管理功能。  
  
WordPress安全公司WPScan在警报中提到，这是一个非常严重的问题，因为未经身份验证的攻击者可能会利用这个漏洞创建具有管理权限的新用户帐户，从而实现夺取网站的完全控制权。  
  
但该漏洞源于不适当的阻止列表逻辑，所以无法将新用户的wp_capabilities用户元值更改为管理员的用户元值，从而获得对站点的完全访问权。  
  
Wordfence研究员Chloe Chamberland称，虽然该插件有一个预先定义的禁用键列表。但还有一些更简单的方法可以绕过过滤器，例如在插件的易受攻击版本中利用各种大小写，斜杠和提供的元键值中的字符编码。  
  
有报道称，受影响的网站上出现了一些非法管理员账户，因此该插件在2.6.4、2.6.5和2.6.6版本发布了部分修复程序，还有一个新的版本更新预计将在未来几天发布。  
  
WPScan指出，这些补丁是不完整的，已经发现了许多绕过它们的方法，这意味着该漏洞仍然可以被积极利用，比如，该漏洞被用于以apadmins、se_野蛮、segs_野蛮、wpadmins、wpengine_backup和wpenginer等名称注册新帐户，通过网站的管理面板上传恶意插件和主题。  
  
此外WPScan还建议广大用户，直到该安全漏洞被完全修复前，都建议Ultimate Member的用户禁用该插件，最好审计网站上的所有管理员级用户，以确定是否添加了未经授权的帐户。  
## 终极会员2.6.7版发布  
  
7月1日，Ultimate Member的作者发布了该插件的2.6.7版本，以解决被积极利用的特权升级漏洞。作为一项额外的安全措施，他们还计划在插件中发布一个新功能，使网站管理员能够重置所有用户的密码。  
  
此外， 网站维护人员还表示：2.6.7引入了我们在发送表单时存储的元键白名单，并且分离了表单设置数据和提交数据，可在两个不同的变量中操作它们。  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylglA4T7xugjRfD3Bic9mV8VA4Wx2yW1zvWd24klTAN5nd5AOIRceKG7yXW07B40LdBxGL5QxuQ2fMw/640?wx_fmt=png "")  
[【安全圈】用户账户信息遭泄露！WordPress 社交登录插件曝出漏洞](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652038343&idx=1&sn=f0f908f052f9183d2cd720a5688663ef&chksm=f36fc887c4184191960ee25208e9ac774f30981ca3ec187af83f622376a5fe0e34ed1c893cbd&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylglA4T7xugjRfD3Bic9mV8VAApJLXJMonCBZ4NfSjnicgTxA6hd4icpNCAotEeumAaWIs4tREATwyLtw/640?wx_fmt=png "")  
[【安全圈】生成的照片连AI鉴别器都看不出来，AI被自己骗了！](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652038343&idx=2&sn=6d254368e4c4b7b7ee94ac58c1f26d1b&chksm=f36fc887c4184191769b11e9107b51c9acb4bc42875eddb67ff27c592f534cd71b71004f0607&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylglA4T7xugjRfD3Bic9mV8VA804bsBNc3MvEQOADrp6PwBbz1waqpFtcdeEvrj8yeS7MxKWwWpXUXQ/640?wx_fmt=jpeg "")  
[【安全圈】为以确保其广告收入，YouTube正测试屏蔽用户的“广告拦截器”](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652038343&idx=3&sn=665332e66f1eb899387fb91a6119025d&chksm=f36fc887c4184191b08c71b59074549ff35d6377554028ae1598fbfdcb032859c82c71557701&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylglA4T7xugjRfD3Bic9mV8VASvtEOFwbzwLHknibljZ5k2lZic9WGwW65dbsU0x2AticFfaZ9Y8uNEreA/640?wx_fmt=png "")  
[【安全圈】网信办：开展“清朗·2023年暑期未成年人网络环境整治”专项行动的通知](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652038343&idx=4&sn=0fc566d4fd6ae66224cc3674c11944eb&chksm=f36fc887c41841917ab5c742bbd0b538e15c6b335ed483d0d038ab3564c0c618d24a169503f7&scene=21#wechat_redirect)  
  
  
  
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
  
  
