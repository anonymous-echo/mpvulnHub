#  【安全圈】WordPress主题中的漏洞可能会导致网站被接管   
 安全圈   2022-07-17 19:00  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylh7xc6n7wCwImnVdc9ib4xcZC9NHXhaSPH1NGsSp13A9bp0agw1SUWw9EEyEQb1I12PCk9KGRs9Bqg/640?wx_fmt=jpeg "")  
  
  
**关键词**  
  
  
  
漏洞、网络攻击  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz/aBHpjnrGylh7xc6n7wCwImnVdc9ib4xcZoU8VHvTX7njaAsjQr956EhJzqY5s1GKISXOz5ujncZ5OzibSGQxtDRw/640?wx_fmt=other "")  
  
  
研究人员发现，在有超过 9 万个 WordPress 网站所使用的两个主题中发现了一个重要的权限升级漏洞，这些漏洞可以让威胁者完全接管这些网站。  
  
  
WordFence 威胁情报团队研究员 Ramuel Gall 发现了这个漏洞，他在周三发表的一篇博文中透露，这是他在 4 月初至 5 月初在 Jupiter 和 JupiterX 高级 WordPress 主题中发现的五个漏洞之一。  
  
  
其中一个漏洞被追踪为 CVE-2022-1654，在 CVSS 上被评为 9.9 级，即关键级，该漏洞允许任何经过验证的攻击者，包括任何用户或客户级攻击者，获得管理权限并完全接管任何运行 Jupiter 主题或 JupiterX 核心插件的网站，并且该插件是运行 JupiterX 主题所必需的。  
  
  
该主题受影响的版本是 Jupiter Theme 6.10.1 或更早，以及 JupiterX Core Plugin 2.0.7 或更早。  
  
  
WordFence 于 4 月 5 日完成了对大部分漏洞的调查，并在同一天向 Jupiter 和 JupiterX 主题开发商 ArtBees 报告了这些漏洞；5 月 3 日，他们向开发商通报了另外一个 Jupiter 主题漏洞。到 5 月 10 日，开发商发布了 Jupiter 和 JupiterX 主题的最新版本，修补了其中所有的漏洞。  
  
  
![](https://mmbiz.qpic.cn/mmbiz/aBHpjnrGylh7xc6n7wCwImnVdc9ib4xcZ6iaPALu97L6GRAbUx4icPI4nBOk4tr1JIR2yhls1ldo8VS7mILBSjvpw/640?wx_fmt=other "")  
  
****  
**严重的漏洞**  
  
  
研究员所发现的关键漏洞存在于一个名为 uninstallTemplate 的函数中，该函数可以卸载模板后重置一个网站。然而，它也具有将调用该函数的用户提升到管理员角色的功能，Jupiter 主题本身就具有该功能。同时在 JupiterX 中，它存在于 JupiterX 核心插件中。  
  
  
他写道，含有漏洞的版本会执行注册 AJAX 动作，但并不执行任何权限检查或 Nonce 检查。  
  
  
在安装了含有漏洞的 Jupiter Theme 版本的网站上，任何登录的用户都可以通过发送 AJAX 请求，将动作参数设置为 abb_uninstall_template，同时将自己的权限提升到管理员的权限。这将调用 uninstallTemplate 函数，该函数将调用 resetWordpressDatabase 函数，从而能够重新安装网站，使得当前登录的用户成为新网站的所有者。  
  
  
他说，在安装了含有漏洞的 JupiterX Core 插件的网站上，任何人都可以通过发送 AJAX 请求，将动作参数设置为 jupiterx_core_cp_uninstall_template，来进行其他恶意攻击。  
  
  
**其他的漏洞**  
  
  
WordPress 的插件，通常是由第三方开发者开发的，经常会不可避免的出现各种漏洞。以前这个流行的网站创建平台的插件中也曾经出现过很多漏洞使得网站可能被恶意接管，以及使攻击者能够彻底删除那些不属于他们的网站，或者攻击者能够伪造给用户发送电子邮件。  
  
  
在 Gall 发现的其他漏洞中，有三个被追踪为 CVE-2022-1656、CVE-2022-1658 和 CVE-2022-1659 被评为中等风险，另一个 CVE-2022-1657 则被评为高风险。  
  
  
高风险漏洞会影响到 JupiterX Theme 2.0.6 或更早版本和 Jupiter Theme 6.10.1 或更早版本，可以让攻击者获得网站的特权信息，如 nonce 值，或执行其他受限制的操作。这可以通过包含和执行网站上任何位置的文件来实现。  
  
Gall 解释说：" 含有漏洞的 Jupiter 和 JupiterX 主题允许登录的用户，包括订阅级别的用户进行路径遍历和本地文件包含 "。  
  
  
在 JupiterX 主题中，可以通过使用 lib/admin/control-panel/control-panel.php 文件中的 jupiterx_cp_load_pane_action AJAX 动作来调用 load_control_panel_pane 函数。攻击者有可能通过使用这个动作，使用 slug 参数包含本地任意的 PHP 文件。  
  
  
他说，Jupiter 主题也有一个几乎是相同的漏洞，攻击者可以通过 framework/admin/control-panel/logic/functions.php 文件中存在的 mka_cp_load_pane_action AJAX 动作，调用 mka_cp_load_pane_action 函数来利用这个漏洞。  
  
  
为保护 Wordfence Premium、Wordfence Care 和 Wordfence Response 客户，Wordfence 研究人员建议使用受影响主题的人立即更新到修补过的版本。  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylia5hic2rWpHUibLlRyX6uIzdRSjJwE3WrMzmE7uVG8mFB4ibWDgvcV3EEJnhAc9WZjepjvxwfmA60rAA/640?wx_fmt=png "")  
[【安全圈】甘肃回应“健康码系统访问异常”：升级维护，正在紧急修复](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652005978&idx=1&sn=59ef1a75ca3fa6d426444169cb84064a&chksm=f36f4a1ac418c30c084ed70e9a05bbb53cc7e96ec0ec18186e55f18405c89cf74309262d522c&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylia5hic2rWpHUibLlRyX6uIzdRIxnfJK58vrKiaknR8H8d42uLUYoktq3ox4TVklibryQWWyV9WLTSQvRA/640?wx_fmt=png "")  
[【安全圈】苍南男子破解赌博网站漏洞，每月“薅羊毛”10 多万元](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652005978&idx=2&sn=8dae9f471f869738d493f89bcb8b43c2&chksm=f36f4a1ac418c30c3bb6a19721674950992c26f9dc7f992488574fd4bc1609b26e01adbc4cc8&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylia5hic2rWpHUibLlRyX6uIzdRHnIjxsMav1P4ghS2xFn7rG4D8GSjIicQzBPQFWCp1RRzbvvgXOkNqbQ/640?wx_fmt=jpeg "")  
[【安全圈】这么自信？苹果打出千万元悬赏！只为寻求 iOS 16 锁定模式 Bug](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652005978&idx=3&sn=042e42b99f3886fc684c3d9738bad74b&chksm=f36f4a1ac418c30cdd0dbe610fdce30dda6a013c562422bb4197f4cfb24dff1ab371a5e56b62&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylia5hic2rWpHUibLlRyX6uIzdR4t1qMYALVyhMK9ZDwam3tneHibeEVew6h0aHaTgibSILwtYdbJax37aA/640?wx_fmt=png "")  
[【安全圈】DHS 首份网络安全审查委员会报告认为 Log4j 已成为待续性威胁](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652005978&idx=4&sn=cee45a6943ca4591c04bfc7ad86788b2&chksm=f36f4a1ac418c30cee92452712c53790719ae65d5d292d54ab435e9fe3d19dce7169f667f03c&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylia5hic2rWpHUibLlRyX6uIzdRia8X2H4z5Z2m3u2Kg19lDF0W7hiambsz5oomrgxrIHVvSLLVj6PEr4uA/640?wx_fmt=jpeg "")  
[【安全圈】遭勒索软件攻击，美190万条医疗记录被泄露](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652005978&idx=5&sn=fd6aa2eecfa2bb80b58a6508b2284d4f&chksm=f36f4a1ac418c30c0f6020b102ce009121697284e2450c37d1ff72030bbfc2a7e0bebd6c7b3d&scene=21#wechat_redirect)  
  
  
  
  
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
  
