#  【安全圈】Google Chrome 136 更新，修复 20 年前访问过的链接隐私漏洞   
 安全圈   2025-04-15 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliadicp21Asygag5qdjbGG2uQZ6nXuicgpdAR6giacsy0yRmjnFzomKjQRw1UXtcngs3vcHfyQeSZGx8g/640?wx_fmt=png&from=appmsg "")  
  
谷歌浏览器 136 版于 2025 年 4 月发布，引入了“访问链接分区”这一革命性功能，修复了困扰网络二十多年的隐私漏洞。  
  
作为第一个实施这一强大防御措施的主流浏览器，Chrome 可确保用户的浏览历史记录不被窥探，标志着网络安全的重大飞跃。  
## 消除历史检测漏洞  
  
自互联网早期以来，CSS :visited 选择器就使网站能够对点击的链接进行样式设置，通常将其变为紫色以增强导航。  
  
此功能虽然用户友好，但却存在漏洞，恶意网站可以检测：visited 样式来推断用户访问过哪些网站。  
  
例如，如果用户从站点 A 点击了站点 B 的链接，恶意 Site Evil 稍后可能会显示同一链接并利用其 :visited 状态来确认用户访问了站点 B。  
  
以前的浏览器缓解措施（例如限制样式选项）减缓了这些历史检测攻击，但未能根除它们。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliadicp21Asygag5qdjbGG2uQ7caZDKeUUKGM3Laic4u56yEXGrFWCjRicgxTpSUBHdCJxr7LKkvmAnIw/640?wx_fmt=png&from=appmsg "")  
  
Chrome 的 :visited 链接分区通过存储带有上下文详细信息（具体来说，链接 URL、顶级站点和框架来源）的链接历史记录正面解决了这一缺陷。  
  
现在，链接只会在被点击的网站上显示为 :visited，从而防止跨站泄漏。在同样的情况下，除非用户点击了 Site Evil 指向 Site B 的链接，否则该链接将保持无样式状态，从而使漏洞利用失效。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliadicp21Asygag5qdjbGG2uQUyHn2mb9JngF8lKmWmOZL34DsmGp53r57TBYMxc1VJZrhjHPYsoQTQ/640?wx_fmt=png&from=appmsg "")  
  
这种分区将访问历史记录从全局的、易受攻击的列表转换为安全的、特定于上下文的记录，以前所未有的精度保护用户的隐私。  
  
谷歌表示： “这是浏览器安全的决定性时刻。通过 :visited 链接分区，Chrome 消除了长期存在的隐私风险，同时保留了用户期望的无缝体验。我们致力于为每个人构建更安全的网络。”  
  
**在不损害安全性的情况下增强可用性**  
  
认识到直观导航的重要性，Chrome 引入了“自链接”功能，以平衡隐私和可用性。  
  
此功能允许网站将指向其子页面的链接样式设置为 :visited，即使这些链接是从其他上下文点击的。例如，在浏览 Site.Wiki 的黄金页面时，如果用户之前访问过其铬和黄铜页面，则指向这些页面的链接将显示为已访问，无论其来源网站是什么。  
  
由于网站已经可以跟踪自己的子页面，因此此例外不会泄露任何新信息，从而保留了分区的隐私保护。  
  
至关重要的是，这项豁免排除了第三方链接和iframe，确保不存在跨站追踪漏洞。这项周到的设计在维护严格的安全标准的同时，保留了网站内导航的便捷性。  
  
该修复程序现已在 Chrome Beta 频道中提供，并将于 2025 年 4 月 23 日在 Chrome 136 稳定版本中推出。鼓励用户通过 Chromium 错误跟踪器提供反馈或报告任何问题。  
  
通过重新定义浏览历史记录的处理方式，Chrome 不仅保留了访问过链接样式的实用性，还为所有人提供了更安全、更私密的网络体验。  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】一潜伏在我核心要害部位间谍落网](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069074&idx=1&sn=29646634be0f345eb7ca43459620ab07&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Medusa勒索软件声称攻击了NASCAR赛事，索要400万美元赎金](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069074&idx=2&sn=c05e68f57648b6835d077657988b50c9&scene=21#wechat_redirect)  
  
  
  
[【安全圈】研究员符某某因为境外非法提供情报罪被判刑！国安部披露细节：向外非法提供我国特有珍惜种质资源](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069074&idx=3&sn=1b49b72cf7aa5903377c9ceafc2686ae&scene=21#wechat_redirect)  
  
  
  
[【安全圈】GitHub 主动屏蔽中国大陆用户，部分港澳用户同样受影响](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069060&idx=1&sn=1633fcbcb48a0517419c5896f8d44571&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
