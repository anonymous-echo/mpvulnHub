#  【安全圈】OneDrive 文件选择器漏洞让应用程序获取用户整个云盘的访问权限   
 安全圈   2025-06-03 11:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylia3xNBMfqUNe7Xg81DGDeVcrFiax5Nx61TibCndG7ZbkXll0VF5VXgxoxo1L5UYAiaPHxrejibtKwibnHg/640?wx_fmt=png&from=appmsg "")  
  
近日，网络安全公司 Oasis Security 的研究人员披露了微软 OneDrive 文件选择器（File Picker）在权限管理上的一个重大疏漏：这一机制允许众多热门 Web 应用（包括 ChatGPT、Slack、Trello 和 ClickUp）在用户毫不知情的情况下，访问远超其授权范围的数据。  
### 问题出在 OAuth 权限范围设置不当  
  
报告指出，问题源自 OneDrive 文件选择器请求 OAuth 权限的方式。正常情况下，用户在上传或下载某个文件时，应该只授予相关应用对那个文件的访问权限，但目前的机制却赋予了应用**整个 OneDrive 云盘的读写权限**  
。这意味着，即使你只选择了一个文件上传，该应用也可能获取整个网盘的数据访问和修改能力，且这种访问权限可能长期保持有效。  
### 用户授权界面存在“误导”  
  
OAuth 是一种常用的授权标准，允许用户授权第三方应用访问其数据。但 Oasis 在其博客中指出，OneDrive 文件选择器缺乏“精细化”的 OAuth 范围控制（scope），让应用获得了远超所需的数据访问权限。  
  
更令人担忧的是，用户在授权时看到的提示界面并没有清晰说明这一点，通常会误以为只授权了所选文件的访问权，实际却是给了整个云盘的“万能钥匙”。  
  
相比之下，**Google Drive 和 Dropbox**  
 在类似集成方面的权限模型更加细致，允许用户只授予对特定文件夹或文件的访问，而不是整个账户。  
### 旧版本更存在严重安全隐患  
  
研究还发现，旧版本的 OneDrive 文件选择器（v6.0 至 v7.2）使用的是过时的认证流程，甚至会将敏感访问令牌（access token）暴露在浏览器的本地存储（localStorage）或 URL 中。  
  
即使是最新的 v8.0 版本，虽然采用了更现代的认证机制，但仍然会将访问令牌以**明文形式**  
保存在浏览器的 sessionStorage 中，若攻击者获取了本地访问权限，仍然可能被利用。  
### 影响范围可能数以亿计  
  
Oasis Security 估计，有数百款应用通过 OneDrive 文件选择器上传文件，潜在受影响用户数量巨大。例如，ChatGPT 允许用户直接从 OneDrive 上传文件，而其每月用户已超过 4 亿，因此实际受到过度授权影响的用户数量可能极其庞大。  
  
Oasis 在披露漏洞前已向微软及相关厂商发出通知。微软承认了该问题的存在，并表示未来**可能会改进**  
，但目前该系统依旧按“设计预期”运作。  
### 专家点评：这是一个严重的 API 安全挑战  
  
Salt Security 网络安全战略总监 Eric Schwake 表示：“Oasis Security 的研究指出了一个重大隐私风险。由于 OneDrive 文件选择器的 OAuth 权限设置过于宽泛，应用可以访问整个云盘，而不仅是选中的文件。”  
  
他还强调：“再加上访问令牌存储不安全，这就构成了严重的 API 安全挑战。随着越来越多的工具依赖 API 处理敏感数据，必须加强权限治理、限制访问范围，并保障令牌安全，才能避免数据暴露。”  
  
  
  
 END   
  
  
阅读推荐  
  
  
[【安全圈】退休后向境外间谍泄露国家秘密，冯某被判6年](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069966&idx=1&sn=b97e67cc3eddab98a5a87837f53269ff&scene=21#wechat_redirect)  
  
  
  
[【安全圈】首次承认！英国宣布将加强对中俄发动网络攻击](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069966&idx=2&sn=ef54fec478ff536068328ba1705de261&scene=21#wechat_redirect)  
  
  
  
[【安全圈】《使命召唤》防线失守：系列多款游戏被破解，黑客公开源代码](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069966&idx=3&sn=775670814fcfbf8e9a75d6875614d248&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
