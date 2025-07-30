#  【安全圈】适用于macOS的多个微软应用程序发现库注入漏洞，用户数据安全受威胁   
 安全圈   2024-08-21 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
根据 Cisco Talos 的最新研究，macOS 上的八个微软应用程序容易受到库注入攻击，有可能让攻击者劫持应用程序的权限并泄露敏感数据。  
  
受影响的微软应用程序包括 Microsoft Teams、Outlook、PowerPoint 和 Word 等流行服务，共有八个 CVE 编号。  
- Microsoft Outlook: CVE-2024-42220  
  
- Microsoft Teams (work or school): CVE-2024-42004  
  
- Microsoft PowerPoint: CVE-2024-39804  
  
- Microsoft OneNote: CVE-2024-41159  
  
- Microsoft Excel: CVE-2024-43106  
  
- Microsoft Word: CVE-2024-41165  
  
- Microsoft Teams (work or school) WebView.app helper app: CVE-2024-41145  
  
- Microsoft Teams (work or school) com.microsoft.teams2.modulehost.app: CVE-2024-41138  
  
攻击者通过使用现有的应用程序权限而不提示用户进行任何额外验证来绕过 macOS 的权限模型，这样，就可以在用户未察觉的情况下从用户账户发送电子邮件、录制音频片段、拍照或录制视频，而无需与用户进行任何交互。  
## macOS 的许可模式受到审查  
  
Cisco Talos 强调了 macOS 基于用户同意的权限模型，该模型包含旨在保护用户隐私和维护系统安全的功能。但研究发现，macOS 对应用程序的权限管理过于信任，允许它们自我监管，这一缺陷可能使攻击者得以利用应用程序的高级权限。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylj5hj5DtRdEYYukSeuf9l0hLzIMdSFjMBKiadKBBoWuuofqLTaicicZ5JX28gtejsYDicdkw2ffVCdqRA/640?wx_fmt=jpeg&from=appmsg "")  
更令人担忧的是，八款流行的微软  macOS 应用程序都激活了禁用库验证的权限“com.apple.security.cs.disable-library-validation ”。  
  
据苹果公司称，该权限允许加载由第三方开发者签名的插件，旨在增强应用程序的功能性。但这一机制存在安全隐患，攻击者可能利用这一点注入任意库，并在被攻击的应用程序中运行恶意代码，进而完全控制应用程序的权限和功能。  
  
研究人员还观察到，macOS 上的所有 Microsoft Office 应用程序都允许加载未签名的动态库。如果要修改已经执行过一次的应用程序，需要特定的权限。不过，攻击者可以通过将应用程序复制到如 /tmp 等其他文件夹来绕过这一安全措施，但这也增加了数据泄露和系统被攻击的风险。  
  
研究人员指出，由于存在相对导入和禁用库验证的权限，所有 Microsoft Office 应用程序都容易受到库注入攻击。  
## 微软用户面临不必要的风险  
  
Cisco Talos 的研究人员说，他们的发现让人们对禁用库验证的必要性产生了疑问，尤其是应用程序不打算加载其他库的情况下。微软通过使用特定权限绕开了 macOS 的加固安全措施，这可能使用户面临原本不必要的风险。  
  
在 Cisco Talos 报告漏洞后，微软虽然认为发现的问题风险较低，但已经对其中的四款应用程序进行了更新，移除了 com.apple.security.cs.disable-library-validation 权限，这意味着它们不再容易受到已知库注入攻击的威胁。  
  
这四款应用程序是 Microsoft Teams 的主应用程序、WebView 应用程序和 ModuleHost 应用程序，以及 Microsoft OneNote。不过，截至 2024 年 8 月 19 日，Microsoft Excel、Outlook、PowerPoint 和 Word 仍然存在漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylj5hj5DtRdEYYukSeuf9l0hxD0rccibRrnXkVwpL9CcdGeyuhX02Av67V0ANeZia5URhPgIJXjSakvg/640?wx_fmt=jpeg&from=appmsg "")  
  
检查 macOS 应用程序是否易受库注入攻击影响的流程图  来源：Cisco Talos  
  
研究人员建议，macOS 可以引入用户提示来降低这一风险。这将允许用户决定是否加载特定的第三方插件，从而提供一种更可控的访问授权方式。  
  
参考来源：https://www.infosecuritymagazine.com/news/microsoft-apps-macos-exposed/  
  
  
END  
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliax3htCKf6qvK3OibcOTibqNTUzn8XeNB95FhFuOVgfcNdOr9eDWPqCN9JHnwTXS3qB3733AvrqHdxw/640?wx_fmt=jpeg "")  
[【安全圈】紧急！WPS被曝出现两个严重漏洞：且已被利用](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063733&idx=1&sn=04dd13bf3a0e027fb707f063fa89ffbf&chksm=f36e6bb5c419e2a399b928d676f3db243488855358d520c5a9617dc0e258679995acfe13a05d&scene=21#wechat_redirect)  
  
  
  
  
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
  
