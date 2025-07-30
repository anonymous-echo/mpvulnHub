#  弹出生成器WordPress插件漏洞利用   
THN  知机安全   2024-03-13 09:58  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QGibgZhUnjfNTO5FCVhdANkVLTBs9kaGEl5G6wrlFGZQxrorrET1c4t82MqnrBTXtKyjKgyWeGPWuOkZftjVlkg/640?wx_fmt=png "")  
  
A new malware campaign is leveraging a high-severity security flaw in the Popup Builder plugin for WordPress to inject malicious JavaScript code.  
  
一项新的恶意软件活动正在利用WordPress的Popup Builder插件中的一个严重安全漏洞，注入恶意JavaScript代码。  
  
According to Sucuri, the campaign has infected more than 3,900 sites over the past three weeks.  
  
根据Sucuri的说法，该活动在过去三周内已经感染了超过3900个网站。  
  
"These attacks are orchestrated from domains less than a month old, with registrations dating back to February 12th, 2024," security researcher Puja Srivastava said in a report dated March 7.  
  
安全研究员Puja Srivastava在3月7日的报告中称：“这些攻击是从不到一个月的域名发起的，注册日期可以追溯到2024年2月12日。”  
  
Infection sequences involve the exploitation of CVE-2023-6000, a security vulnerability in Popup Builder that could be exploited to create rogue admin users and install arbitrary plugins.  
  
感染序列涉及利用Popup Builder中的CVE-2023-6000漏洞，该漏洞可被利用创建恶意管理用户并安装任意插件。  
  
The shortcoming was exploited as part of a Balada Injector campaign earlier this January, compromising no less than 7,000 sites.  
  
这个短板在今年1月早些时候作为Balada Injector活动的一部分被利用，影响不少于7000个网站。  
  
The latest set of attacks lead to the injection of malicious code, which comes in two different variants and is designed to redirect site visitors to other sites such as phishing and scam pages.  
  
最新一轮攻击导致注入恶意代码，有两种不同的变体，旨在将站点访问者重定向到其他网站，如钓鱼和诈骗页面。  
  
WordPress site owners are recommended to keep their plugins up-to-date as well as scan their sites for any suspicious code or users, and perform appropriate cleanup.  
  
建议WordPress站点所有者保持其插件的最新状态，扫描其站点以查找任何可疑代码或用户，并进行适当的清理。  
  
"This new malware campaign serves as a stark reminder of the risks of not keeping your website software patched and up-to-date," Srivastava said.  
  
Srivastava表示：“这个新的恶意软件活动提醒人们要及时更新和维护网站软件的风险。”  
  
The development comes as WordPress security firm Wordfence disclosed a high-severity bug in another plugin known as Ultimate Member that can be weaponized to inject malicious web scripts.  
  
这一发展发生在WordPress安全公司Wordfence披露了另一个名为Ultimate Member的插件中的高危漏洞，可以被利用注入恶意网页脚本。  
  
The cross-site scripting (XSS) flaw, tracked as CVE-2024-2123 (CVSS score: 7.2), impacts all versions of the plugin, including and prior to 2.8.3. It has been patched in version 2.8.4, released on March 6, 2024.  
  
这个跨站脚本（XSS）漏洞被跟踪为CVE-2024-2123（CVSS评分：7.2），影响插件的所有版本，包括和之前的2.8.3版本。已在2024年3月6日发布了2.8.4版本进行了修补。  
  
The flaw stems from insufficient input sanitization and output escaping, thereby allowing unauthenticated attackers to inject arbitrary web scripts in pages that will be executed every time a user visits them.  
  
这个缺陷源于不足的输入清理和输出转义，从而允许未经身份验证的攻击者在页面中注入任意的网页脚本，每次用户访问时都会执行。  
  
"Combined with the fact that the vulnerability can be exploited by attackers with no privileges on a vulnerable site, this means that there is a high chance that unauthenticated attackers could gain administrative user access on sites running the vulnerable version of the plugin when successfully exploited," Wordfence said.  
  
Wordfence表示：“结合漏洞可以被没有特权的攻击者利用的事实，这意味着未经身份验证的攻击者成功利用时，有很高的可能性可以获得运行易受攻击版本插件的站点上的管理用户访问权限。”  
  
  
It's worth noting that the plugin maintainers addressed a similar flaw (CVE-2024-1071, CVSS score: 9.8) in version 2.8.3 released on February 19.  
  
值得注意的是，插件维护者在2月19日发布的2.8.3版本中解决了一个类似的漏洞（CVE-2024-1071，CVSS评分：9.8）。  
  
It also follows the discovery of an arbitrary file upload vulnerability in the Avada WordPress theme (CVE-2024-1468, CVSS score: 8.8) and possibly executes malicious code remotely. It has been resolved in version 7.11.5.  
  
在Avada WordPress主题中发现了一个任意文件上传漏洞（CVE-2024-1468，CVSS评分：8.8），可能远程执行恶意代码。已在版本7.11.5中解决。  
  
"This makes it possible for authenticated attackers, with contributor-level access and above, to upload arbitrary files on the affected site's server which may make remote code execution possible," Wordfence said.  
  
Wordfence表示：“这使得有权限的攻击者，具有贡献者级别的访问权限及以上，可以在受影响站点服务器上上传任意文件，从而可能实现远程代码执行。”  
  
**参考资料**  
  
[1]https://thehackernews.com/2024/03/malware-campaign-exploits-popup-builder.html  
  
**关注我们**  
  
        欢迎来到我们的公众号！我们专注于全球网络安全和精选双语资讯，为您带来最新的资讯和深入的分析。在这里，您可以了解世界各地的网络安全事件，同时通过我们的双语新闻，获取更多的行业知识。感谢您选择关注我们，我们将继续努力，为您带来有价值的内容。  
  
  
