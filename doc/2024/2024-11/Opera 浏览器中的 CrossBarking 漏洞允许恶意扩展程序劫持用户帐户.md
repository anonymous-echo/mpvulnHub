#  Opera 浏览器中的 CrossBarking 漏洞允许恶意扩展程序劫持用户帐户   
原创 星空浪子  星空网络安全   2024-11-04 22:14  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/n4Jw29uPBick4md1DhZVzMu5N2en3UhUadEOJsTHARiaeQYjWNO9tZYQqN65TTTosqGG2GGDTMKVKhBKXAHIIJ3w/640?wx_fmt=other&from=appmsg "")  
  
Chrome 商店中的 Puppy 主题扩展程序跨越 Opera 界限并利用了 0-Day 漏洞 | 图片来源：Guardio Labs  
  
  
  
  
Guardio Labs 发现了 Opera 浏览器的一个严重安全漏洞，称为“CrossBarking”，该漏洞允许恶意扩展绕过安全协议并利用私有 API。此漏洞使攻击者能够捕获屏幕、更改浏览器设置，甚至劫持用户帐户。由 Guardio Labs 负责人 Nati Tal 领导的研究发现揭示了对用户的严重威胁，并强调了现代浏览器中用户生产力与安全性之间日益加剧的紧张关系。  
  
Guardio Labs 在其报告中解释了浏览器（尤其是基于 Chromium 的浏览器，如 Opera）如何集成私有 API 来增强用户体验。这些 API 通过授予特定功能（如 Opera 的 Pinboard 和 Wallet 服务）对浏览器功能的特权访问权，促进了这些功能的实现。Nati Tal  
指出  
，“现代网站的功能就像功能齐全的应用程序一样  
……您的浏览环境必须完全沙盒化  
——与系统的其余部分隔离”。然而，这些本应被安全控制的私有 API 却因域访问过于宽松而遭到利用。  
  
为了展示该漏洞的影响，Guardio Labs 的研究人员开发了一个概念验证扩展程序，该扩展程序以可爱的小狗图像为特色——一个看似无害的附加组件，却隐藏了恶意功能。根据报告，“我们所需要的只是打开一个标签页，进入  
[允许的]域  
下的页面，注入我们特制的代码  
，然后调用 chrome.settingsPrivate.setPref()  
 ”。此漏洞在用户不知情的情况下更改了用户的 DNS 设置，为网络钓鱼攻击等铺平了道路。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/n4Jw29uPBick4md1DhZVzMu5N2en3UhUaocTFUWFpNVDSiaQd1SPU9ZDNzGPTYEICBa0xuY1G2AVUibtsD5o6MniaQ/640?wx_fmt=other&from=appmsg "")  
  
该漏洞如何改变 HTTPs 上的 DNS 设置 | 图片来源：Guardio Labs  
  
虽然 Opera 的扩展程序审核非常严格，但它也允许用户安装 Chrome 扩展程序，从而绕过 Opera 的审核流程。Guardio 团队透露，“为了说明绕过扩展程序商店安全措施是多么容易  
……我们能够将利用私有 API 的恶意 Opera 扩展程序藏匿在官方 Chrome 商店中  
”。鉴于 Chrome 商店的广泛影响力，这一跨商店漏洞凸显了对数百万用户的潜在威胁。  
  
收到警报后，Opera 与 Guardio Labs 合作实施了修复。Opera 强调，“这凸显了健全审核流程的重要性  
……以及扩展程序所能发挥的强大作用  
”。由于 Guardio 的主动报告，该漏洞于 9 月 24 日得到修补，确保没有用户成为攻击的受害者。  
  
  
希望这些信息对您有所帮助！如果觉得这篇文章有价值，  
**欢迎点赞、分享、再看、转载**  
**，**如果您有网络安全的疑问，联系我随时为您解答，感谢您的支持！  
  
