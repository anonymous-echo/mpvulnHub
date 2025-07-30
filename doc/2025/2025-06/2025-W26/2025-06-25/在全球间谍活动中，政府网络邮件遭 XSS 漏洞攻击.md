> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3ODY0NTczMA==&mid=2247493041&idx=1&sn=518361ee24bc2da2bdc44f947e1046a8

#  在全球间谍活动中，政府网络邮件遭 XSS 漏洞攻击  
Rhinoer  犀牛安全   2025-06-25 15:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBlkqb2UwXDnXb0MYfKajE4r3fpITcJp5MjZiata25eWBOs9ROdsqbCyoeFdMJHIpQWibZnzHajAL5hg/640?wx_fmt=png&from=appmsg "")  
  
黑客正在开展一项代号为“RoundPress”的全球网络间谍活动，利用网络邮件服务器中的零日漏洞和 n 日漏洞窃取高价值政府组织的电子邮件。  
  
发现此次行动的ESET 研究人员认为，该行动是俄罗斯政府支持的黑客APT28（又名“Fancy Bear”或“Sednit”）所为，且有一定把握。  
  
该活动于 2023 年启动，并于 2024 年继续采用新的漏洞利用，目标是 Roundcube、Horde、MDaemon 和 Zimbra。  
  
值得注意的目标包括希腊、乌克兰、塞尔维亚和喀麦隆的政府、乌克兰和厄瓜多尔的军事单位、乌克兰、保加利亚和罗马尼亚的国防公司以及乌克兰和保加利亚的关键基础设施。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBlkqb2UwXDnXb0MYfKajE4rATxQ6VCWrM7e8JVu9TG47LY6LHzlPibluSicjdEV0ZMw0h9pPzDwzuAA/640?wx_fmt=png&from=appmsg "")  
  
打开电子邮件，数据被盗  
  
攻击始于一封引用当前新闻或政治事件的鱼叉式网络钓鱼电子邮件，通常包括新闻文章摘录以增加合法性。  
  
电子邮件 HTML 正文中嵌入的恶意 JavaScript 负载会触发收件人使用的 Web 邮件浏览器页面中的跨站点脚本 (XSS) 漏洞的利用。  
  
受害者只需打开电子邮件即可查看，因为恶意 JavaScript 脚本的执行不需要其他交互/点击、重定向或数据输入。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBlkqb2UwXDnXb0MYfKajE4refBqmmZRRwUK0laURp6w9J6VwoMbXnvG279k5mlGybUEwUgY8woR2A/640?wx_fmt=png&from=appmsg "")  
  
该有效载荷没有持久机制，因此仅在打开恶意电子邮件时执行。  
  
该脚本创建不可见的输入字段来诱骗浏览器或密码管理器自动填充受害者电子邮件帐户的存储凭据。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBlkqb2UwXDnXb0MYfKajE4rKDZx19A52ylb6fvCC3NTQgEicOAfv7Dw9h7gKKJGIgxv6lVxtKpqd4A/640?wx_fmt=png&from=appmsg "")  
  
此外，它还读取 DOM 或发送 HTTP 请求来收集电子邮件消息内容、联系人、网络邮件设置、登录历史记录、双因素身份验证和密码。  
  
然后使用 HTTP POST 请求将数据泄露到硬编码的命令和控制 (C2) 地址。  
  
每个脚本都有一组略有不同的功能，根据其目标产品进行调整。  
  
漏洞目标  
  
RoundPress 行动针对的是重要组织通常用来注入恶意 JS 脚本的各种网络邮件产品中的多个 XSS 漏洞。  
  
与此活动相关的 ESET 漏洞利用涉及以下缺陷：  
- Roundcube - CVE-2020-35730：黑客于 2023 年利用的一个存储型 XSS 漏洞，将 JavaScript 直接嵌入电子邮件正文中。当受害者在基于浏览器的 Web 邮件会话中打开电子邮件时，该脚本会在其上下文中执行，从而窃取凭证和数据。  
  
- Roundcube - CVE-2023-43770：Roundcube 处理超链接文本时存在 XSS 漏洞，该漏洞于 2024 年初被利用。不当的清理导致攻击者将 <script> 标签注入电子邮件内容，并在用户查看时执行。  
  
- MDaemon - CVE-2024-11182：MDaemon 电子邮件服务器 HTML 解析器中的一个零日 XSS 漏洞，于 2024 年末被黑客利用。攻击者通过构造带有 noembed 标签的畸形 title 属性，可以渲染隐藏的 <img onerror> 负载并执行 JavaScript 代码。这会导致凭证窃取、双因素身份验证 (2FA) 绕过以及通过应用密码实现持久访问。  
  
- Horde – 未知 XSS：APT28 试图通过在 <img onerror> 处理程序中放置脚本来利用 Horde 中一个旧的 XSS 漏洞。然而，此次尝试失败了，可能是由于现代 Horde 版本中的内置过滤功能。具体漏洞尚未确认，但目前似乎已得到修补。  
  
- Zimbra - CVE-2024-27443：Zimbra 日历邀请处理中存在一个 XSS 漏洞，此前该漏洞未被标记为主动利用漏洞。X-Zimbra-Calendar-Intended-For 标头中未经过滤的输入允许 JavaScript 代码注入日历界面。APT28 嵌入了一个隐藏脚本，该脚本会在用户查看邀请时解码并执行 base64 JavaScript 代码。  
  
  
尽管 ESET 没有报告 2025 年的任何 RoundPress 活动，但黑客的方法也很容易应用于今年，因为流行的网络邮件产品中不断出现新的 XSS 漏洞。  
  
  
信息来源：B  
leepingComputer  
  
