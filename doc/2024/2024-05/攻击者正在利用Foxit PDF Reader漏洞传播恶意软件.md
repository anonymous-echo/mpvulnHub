#  攻击者正在利用Foxit PDF Reader漏洞传播恶意软件   
安全客  安全客   2024-05-16 16:38  
  
        
Check Point Research 发现 PDF 漏洞正在广泛传播，主要针对 Foxit Reader 用户。通过触发安全警告，毫无戒心的用户可能会被欺骗执行有害命令。  
  
许多攻击者已经在利用该漏洞，该漏洞利用了“福昕阅读器（Foxit Reader）中警告消息的设计缺陷”。  
  
尽管 Adobe Acrobat Reader 在市场上占据主导地位，但 Foxit Reader 已成为重要的参与者，在全球拥有超过 7 亿用户，其中包括政府和技术领域的主要客户。  
  
当用户打开已更改的 PDF 文件时，该漏洞会触发安全警告。如果粗心的用户两次使用默认选项（这是最有害的），该漏洞就会从远程服务器下载并执行有效负载。  
  
研究人员表示：“感染成功且检测率低，使得恶意 PDF 可以通过许多非传统方式（例如 Facebook）进行传播，而不会被任何检测规则阻止。”  
  
受害者场景如下所示：打开文件时，我们遇到第一个弹出窗口，默认选项‘信任一次’，这是正确的方法。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb494deKcm2OFy8hOL1PseaiarMiaI2Xyx4Fnn2ld8Zn4qXcLc7b2kyq7KHEQkUrwrLVuaYga4pJxehw/640?wx_fmt=png&from=appmsg "")  
  
        
“一旦点击‘确定’，目标就会出现第二个弹出窗口。如果目标用户有机会阅读第一条消息，则第二条消息将在不阅读的情况下“同意”。在这种情况下，威胁行为者正在利用这种有缺陷的逻辑和常见的人类行为，这提供了最“有害”的默认选择。”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb494deKcm2OFy8hOL1PseaiapPgYB6tfia21I7fOcZk7ItiawmLoApq2aLInrPLZ9xfRMYQ4dUMubHBg/640?wx_fmt=png&from=appmsg "")  
  
默认选项触发恶意命令  
  
该漏洞的用途广泛，从间谍活动到具有多个链接和工具的电子犯罪，可实现令人印象深刻的攻击链。  
  
在一个实例中，标记为 APT-C-35 / DoNot Team 的攻击者获得了针对 Windows 和 Android 设备执行混合活动的能力，“这也导致了双因素身份验证 (2FA) 被绕过”。  
  
研究人员表示：“各种网络犯罪行为者也利用了这一漏洞，传播最著名的恶意软件系列，例如 VenomRAT、Agent-Tesla、Remcos、NjRAT、NanoCore RAT、Pony、Xworm、AsyncRAT、DCRat。”  
  
在一次恶意活动中，Check Point 跟踪了通过 Facebook 分发的链接，这导致了很长的攻击链，系统被安装了一个信息窃取木马和两个加密货币挖矿木马。  
  
另一项活动是由黑客组织 @silentkillertv 发起的，他利用了两个链接的 PDF 文件，其中一个托管在合法网站 trello.com 上。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb494deKcm2OFy8hOL1PseaiaxeZnJ6fsAL70MTgS0zpRqWMsnCMQeduuR0ocCR4nT3LyRyiaz35d6Zg/640?wx_fmt=png&from=appmsg "")  
  
复杂的攻击链  
  
“Check Point 获得了攻击者拥有的多个构建器，这些构建器利用此漏洞创建恶意 PDF 文件。收集到的大多数 PDF 都在执行 PowerShell 命令，该命令从远程服务器下载有效负载然后执行，尽管在某些情况下使用了其他命令。”报告中写道。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb494deKcm2OFy8hOL1PseaiarTNQyYa5Etw3VJrJgsWe0wpC1sIQzZhotCDuHAENOZA0BicQxcdEsTw/640?wx_fmt=png&from=appmsg "")  
  
PDF 命令执行分析  
  
研究人员将此 PDF 漏洞归类为针对 Foxit PDF Reader 用户的网络钓鱼或社会工程形式，而不是典型的恶意活动。攻击者需要诱骗用户习惯性地单击“确定”，而不了解所涉及的潜在风险。  
  
Foxit Reader承认了该问题，并向Check Point表示将在2024 3版本中解决该问题。安全专家建议用户在打开未知来源的PDF文件时注意并谨慎行事。  
  
详细技术报告：  
  
https://blog.checkpoint.com/research/foxit-pdf-reader-flawed-design-hidden-dangers-lurking-in-common-tools/  
  
https://research.checkpoint.com/2024/foxit-pdf-flawed-design-exploitation/  
  
**参考链接：**  
https://cybernews.com/news/foxit-pdf-reader-exploit/  
  
  
**来**  
  
**领**  
  
**资**  
  
**料**  
  
**【免费领】**  
**网络安全专业入门与进阶学习资料，轻松掌握网络安全技能！**  
  
****![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb4N2VUg5icoU6eUKJ14GUznZiaB5GRRWfKMn3k9mc03BRO6zB0LoPzN4UFb1vIKXwibvsEkPLy6ozj8Q/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
