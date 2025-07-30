#  安全公司曝光黑客利用 Office 已知漏洞散播 Remcos RAT 木马程序   
 信安网络技术   2024-11-18 00:36  
  
IT之家 11 月 15 日消息，安全公司 Fortinet 发布报告，称最近有黑客利用 5 年前公布的 CVE-2017-0199 漏洞，瞄准 Office 企业用户发动攻击。  
  
IT之家参考报告获悉，相关黑客首先发送一批伪造成公司业务往来信息的网络钓鱼邮件，其中带有含有木马的 Excel 附件。一旦收件人打开附件，就会看到相关文件受到保护，要求用户启用编辑功能才能查看内容，**在用户点击“启用编辑”按钮后，便会触发 CVE-2017-0199 远程代码执行漏洞**，之后受害者设备便会在后台自动下载运行黑客预备的 HTML 文件（HTA）。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/KGSIlMW3xHfjdbzxaBbOTWRDdpNhc4OLjbv7Jn6vgmGZJ8csfI3IrlibZysWia7BSfb64XKYH4deHj8gO3GIiaj1w/640?wx_fmt=jpeg&from=appmsg "安全公司曝光黑客利用 Office 已知漏洞散播 Remcos RAT 木马程序")  
  
安全公司曝光黑客利用 Office 已知漏洞散播 Remcos RAT 木马程序  
  
▲ 黑客制造的虚假邮件  
  
值得注意的是，这一 HTA 文件据称使用 JavaScript、VBScript 等脚本并结合 Base64 编码算法和 PowerShell 命令进行多层包装以避免被安全公司发现。一旦 HTA 文件被启动，它会将黑客预备的 dllhost.exe 下载到受害者设备上运行，而后相关 exe 文件会将恶意代码注入到一个新的进程 Vaccinerende.exe 中，从而传播 Remcos RAT 木马。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/KGSIlMW3xHfjdbzxaBbOTWRDdpNhc4OLfric2uHfIia96OmCIh43cQLpic7FgmxmcTFUJPniaYTRAIiccia0MbReRgnA/640?wx_fmt=jpeg&from=appmsg "安全公司曝光黑客利用 Office 已知漏洞散播 Remcos RAT 木马程序")  
  
▲ 黑客的 HTA 文件采用多重包装以防止遭到安全公司分析  
  
研究人员指出，黑客为隐藏其踪迹利用了多种反追踪技术，包括“异常处理”、“动态 API 调用”等手段，以达到规避检测的目的。就此，安全公司提醒企业及用户个人应及时更新 Office 软件，降低被黑客攻击的风险。  
  
  
