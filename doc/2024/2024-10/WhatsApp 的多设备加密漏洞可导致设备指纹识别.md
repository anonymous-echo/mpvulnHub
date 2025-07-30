#  WhatsApp 的多设备加密漏洞可导致设备指纹识别   
原创 很近也很远  网络研究观   2024-10-22 21:19  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yvLFKBRPQxPJUfg3D7xdxjcFMf9diaIBTLajSg4dDCjPSBuHZh4j0UEkRcR2HmZSwaYpibO3es8toRbtSHstjJuw/640?wx_fmt=png&from=appmsg "")  
  
WhatsApp 设备识别机制中存在重大隐私漏洞，攻击者可以利用该漏洞通过 WhatsApp 的端到端加密 (E2EE) 协议获取用户设备操作系统的指纹。  
  
安全研究员 Tal Be'ery 发现，这些漏洞会泄露用户设备信息，从而帮助攻击者进行侦察。  
  
隐私问题源于 WhatsApp 的多设备 E2EE 协议，该协议基于 Signal 的芝麻协议。  
  
在这种多设备设置中，发送者必须与接收者的每台设备建立安全会话。  
  
然而，这种设计也会无意中泄露有关接收者设备的详细信息，例如他们正在使用多少台设备、设备是移动设备还是台式机，以及每台设备的长期标识符。  
  
这些标识符允许对设备进行持续跟踪，即使用户在平台上屏蔽了另一台设备。  
  
虽然这些信息泄露本身就存在问题，但 Be'ery 的研究发现，攻击者还可以推断出更具体的细节，例如每台设备使用的操作系统。  
```
https://medium.com/@TalBeerySec/i-know-which-device-you-used-last-summer-fingerprinting-whatsapp-users-devices-71b21ac8dc70
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yvLFKBRPQxPJUfg3D7xdxjcFMf9diaIBT9mSRrhLGXKCz3xfiaptd4gQOiaEWXLThp5nJ2fMsthzzoiajCVIQyDHEQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yvLFKBRPQxPJUfg3D7xdxjcFMf9diaIBTr56mN7r5hMDbTqIskJleeBZge44kU1SsWul7RWfkuASTT1WbYy2xag/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yvLFKBRPQxPJUfg3D7xdxjcFMf9diaIBTdGcMicL6tYOUjPSIeHmo09dbqNuOzYVKIEqy2VaNcLFibGCUD0GVm4ibA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yvLFKBRPQxPJUfg3D7xdxjcFMf9diaIBTiasKh8ODCfvuz4Z3hxiakuHuoib5CkD4CiakIHlNymicMDVY54vIRFTLiaRA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yvLFKBRPQxPJUfg3D7xdxjcFMf9diaIBTauJk6HJlJia9p2KKLic4qMV4717KwYUTTwFzWMmPdgSFQ8txSibNU9BRw/640?wx_fmt=png&from=appmsg "")  
  
这为攻击者利用特定于操作系统的漏洞提供了更多针对性攻击的途径。  
  
例如，攻击者可以识别受害者使用的是 Android、iOS、Mac 还是 Windows 设备，并利用这些信息定制攻击，以漏洞最多的设备为目标。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/yvLFKBRPQxPJUfg3D7xdxjcFMf9diaIBTgYWR5z1HZrN528EdXVtOFXtH2OsSBNe4GpGHqhASICyCXeYflSgysw/640?wx_fmt=jpeg&from=appmsg "")  
  
WhatsApp 消息的结构  
  
WhatsApp 隶属于 Meta，在全球拥有超过 24 亿活跃用户，这些隐私问题可能会产生大规模影响。  
  
Be'ery 于今年早些时候首次发现这一问题，而他最近的发现表明，问题比最初想象的还要严重。  
  
通过检查“查看一次媒体”功能和消息 ID 结构等功能，Be'ery 能够改进他的分析，显示 WhatsApp 消息包含特定于操作系统的标识符。  
  
这意味着攻击者不仅可以确定设备类型，还可以确定所使用的操作系统，例如区分 Mac 和 iPhone 或 Android 和台式机。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/yvLFKBRPQxPJUfg3D7xdxjcFMf9diaIBTMcMWxvKoHFDD3xXBgPYKOAHQgOeicqDicPuFBXyD38FupD1vqZ08Pwhw/640?wx_fmt=jpeg&from=appmsg "")  
  
获取设备 ID  
  
这些漏洞的影响并不十分严重，但攻击者仍然可以利用它们作为复杂攻击链的一部分，以识别和利用受害者设备生态系统中最薄弱的环节。  
  
即使是非技术攻击者，例如从事国内间谍活动的个人，也可以利用这些数据泄露来深入了解受害者的设备设置。  
  
Be'ery 于 2024 年 9 月 17 日向 Meta 披露了该问题，但只收到了部分回复。  
  
Meta 的安全团队承认了该报告，但尚未发布全面修复。  
  
鉴于 WhatsApp 漏洞通过 WhatsApp Web 扩展等工具被广泛利用，Be'ery 决定在 Meta 沉默一个月后公布他的发现。  
  
研究人员认为，解决这个问题可能很简单，只需在各个平台上标准化消息 ID 生成以消除指纹识别向量即可。  
  
对于担心这些漏洞的用户，可以采取一些步骤来保护自己：  
- 请注意链接到您的 WhatsApp 帐户的设备数量，尤其是桌面客户端。  
  
  
- 如果可能的话，考虑限制使用 WhatsApp Web 或桌面应用程序。  
  
  
- 监控 WhatsApp 帐户上的任何异常活动，例如在您未使用的设备上标记为已读的消息。  
  
  
WhatsApp 对 Be'ery 的报告发表评论，一位发言人向我们发送了以下评论：  
  
“我们感谢研究人员的提交。我们仍然专注于保护我们的用户免受各种攻击，同时仍然确保我们能够顺利运行全球超过 20 亿人使用的服务。” – WhatsApp 发言人  
  
