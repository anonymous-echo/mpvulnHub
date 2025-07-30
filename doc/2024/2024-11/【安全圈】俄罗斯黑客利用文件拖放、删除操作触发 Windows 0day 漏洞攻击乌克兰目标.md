#  【安全圈】俄罗斯黑客利用文件拖放、删除操作触发 Windows 0day 漏洞攻击乌克兰目标   
 安全圈   2024-11-16 06:34  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
漏洞  
  
  
网络安全公司   
ClearSky  
 警告称，Windows 中一个新修补的  
day  
漏洞  
可通过用户最少的交互（例如删除文件或右键单击文件）被利用。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgH2Vr9Yiaclr72VvEAKak13ZIZNFszYmlxUWJxSuevtyViaKzDhNVSiaRzruCb8GfZN2kqvPp3L0ncg/640?wx_fmt=png&from=appmsg "")  
  
  
该0day漏洞编号为 CVE-2024-43451，是一个中等严重程度的漏洞，会影响 MSHTM 引擎，该引擎继续由 Internet Explorer 模式下的 Edge 和其他应用程序通过 WebBrowser 控件使用，从而使它们暴露于困扰该组件的任何安全缺陷。  
  
  
成功利用 CVE-2024-43451 允许威胁组织窃取受害者的 NTLMv2 哈希，然后通过执行传递哈希攻击使用它来作为目标用户进行身份验证。  
  
  
微软在 11 月 12 日的安全公告（https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43451）中指出：“用户与恶意文件进行最小程度的交互，例如选择（单击）、检查（右键单击）或执行除打开或执行之外的操作，都可能触发此漏洞。”  
  
  
ClearSky 发现了该漏洞并于 2024 年 6 月向微软报告，据该公司称，一些看似无害的操作可能会触发隐藏在 URL 文件中的漏洞，包括删除文件和将文件拖放到另一个文件夹。  
  
  
ClearSky 观察到 CVE-2024-43451 被疑似俄罗斯黑客在针对乌克兰实体的攻击中利用。  
  
  
受害者会收到来自受感染的乌克兰政府服务器的钓鱼电子邮件，提示他们更新学历证书。这些电子邮件将受害者引导至从政府官方网站下载的恶意 ZIP 文件。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgH2Vr9Yiaclr72VvEAKak13Um1oS0ydhouUJA3QsicOUMZ8Y0siazMcvwbq8GRqOUian2tGCwowyLNFg/640?wx_fmt=png&from=appmsg "")  
  
  
该档案包含两个文件——一个 PDF 文档和一个 URL 文件——针对两个已知漏洞，即 CVE-2023-320462 和 CVE-2023-360251。该 URL 指向外部服务器以获取两个可执行文件，也旨在利用新披露的0day漏洞。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgH2Vr9Yiaclr72VvEAKak130WTTHYeaXPDMVn7xRLnPibCqMRqTpwmhgnKcHaM7ewsoZkhnlnibwv6Q/640?wx_fmt=png&from=appmsg "")  
  
  
ClearSky 在一份技术报告中解释道：“当用户通过右键单击、删除或移动 URL 文件与它交互时，漏洞就会被触发。此操作会与攻击者的服务器建立连接并下载更多恶意文件，包括 SparkRAT 恶意软件。”  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgH2Vr9Yiaclr72VvEAKak13wqwSeM3HbwKQWT4C2TSxZMDKkvkSxRMGPphTCoticjertucoviciaMhfQ/640?wx_fmt=png&from=appmsg "")  
  
攻击链  
  
  
该网络安全公司表示，在 Windows 10 和 Windows 11 上，URL 文件在执行任何这些操作时都会立即与外部服务器建立通信。在 Windows 7、8 和 8.1 上，该漏洞仅在多次尝试后才会触发。  
  
  
ClearSky 表示，这表明“新发现的漏洞在 Windows 10/11 操作系统上更容易被利用”。  
  
  
乌克兰计算机应急响应小组 (CERT-UA) 称，CVE-2024-43451 已被追踪为 UAC-0194 的威胁组织利用为0day漏洞，该威胁组织疑似来自俄罗斯。据 ClearSky 称，攻击者使用了与其他团体常见的工具包和技术。  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】打补丁要快！0Day漏洞正在被黑客广泛利用](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652065974&idx=1&sn=d6789e893634a0f2fb9c34b2bfb0a8f9&chksm=f36e7cf6c419f5e0cf5388d52919823df63584452d66f1079566f5e2b4f9dbbebf6cd788ff74&scene=21#wechat_redirect)  
  
  
  
[【安全圈】朝鲜黑客创建经过安全验证的恶意软件攻击macOS系统](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652065974&idx=2&sn=010755f0a25a61fd86bd0766d523950f&chksm=f36e7cf6c419f5e0c46265072c96b8a08d4d6bbc94045690bcffab55bb5671a022709a21205e&scene=21#wechat_redirect)  
  
  
  
[【安全圈】黑客声称近5亿Instagram用户的数据被抓取](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652065974&idx=3&sn=8561949d0e269ce6c32fac5e2e36b663&chksm=f36e7cf6c419f5e04e3e14cf54a64911a3e530eb7482e1f6d1c3a65638b274b8547ce6234741&scene=21#wechat_redirect)  
  
  
  
[【安全圈】研究人员警告 AI 图像生成模型可能会泄露敏感指令](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652065974&idx=4&sn=22b17e04546da474a95971cd15506efa&chksm=f36e7cf6c419f5e09e31d108e4344afc1def30835bb8a778009442c8d7e9b125865f3ea81db1&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
  
  
  
  
