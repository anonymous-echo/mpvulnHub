#  Telegram 修复Windows 版中的0day漏洞   
Lawrence Abrams  代码卫士   2024-04-15 17:47  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**Telegram 修复了位于 Windows 桌面应用中的一个 0day 漏洞，它可**  
  
**被用于绕过安全提醒并自动启动 Python 脚本。**  
  
  
  
几天前，就曾有人在X和黑客论坛上提到 Windows 版本的 Telegram 上存在一个远程代码执行漏洞。虽然有些帖子表示该漏洞是一个零点击漏洞，不过演示视频显示有人试图启动 Windows 计算器。Telegram 迅速平息了这些言论，指出他们“无法证实该漏洞存在”，该视频可能是一场欺骗。  
  
然而，第二天，XSS黑客论坛上出现了一个相关的 PoC 利用解释称，Telegram 的 Windows 版本源代码中存在一个拼写错误，可被用于发送 Python .pyzw 文件，被点击时会绕过安全提醒。Python 会自动执行该文件，且不会收到 Telegram 对其它可执行文件做的那样的提醒，而如果该文件中不存在拼写错误则可能会收到类似提醒。  
  
更糟糕的是，该PoC 利用将该 Python 文件伪装成一个共享视频，同时会配有缩略图，诱骗用户点击虚假视频并观看。Telegram 表示，该漏洞虽然是一个零点击漏洞，但他们已在 Windows 版本中修复了该问题，阻止 Python 脚本被点击时自动启动。该修复方案是一个服务器端修复方案。  
  
Telegram 解释称，“在 Telegram 桌面上，存在一个问题可导致用户在将 Python 解释器安装到计算机时点击恶意文件。和之前的报道不同，它并非零点击漏洞，仅影响少量用户：不到0.01%的用户安装了 Python 并使用 Telegram 桌面版相关版本。已应用服务器端修复方案，确保该问题不会再复现，因此所有 Telegram 桌面版（包括老旧版本）均不再有这个问题。”  
  
BleepingComputer 询问 Telegram 如何了解到用户的 Windows 设备上安装了哪些软件，因为这类数据并未在他们的隐私策略中提到。目前暂未收到回复。  
  
  
**Telegram 漏洞**  
  
  
该 Telegram 桌面客户端在追踪与风险文件相关联的文件扩展，如可执行的文件。如果有人将其中一种文件类型发送到 Telegram，用户点击了该文件，则Telegram 不会自动在相关程序中启动它，而是会首先给出如下安全提醒：“该文件的扩展是 .exe。它可能会损害您的计算机。您确信想要运行它？”  
  
然而，在Telegram中分享的未知文件类型会自动在 Windows 中启动，让操作系统决定使用什么程序。安装了 Windows 版本的 python 后，它会将 .pyzw 文件扩展和 Python 可执行文件关联，导致文件被双击后，脚本被自动执行。  
  
.pyzw 扩展用于 Python zipapps，即ZIP压缩文件中包含的自包含 Python 程序。Telegram 开发人员发现这些可执行文档类型应当被视作是具有风险的并将其纳入可执行文件扩展中。遗憾的是，当他们添加该扩展时犯了一个拼写错误，将扩展输入为 “pywz” 而不是”pyzw”。因此，当这些文件通过 Telegram 发送并被点击后，如果Windows 设备上安装了 Python，则会被 Python 自动启动。  
  
这就导致攻击者绕过安全提醒并诱骗用户打开文件，在目标 Windows 设备上远程执行代码。为了伪装该文件，研究人员使用一个 Telegram 机器人通过 “video/mp4” 的媒体类型发送该文件，导致 Telegram 将该文件以共享视频的方式显示。如果用户点击该视频并观看，该脚本就会通过Windows 版本的 Python 启动。  
  
BleepingComputer 与网络安全研究员 AabyssZG共同测试了该利用。他们使用老旧版本的 Telegram 接收了 mp4 视频格式的 video.pywz 文件。该文件中包含 Python 代码，可打开命令提示符。然而，当点击视频并观看后，Python 会自动执行该脚本。  
  
研究人员在4月10日将该漏洞报送给 Telegram，后者修改 “data_document_resolver.cpp” 源代码文件中该扩展的拼写，修复了这个漏洞。然而，该修复方案似乎尚未上线，因为点击该文件时，并未出现安全提醒。Telegram 使用了服务器端修复方案，将.untrusted 扩展作为 pyzw文件的后缀。当点击该文件时，Windows 会询问你希望使用哪个程序打开这些文件，而不是自动在 Python 中启动。  
  
Telegram Desktop app的后续版本应该会包含安全提醒，而不仅仅是添加 “.untrusted” 扩展，从而提高该流程的安全性。  
  
  
****  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Telegram 和 AWS等电商平台用户遭供应链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517920&idx=2&sn=9b81bba53ca92b9dba48012df9a9d2cb&chksm=ea94b78adde33e9c5b9a7a2184d0c433e97efba3d73c58471d585199cd6d4d88409f7bd57770&scene=21#wechat_redirect)  
  
  
[如何操纵通过 WhatsApp 和 Telegram 发送的媒体文件？](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247490428&idx=1&sn=c3612b2a032e14373c9548f49a544810&chksm=ea972a16dde0a30026e0ea810c67a930b83d880f96cfb86f0e7030846cbd4e0747da0d5b77cc&scene=21#wechat_redirect)  
  
  
[Telegram 通讯服务遭受大规模 DDoS 攻击，影响全球用户](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247490187&idx=3&sn=b810db8ffd735c04f3a5f8dbd2ccbfb2&chksm=ea972be1dde0a2f7fdff562393cd33a88b22d32df7db52201dc00468c3a221ca8addfe4c049a&scene=21#wechat_redirect)  
  
  
[用 Telegram 拨打电话？小心 IP 地址遭泄漏](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247488180&idx=2&sn=0a7dc6f09ee20985436f6913fa86dbd5&chksm=ea9723dedde0aac87de56975900a6eec38cb66644f41a510f319cfbc1b3a274b826fee4251be&scene=21#wechat_redirect)  
  
  
[雪上加霜：俄罗斯恶意软件收集 Telegram 桌面凭证和通讯](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247487147&idx=3&sn=520d7b6164a44c7f964f7573834a0e43&chksm=ea973fc1dde0b6d7f2428db2d2c32b58b4cc3d671840dffefa8863340cf7a82f782b5fab6bc6&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/telegram-fixes-windows-app-zero-day-used-to-launch-python-scripts/  
  
  
题图：  
Pexels  
 License  
  
****  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
