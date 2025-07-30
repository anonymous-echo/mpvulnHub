> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070639&idx=3&sn=bbaf04680a16d1922d1ac51d26b48f5a

#  【安全圈】印度背景黑客组织 DoNot APT 使用 LoptikMod 恶意软件攻击欧洲外交部  
 安全圈   2025-07-13 11:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
网络攻击  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgvicgOibfJv5FVZticJmXUibrc1Q4Cb14ZIyxEmKtbseg5nXrkCBYJjR7qx9K7wDtNH05VbJyXCIcfrg/640?wx_fmt=png&from=appmsg "")  
  
据 Trellix 高级研究中心披露，长期活跃于南亚地区的 DoNot APT 黑客组织近期将攻击目标扩展至欧洲外交体系。该组织成功发动了一起高级鱼叉式网络钓鱼攻击，目标为某欧洲国家外交部，企图通过精心伪装的电子邮件和恶意软件窃取敏感信息。此事件再次凸显地缘政治背景下的网络间谍活动正不断外溢至全球外交网络。  
  
DoNot APT，又称 APT-C-35 或 Mint Tempest，自 2016 年起已被广泛监测。其常年针对政府、军队及外交机构发动攻击，并多次被归因与印度有关联。此次入侵欧洲外交系统标志着该组织在战略方向上的拓展。  
  
本次攻击由一封精心设计的钓鱼邮件引发，邮件伪装成来自欧洲国防官员，内容提及一次前往孟加拉国的“国防武官访问”。攻击者使用 Gmail 邮箱（int.dte.afd.1@gmailcom）作为发信地址，并在主题中嵌入 HTML 编码及 UTF-8 字符处理，以真实呈现如“Attaché”等外语字符，提升邮件的可信度。  
  
邮件中附有指向 Google Drive 的链接，诱导受害者下载名为 “SyClrLtr.rar” 的压缩包。该文件解压后包含一个伪装为 PDF 文件的可执行程序（notflog.exe），一旦运行，即触发后续批处理脚本和持久化机制——其中包括每十分钟自动执行的计划任务，使恶意软件在系统重启后仍可保持激活状态。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgvicgOibfJv5FVZticJmXUibrcoxLwRKQqribqD0u0mRW6jHNGt8ZU2oJGm1ZyvTw7WfMt8JTC2CXQBog/640?wx_fmt=png&from=appmsg "")  
  
此次攻击所使用的核心恶意载荷为 LoptikMod，这是一款自 2018 年起即被 DoNot APT 组织专属使用的间谍软件。该工具可收集受害系统的 CPU 型号、操作系统信息、用户名和主机名等基本系统情报，并通过加密方式上传至远程控制服务器。此外，DoNot APT 组织还广泛使用定制的 Windows 后门程序，包括 YTY 和 GEdit，用于深度渗透与数据控制。  
  
攻击目标锁定欧洲外交机构，说明该组织有明确的信息收集企图，其目的可能涉及外交信函、政策决策、国家情报等核心内容。此类行动符合典型国家支持型间谍活动特征，手法隐蔽、链条完整、目的明确。  
  
安全专家强调，当前外交机构必须全面加强电子邮件防护、网络流量分析及终端安全监测能力。通过部署先进的威胁检测系统与“零信任”策略，才能有效防御此类复杂持久的间谍攻击。  
  
这起事件不仅暴露了欧洲政治机构所面临的现实风险，也再次提醒全球范围内的政府与战略部门：地缘政治背景下的网络安全已不再具有地域限制，跨境威胁正在成为新常态。  
  
  
 END   
  
  
阅读推荐  
  
  
[【安全圈】DeepSeek再遭捷克封杀！](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070622&idx=1&sn=0b6e4805766d104ac954112f8872fc2c&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Coinbase事件撕开加密安全最脆弱的防线](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070622&idx=2&sn=f58a0b0f5da56125d6d0c40e1e904f86&scene=21#wechat_redirect)  
  
  
  
[【安全圈】拿“123456”当密码，麦当劳6400万条求职信息存在泄露风险](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070622&idx=3&sn=5b53dd9b5f6d29081c504ae7e02b9dd2&scene=21#wechat_redirect)  
  
  
  
[【安全圈】ChatGPT 被绕过守护机制，泄露 Windows 产品密钥事件概述](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070608&idx=1&sn=4e5dc281a4812d0a3f756ec67d0bc633&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
