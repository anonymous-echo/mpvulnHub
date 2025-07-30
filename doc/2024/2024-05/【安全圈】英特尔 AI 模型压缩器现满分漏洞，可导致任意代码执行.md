#  【安全圈】英特尔 AI 模型压缩器现满分漏洞，可导致任意代码执行   
 安全圈   2024-05-23 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
漏洞  
  
  
据Info risk today消息，英特尔公司的人工智能模型压缩软件Neural Compressor 中存在一个最高级别的漏洞，该漏洞在 CVSS 的评分为满分10分，黑客可以在运行受影响版本的系统上执行任意代码。  
  
Neural Compressor 软件可帮助公司减少人工智能模型所需的内存量，同时降低缓存丢失率和使用神经网络的计算成本，帮助系统实现更高的推理性能。公司使用开源 Python 库在不同类型的硬件设备上部署人工智能应用，包括那些计算能力有限的设备（如移动设备）。  
  
英特尔没有说明有多少公司使用该软件，也没有说明受影响的用户数量，称该漏洞只影响使用 2.5.0 之前版本的用户。  
  
在英特尔上周发布的 41 份安全公告中，该漏洞被追踪为 CVE-2024-22476，源于输入验证不当或未对用户输入进行消毒，黑客无需任何特殊权限或用户交互即可远程利用该漏洞，对数据的保密性、完整性和可用性构成很大影响。  
  
除此以外，还有另一个漏洞被追踪为 CVE-2024-21792，严重程度为中等，是一个检查时间、使用时间漏洞，可能会让黑客获取未经授权的信息。黑客需要通过本地验证访问存在漏洞的系统才能利用该漏洞。  
  
英特尔表示，一个外部安全实体提交了该漏洞报告，但没有说明个人或公司的身份。目前，英特尔已经发布了针对上述两个 Neural Compressor 漏洞的修复程序。  
  
去年，研究人员在大型语言模型中发现了几十个漏洞，这些漏洞可能导致操纵实时对话、自我传播零点击漏洞以及利用幻觉传播恶意软件。  
  
使用这种软件作为核心组件来构建和支持人工智能产品的公司可能会增加漏洞的影响，英特尔就是一个例子。一个月前，来自 Wiz 的研究人员在流行的人工智能应用开发商 HuggingFace 上发现了现已缓解的漏洞，允许攻击者篡改其注册表上的模型，甚至向其中添加恶意模型。  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljtafx9Y8EsvLPGEWGUOEEPeKXSsEVD5QjT2n0cxqFEn9Ko62DRFoTIfVySaStX7v2bVs0I5phf9w/640?wx_fmt=jpeg "")  
[【安全圈】麦当劳APP崩了！麦当劳紧急回应](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652060362&idx=1&sn=96b37454cc23cd7e4831acd39e818b18&chksm=f36e168ac4199f9cd88dd21649d29fbf3e4e4888123846f5035f3fc1d867704c5448de33dd5b&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljtafx9Y8EsvLPGEWGUOEEP7iaTkryzpNOKIhk9FNEthJXfkltaF3vuuwzmUNYPuezF2YURK0CCxHQ/640?wx_fmt=jpeg "")  
[【安全圈】汇丰银行和巴克莱银行遭黑客入侵，金融系统面临重大危机](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652060362&idx=2&sn=831edc3f26cf6c6558ca354e32f47530&chksm=f36e168ac4199f9ca78dd4d74ff129180cda8701b7c577524965e261abfbb9a071d08b3fb3de&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljtafx9Y8EsvLPGEWGUOEEPW7OibQFKhEUp307vBxgHuan8VcJozfb10espXbfoYuuEdusWhTFa4AA/640?wx_fmt=jpeg "")  
[【安全圈】可绕过身份验证，GitHub 企业服务器曝满分漏洞，附 PoC](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652060362&idx=3&sn=505f4f8076fc9bc85e9fc7214f64c120&chksm=f36e168ac4199f9c62c375d0278a2be1d1997cf90e4454f73bdd593a1839b80aef5a08c75382&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljtafx9Y8EsvLPGEWGUOEEPKmIOBVDQmMdIeFsBetMFk52sIcG0icbyibyP7aTKlHVmzCic8zqnricBhw/640?wx_fmt=jpeg "")  
[【安全圈】黑客滥用微软“快速助手”，展开网络钓鱼攻击活动](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652060362&idx=4&sn=8ccd1fbdd75273bd4ccb8e44248c7c70&chksm=f36e168ac4199f9c9d3e4940b615d5b1b12ec1aaa664ef22375a2af0f8663f3a17ec492aa44b&scene=21#wechat_redirect)  
  
  
  
  
  
  
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
  
