#  荐读丨Fluent Bit高危漏洞威胁全球云计算大厂   
 工业安全产业联盟平台   2024-05-24 22:03  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JaFvPvvA2J23HBltRgVqzDh9vGfXuGnKn8sczXgkjMEDo1wpibZR8EYYvYX7EZmupY6uUscGRAwMFFicnvuqfJ0Q/640?wx_fmt=png "")  
  
  
Fluent Bit是一个极为流行的开源多平台日志处理器工具，近日曝出高危漏洞，波及全球几乎所有主流云服务商和众多科技巨头。  
  
  
Fluent Bit不仅兼容Windows、Linux和macOS系统，还嵌入在各大主流Kubernetes发行版中，其中就包括亚马逊AWS、谷歌GCP和微软Azure的产品。截至2024年3月，Fluent Bit的下载部署量已超过130亿次，相比2022年10月报告的30亿次呈现爆炸式增长。  
  
  
Crowdstrike、趋势科技等网络安全厂商以及思科、VMware、英特尔、Adobe和戴尔等科技公司均在其系统中部署了FluentBit。  
  
  
Tenable安全研究人员发现此漏洞并将其命名为“CVE-2024-4323-语言伐木工(Linguistic Lumberjack)”，这是一个内存损坏高危漏洞，出现在Fluent Bit嵌入式HTTP服务器解析跟踪请求过程中，版本号则最早可追溯至2.0.7。  
  
  
未经身份验证的攻击者可以轻松利用此漏洞发动拒绝服务攻击，或远程窃取敏感信息。在具备充分条件和时间的情况下，甚至有可能借此漏洞实现远程代码执行。Tenable表示：“这类堆栈溢出漏洞虽然已知可被利用，但要构建一个可靠的攻击程序不仅困难，而且极其耗时。研究人员认为，该漏洞最紧迫的风险在于易于发起的拒绝服务攻击和信息泄露。”  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FpQm8QaW5lU7IHDrMJ67ibictYsJA9kCgkbTAXpCoMge1icvJ9ygbZtKDoEmWRX8HYALc6rbYAWnEINJqoULIEicg/640?wx_fmt=png&from=appmsg "")  
  
**修复措施**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FpQm8QaW5lU7IHDrMJ67ibictYsJA9kCgqfV6S9Vhl6qiaCFDicFqA5JycOasUcFsibGJfZfW0Uto4ub85d9f45s8g/640?wx_fmt=png&from=appmsg "")  
  
  
  
Tenable在4月30日向Fluent Bit开发商通报了该安全漏洞，相关修复程序已于5月15日提交至Fluent Bit的主分支。包含漏洞修复的正式版本预计将随Fluent Bit 3.0.4发布（Linux软件包链接：https://github.com/fluent/fluent-bit/actions/runs/9097880110）。  
  
  
Tenable也于5月15日通过漏洞披露平台通知了微软、亚马逊和谷歌。  
  
对于已经部署Fluent Bit的用户，在官方补丁发布之前，可以通过限制对Fluent Bit监控API的访问（仅授权用户和服务）来降低风险。若非必要，也可以禁用该易受攻击的API端点，以确保潜在攻击被阻断并缩小攻击面。  
  
  
**参考链接：**  
  
**https://www.tenable.com/blog/linguistic-lumberjack-attacking-cloud-services-via-logging-endpoints-fluent-bit-cve-2024-4323**  
  
  
**end**  
  
  
  
  
来源 | 关键基础设施安全应急响应中心  
  
责任编辑 | 赫敏  
  
  
声明：本文由工业安全产业联盟微信公众平台（微信号：ICSISIA）转发，如有版权问题，请联系删除。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/4FpQm8QaW5kiaicHTUwSf9sId0er1ytR3D1Sc1RPfDpmk8FiciciadlBic9jSUbt1ciaE3G3aKiaicickE5ficq81KuYplgow/640?wx_fmt=png "")  
  
  
  
**如需合作或咨询，请联系工业安全产业联盟小秘书微信号：ICSISIA20140417**  
  
  
  
**往期荐读**  
  
[荐读 | 工业嵌入式控制系统可信计算技术应用研究](http://mp.weixin.qq.com/s?__biz=MzI2MDk2NDA0OA==&mid=2247519333&idx=2&sn=bf43af3fddbb39488cd710e74a1032ed&chksm=ea6367dadd14eeccb05e00991d2102691823321dc5ab0cec7cdbf0b7fdbababcf3072ef9bab5&scene=21#wechat_redirect)  
  
  
[重磅 | 《自动化博览》2024年第一期暨《工业控制系统信息安全专刊（第十辑）》上线](http://mp.weixin.qq.com/s?__biz=MzI2MDk2NDA0OA==&mid=2247526449&idx=1&sn=8833fa51b2d2d561b92a903afe7d3940&chksm=ea63838edd140a987d94f7154fd7e61808299215c930bec12eb4d1349dc8f642e21ddd055ea5&scene=21#wechat_redirect)  
  
  
[解决方案 | 长输供热工程工控安全防护解决方案](http://mp.weixin.qq.com/s?__biz=MzI2MDk2NDA0OA==&mid=2247519250&idx=1&sn=ef38b08e844bd87ea31f7c255749a2d2&chksm=ea6367addd14eebbad577732f522bae728f9b27f4f5f8924ce494af774ce7bd0637578052a47&scene=21#wechat_redirect)  
  
  
[关注 | 两会话安全：网络安全提案速览](http://mp.weixin.qq.com/s?__biz=MzI2MDk2NDA0OA==&mid=2247519102&idx=1&sn=82cc167aa7b73ea80a8306b1a0628cfc&chksm=ea6360c1dd14e9d7bb308b186182d17336c154fe084eee541ceb75b39edae090bc4fa7d6a936&scene=21#wechat_redirect)  
  
  
[荐读 | 工业互联网渗透测试技术研究](http://mp.weixin.qq.com/s?__biz=MzI2MDk2NDA0OA==&mid=2247519019&idx=1&sn=77752855e976481fa468f1771f943d9f&chksm=ea636094dd14e98212426441e59d8b26bf4739a9099ae2f0e95dc5849889fe5de2420115afe3&scene=21#wechat_redirect)  
  
  
[解决方案 | 精细化工产业互联网安全体系建设方案](http://mp.weixin.qq.com/s?__biz=MzI2MDk2NDA0OA==&mid=2247519524&idx=1&sn=9cfea10f776336d016f54b398bd49d13&chksm=ea63669bdd14ef8d331333ae32ca7470321b566adb26c8559d4614c694e85553477318fa88b1&scene=21#wechat_redirect)  
  
  
[荐读 | 智能制造装备安全方案](http://mp.weixin.qq.com/s?__biz=MzI2MDk2NDA0OA==&mid=2247519506&idx=1&sn=56c9d0355d2c8b769ad8eb3c046d64fc&chksm=ea6366addd14efbb0741053e462cb5c029b4cccc3dc886ffa1cfdf630aa400248315c44cb0d8&scene=21#wechat_redirect)  
  
  
[观点 | CCF计算机安全专委会发布2023年网络安全十大发展趋势](http://mp.weixin.qq.com/s?__biz=MzI2MDk2NDA0OA==&mid=2247518554&idx=1&sn=e2a24ea69c914133583f0b2361417af1&chksm=ea6362e5dd14ebf33f035330815cba14b344f2100799e1c8e4d46ee74fc7afd0f39d9e520641&scene=21#wechat_redirect)  
  
  
[荐读 | 智能制造背景下我国工业网络安全的新挑战](http://mp.weixin.qq.com/s?__biz=MzI2MDk2NDA0OA==&mid=2247519439&idx=1&sn=51637c6f276e86baa666b5812ef3bb03&chksm=ea636770dd14ee66da717009491d91283c666a7f755ff45bd49c6d1eff4b41ec29210ef0de66&scene=21#wechat_redirect)  
  
  
[报告 | 《中国网络安全产业研究报告》发布：多方利好驱动网络安全产业高质量发展](http://mp.weixin.qq.com/s?__biz=MzI2MDk2NDA0OA==&mid=2247518760&idx=1&sn=ded3f64e6fd6418f61be5a9287c20264&chksm=ea636197dd14e881a65fa9de6fb17a5490933c41879be32d043bb1c0aba9a2a6f310e16a83b0&scene=21#wechat_redirect)  
  
  
[荐读 | 基于改进预处理PCA算法的代码混淆分析](http://mp.weixin.qq.com/s?__biz=MzI2MDk2NDA0OA==&mid=2247519239&idx=1&sn=e91df29cbcf48862f57011ba38a10a3f&chksm=ea6367b8dd14eeaedd9ce58fe699e16f3dbba2aea71bf63c34df5a1ce15dd8513075bfb80fcb&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/4FpQm8QaW5kiaicHTUwSf9sId0er1ytR3DKSoeMXFlR7IoysRX7Q4YAxbhISo0Jj8tibs5VJUeZia2DwUriaibkjwTeg/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/4FpQm8QaW5kiaicHTUwSf9sId0er1ytR3DK7kFf9H00Hb5BHKX6icdia87wKNiceZOnsBoIkibsHL5XdDsBYYia7iaG1Bg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/4FpQm8QaW5kiaicHTUwSf9sId0er1ytR3D7Dicvw7EsV5RaicB7ichujWBE3OVfOfz5Pfdwicia2SCIpPpuOuNcts3Ribw/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/4FpQm8QaW5kiaicHTUwSf9sId0er1ytR3DjY6RJTmeoPiahgjyp37sB2fQWa2aHXellbm8zJVHPWqYdJ7ckzd5Fhw/640?wx_fmt=jpeg "")  
  
  
