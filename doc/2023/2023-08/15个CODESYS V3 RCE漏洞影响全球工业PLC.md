#  15个CODESYS V3 RCE漏洞影响全球工业PLC   
THN  代码卫士   2023-08-14 17:46  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**CODESYS V3 软件开发包 (SDK) 中存在16个高危漏洞，在特定条件下可导致远程代码执行和拒绝服务后果，从而为运营技术 (OT) 环境带来风险。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRBGNwgicSuTe4Y4rEOSqVh2Oh4ehfs24kGuWSkdIa78Lfyy14XNT1icYGk0XVHJgBEkia0R3jwibEVjg/640?wx_fmt=png "")  
  
  
IEC 61131-3 标准提到，全球超过500家设备制造商使用 CODESYS V3 SKD 在超过1000个 PLC 模型中进行编程，从而开发出自定义的自动化序列。该SDK 还提供 Windows 管理接口和模拟器，使用户能够在部署到生产环境中之前测试 PLC的配置和编程。  
  
这些漏洞的编号从 CVE-2022-47378到CVE-2022-47393，被统称为 CoDe16，CVSS 评分为8.8。CVE-2022-47391的严重程度为7.5。在这些漏洞中，12个是缓冲溢出漏洞。  
  
微软威胁情报社区成员 Vladimir Tokarev 在报告中提到，“这些漏洞影响 CODESYS 3.5.19.0之前的所有V3版本，可使 OT 基础设施处于风险之中，如远程代码执行和拒绝服务等。”虽然成功利用这些漏洞要求用户认证以及对 CODESYS V3 的专有协议具有深入了解，但这些漏洞可造成严重后果，导致关键自动化流程关闭以及遭恶意篡改。这些远程代码执行漏洞可被用于在OT设备中安装后门并干扰可编程逻辑控制器的运行，从而窃取信息。Tokarev 解释称，“利用这些漏洞要求用户认证以及绕过这些PLC使用的数据执行防御 (DEP) 机制和ASLR。”  
  
要绕过用户认证阻碍，攻击者利用已知漏洞 (CVE-2019-9013) 对PLC实施重放攻击以窃取凭据，之后利用这些漏洞触发缓冲区溢出漏洞并获得对设备的控制权限。  
  
漏洞补丁已在2023年4月发布，相关简述如下：  
  
- CVE-2022-47378：成功认证后，具有不一致内容的特定构造通信请求可导致 CmpFiletransfer 组件从不合法地址进行内部读取，从而导致拒绝服务条件。  
  
- CVE-2022-47379：成功认证后，特定的构造通信请求可导致 CmpApp 组件将受攻击者控制的数据写入内存，从而导致拒绝服务条件、内存覆写或远程代码执行后果。  
  
- CVE-2022-47380和CVE-2022-47381：成功认证后，特定构造通信请求可导致 CmpApp 组件将受攻击者控制数据写入栈，从而导致拒绝服务条件、内存覆写或远程代码执行后果。  
  
- CVE-2022-47382、CVE-2022-47383、CVE-2022-47384、CVE-2022-47386、CVE-2022-47387、CVE-2022-47388、CVE-2022-47389和CVE-2022-47390：成功认证后，特定构造的通信请求可引发 CmpTraceMgr 组件将受攻击者控制的数据写入栈，从而导致拒绝服务条件、内存覆写或远程代码执行后果。  
  
- CVE-2022-47385：特定构造的通信请求可导致受影响产品从不合法地址实施内部读取，可能导致拒绝服务条件。  
  
- CVE-2022-47392：成功认证后，具有不一致内容的特定构造通信请求可引发CmpApp/CmpAppBP/CmpAppForce 组件从不合法地址实施内部读取，从而导致拒绝服务条件。  
  
- CVE-2022-47393：成功认证后，特定构造的通信请求可导致 CmpFiletransfer 组件解引用由该请求提供的地址，实施内部读访问，导致拒绝服务情况。  
  
  
  
Tokarev 表示，“很多厂商都在使用 CODESYS，一个漏洞就可能影响很多部门、设备类型和垂直行业，更不用说很多个漏洞了。威胁行动者可使用易受攻击的 CODESYS 版本对设备发起DoS 攻击，关闭工业操作或利用这些RCE漏洞部署后门窃取敏感数据、篡改操作或强迫PLC 以危险方式运行。”  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[奇安信入选全球《静态应用安全测试全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516678&idx=1&sn=5b9e480c386161b1e105f9818b2a5a3d&chksm=ea94b36cdde33a7a05cafa9918733669252a02611c222b02bc6e66cbb508ee3fbf748453ee7a&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[德企Festo 和 CODESYS 的OT产品受3个漏洞影响，可导致供应链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514853&idx=4&sn=f887c2246bde0615a6afcc197112e9a8&chksm=ea948b8fdde30299897ba08d1d9780bac245ae05c8b213f63334fa58fc54924eb5c5e95c5bac&scene=21#wechat_redirect)  
  
  
[CODESYS 工业自动化软件存在多个严重缺陷](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247506504&idx=1&sn=8bc31a5780041acc90704bb3fe847c65&chksm=ea94eb22dde36234b6299f4009fd280b2cb47f881f429d063cd0c4d8c5100ee86143cf4a0896&scene=21#wechat_redirect)  
  
  
[很多工控产品都在用的 CODESYS 软件中被曝10个严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247505442&idx=1&sn=645ef4a67cc6372f43f130a8137ab64b&chksm=ea94e748dde36e5e6a22fd7095c3617ac52b1376100a574a8020f04cef31b81c971ae57ad756&scene=21#wechat_redirect)  
  
  
[工业环境软件套件 CODESYS web 服务器被曝严重的RCE漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247492594&idx=3&sn=4e4e6eabe37cb1f89a238a8f0906d663&chksm=ea94d298dde35b8e2b87fb71775d04cec94b96fdf123e4345d933e3d6dcfe2017498faaf5a80&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2023/08/15-new-codesys-sdk-flaws-expose-ot.html  
  
  
题图：  
Pixab  
ay License  
  
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
  
