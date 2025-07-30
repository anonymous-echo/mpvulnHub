#  隐秘的 npm 供应链攻击：误植域名导致RCE和数据破坏   
Ddos  代码卫士   2025-06-03 10:35  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRSylJK2k7H6mNqiaS2G6WRaeeK34cLHE6pe9VeOIHYiboAnKB0TMoayZCxFpHMLljzTnz9DnNuFiaqQ/640?wx_fmt=png "")  
  
  
  
专栏·供应链安全  
  
  
数字化时代，软件无处不在。软件如同社会中的“虚拟人”，已经成为支撑社会正常运转的最基本元素之一，软件的安全性问题也正在成为当今社会的根本性、基础性问题。  
  
  
随着软件产业的快速发展，软件供应链也越发复杂多元，复杂的软件供应链会引入一系列的安全问题，导致信息系统的整体安全防护难度越来越大。近年来，针对软件供应链的安全攻击事件一直呈快速增长态势，造成的危害也越来越严重。  
  
  
为此，我们推出“供应链安全”栏目。本栏目汇聚供应链安全资讯，分析供应链安全风险，提供缓解建议，为供应链安全保驾护航。  
  
  
注：以往发布的部分供应链安全相关内容，请见文末“推荐阅读”部分。  
  
  
  
**Socket 威胁研究团队最近发现一起利用误植域名和远程代码执行实施的隐秘的 npm 供应链攻击活动。这些恶意包名称为 “xlsx-to-json-lh”，它们假冒的是合法且广泛使用的 Excel-to-JSON 转换工具 xlsx-to-json-lc，虽然仅修改了最后一个字母，但影响却不容小觑。**  
  
Socket 发布报告提到，“该程序包在发现前已经在 npm 上存在了六年之久。”截止本文发布之时，该程序包仍然活跃于注册表中，需立即删除。  
  
和其它恶意软件不同，xlsx-to-json-lh 会狡猾地伪装成一个合法模块，它实际执行的是预期的对话功能，因此能够通过基础的功能测试。但它实际上导入了连接到一个C2服务器的第二阶段的 payload，默默等待一个kill-switch 命令。  
  
而该供应链攻击最危险的地方在于，除了导入该模块外，无需任何用户交互即可实施攻击。一旦被加载，payload 就会监听一个名为“重置为零”的命令。收到之后，该恶意软件会删除整个项目目录，包括源文件、.git文件夹、node_modules、配置文件以及路径上的其它所有一切。Socket 团队提醒称，“没有外部备份，恢复实际上是不可能实现的。”  
  
为了欺骗开发人员，该恶意包保留了原始作者的元数据、模拟可信作者 rahil471，同时还引入了化名为 “leonhard” 的npm 新维护人员。这种技术利用的是开发人员依赖元数据获得信任信号的行为。Package.json 文件丝滑利用了这一事实，使攻击看似无害。  
  
研究人员认为这起攻击或与一名讲法语的攻击者有关。该维护人员的邮件地址以 “.fr” 结尾，而破坏性的触发命令用法语编写。此外，该恶意软件使用了scoket.io-client 维持对 Heroku 服务器的可持久的WebSocket 连接。一旦连接，它就会静静等待表示该代码库。攻击的这种简约性和规模正是其可怕之处。想象一下环境中有多个项目文件夹的开发人员遭感染的情况有多危险。只需一个远程命令，这三个倾注多年努力的项目就会在数秒内被擦除。正如Socket 描述的那样，“每个拥有2-3个受感染项目的20名开发人员意味着40-60个代码库被立马破坏。”  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMTBzmfDJA6rWkgzD5KIKNibpR0szmPaeuu4BibnJiaQzxBpaRMwb8icKTeZVEuWREJwacZm3wElt7vOtQ/640?wx_fmt=jpeg "")  
  
  
开源  
卫士试用地址：  
https://sast.qianxin.com/#/login  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[NPM恶意包利用Unicode 隐写术躲避检测](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523031&idx=2&sn=5071cdb63bdd6339b1a3ff7ef3581cd5&scene=21#wechat_redirect)  
  
  
[Aikido在npm热门包 rand-user-agent 中发现恶意代码](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522945&idx=1&sn=c767722383afc7e6b505aef2f50ba4cd&scene=21#wechat_redirect)  
  
  
[密币Ripple 的NPM 包 xrpl.js 被安装后门窃取私钥，触发供应链攻击](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522841&idx=2&sn=024b6c290bf4ebecc241f11bc944be1c&scene=21#wechat_redirect)  
  
  
[已存在9年的 npm 包遭劫持，通过混淆脚本投毒提取API密钥](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522612&idx=1&sn=1083440528cb0effbb60af2d98c5dc48&scene=21#wechat_redirect)  
  
  
[NPM新型攻击通过后门投毒本地包](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522605&idx=2&sn=c123175c0f1e9db64ef4e1bbaf5521f7&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://securityonline.info/stealthy-npm-supply-chain-attack-typosquatting-leads-to-remote-code-execution-and-data-destruction/  
  
  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
  
