> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070655&idx=2&sn=48c5a098c1fb64e52d12ffeb8309e9b1

#  【安全圈】WinRAR现0day高危漏洞：地下黑客叫价8万美元，数亿Windows用户面临远程攻击风险  
 安全圈   2025-07-14 11:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
WinRAR  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylj36aZkXSpokWicU6IbwrvWuu7yn76l7QrLsgPxsx1VNAJZScCQoXDbwI39FuRFuwR6DC6mPBJHd7Q/640?wx_fmt=png&from=appmsg "")  
  
一名使用“zeroplayer”网名的威胁行为者近日在地下论坛上公开兜售一枚WinRAR远程代码执行（RCE）0day漏洞，售价为8万美元。据称，该漏洞影响当前WinRAR最新版及以下版本，与近期披露并修复的CVE-2025-6218漏洞无关，且仅通过论坛的担保交易系统出售。  
  
WinRAR作为广泛部署在数亿台Windows设备上的压缩软件，一直以来都是攻击者眼中的高价值目标。该工具在企业与个人终端中使用频繁，尤其是在处理压缩附件时，潜在攻击面巨大。类似的漏洞一旦被武器化，国家级APT组织与犯罪团伙可利用其将攻击周期从数周压缩至数小时，尤其在钓鱼邮件投递场景中效果显著。  
  
目前虽然zeroplayer未公布详细利用代码，但过往WinRAR漏洞的利用路径可提供参考。攻击者通常构造恶意压缩包，在其中嵌入异常格式化的头部或超长文件名，诱导WinRAR解析逻辑出错，进而触发堆栈溢出或内存破坏。在实现初始控制后，攻击者可部署小型加载器，将控制流转向自定义地址，继而下载更大规模的有效载荷。为实现持久化，恶意代码往往写入启动目录，或通过注册表劫持COM组件，实现开机自启。  
  
若该漏洞确实能绕过现有的DEP和ASLR等Windows系统防护机制，且能在默认配置下实现稳定的远程执行代码效果，无疑将对防御方构成极大挑战。企业环境中大量存在自动解压缩流程，特别是在构建服务器或CI/CD管道中，更为此类漏洞提供了近乎无感知的攻击通道。  
  
此前，APT40、Sandworm等组织就曾利用WinRAR解析缺陷传播DarkMe、BitterRAT与UAC-0050等间谍程序，足见此类攻击链的实战可行性。对于此次疑似0day的出售行为，极有可能被“初始访问经纪人”购入后用于构建初始入口，并在地下市场将系统访问权限转售给勒索软件合作团伙。届时，入侵周期将大幅缩短，极大提升攻击成功率与破坏能力。  
  
鉴于风险程度较高，防御团队应即刻加强对压缩包提取行为的审计，配置入侵防御系统以虚拟补丁形式拦截可疑流量，并为可能的厂商紧急补丁预先做好部署准备。在此之前，任何来自不可信来源的压缩文件均应被视为潜在威胁，加强操作规范和安全意识教育，是当前阶段的唯一缓解手段。  
  
  
 END   
  
  
阅读推荐  
  
  
[【安全圈】OpenAI 即将推出集成 AI 智能体的 Chromium 浏览器，挑战 Chrome 市场主导地位](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070639&idx=1&sn=f8fe5c05daa266c8470e771cba01275f&scene=21#wechat_redirect)  
  
  
  
[【安全圈】PerfektBlue：四项蓝牙协议栈漏洞危及数百万车辆，可被远程执行代码](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070639&idx=2&sn=f98a8cececf06db2add503959abb412c&scene=21#wechat_redirect)  
  
  
  
[【安全圈】印度背景黑客组织 DoNot APT 使用 LoptikMod 恶意软件攻击欧洲外交部](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070639&idx=3&sn=bbaf04680a16d1922d1ac51d26b48f5a&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Trendyol 披露 Meta  存在漏洞：Prompt Injection 成功率高达 50%](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070639&idx=4&sn=4e7c93291c55d089867addbbd0436070&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
