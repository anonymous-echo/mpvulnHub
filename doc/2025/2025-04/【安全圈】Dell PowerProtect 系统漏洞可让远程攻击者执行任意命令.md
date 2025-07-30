#  【安全圈】Dell PowerProtect 系统漏洞可让远程攻击者执行任意命令   
 安全圈   2025-04-08 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgwj1wxnZsmMk2aBsXUw5Z87SLZ94BLuibNUjxp41dmfsh5R4lHibicFWJ8ibntMNjOOVSMjKGv3QZXVg/640?wx_fmt=png&from=appmsg "")  
  
已发现 Dell Technologies PowerProtect Data Domain 系统存在一个重大安全漏洞，该漏洞可能使已认证用户能够以 root 权限执行任意命令，从而有可能危及关键的数据保护基础设施。  
  
Dell 已发布修复补丁，以解决这一严重影响其企业备份和恢复产品组合中多条产品线的高危问题。  
  
安全研究人员在运行 Data Domain 操作系统（DD OS）8.3.0.15 版本之前的 Dell PowerProtect Data Domain 系统中，发现了一个被追踪编号为 CVE-2025-29987 的严重缺陷。该漏洞的通用漏洞评分系统（CVSS）基础评分为 8.8（高危），评分向量字符串为 CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H，这表明如果该漏洞被利用，可能会造成重大损害。  
  
其核心问题被归类为 “访问控制粒度不足漏洞”，这可能会使 “来自受信任远程客户端的已认证用户” 获得未经授权的权限提升。该漏洞允许 “以 root 权限执行任意命令”，这实质上赋予了攻击者对受影响系统的完全控制权。  
  
根据安全公告，此漏洞影响Dell 数据保护基础设施的多个版本。其 2.8 的可利用性评分和 5.9 的影响评分，进一步突显了使用未修补版本的组织所面临的重大风险。  
### 受影响的产品和系统  
  
该漏洞影响了一系列 Dell PowerProtect Data Domain 产品，包括：  
  
1.Dell PowerProtect Data Domain 系列设备。  
  
2.Dell PowerProtect Data Domain 虚拟版。  
  
3.Dell APEX 保护存储。  
  
4.PowerProtect DP 系列设备（IDPA）2.7.6、2.7.7 和 2.7.8 版本。  
  
5.大型机用磁盘库 DLm8500 和 DLm8700。  
  
具体来说，存在漏洞的 DD OS 版本包括 7.7.1.0 至 8.3.0.10、7.13.1.0 至 7.13.1.20 以及 7.10.1.0 至 7.10.1.50 这些版本。  
  
以下是该漏洞的概述：  
<table><tbody><tr style="box-sizing: border-box;background-color: rgb(240, 240, 240);"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong style="box-sizing: border-box;font-weight: bold;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">风险因素</span></font></font></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong style="box-sizing: border-box;font-weight: bold;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">细节</span></font></font></strong></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">受影响的产品</span></font></font></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">Dell PowerProtect Data Domain 系列设备、Dell PowerProtect Data Domain 虚拟版、Dell APEX Protection Storage、PowerProtect DP 系列设备 (IDPA)、适用于大型机 DLm8500 和 DLm8700 的磁盘库</span></font></font></td></tr><tr style="box-sizing: border-box;background-color: rgb(240, 240, 240);"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">影响</span></font></font></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">执行任意命令</span></font></font></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">漏洞利用前提条件</span></font></font></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">来自受信任远程客户端的经过身份验证的用户；需要低权限访问</span></font></font></td></tr><tr style="box-sizing: border-box;background-color: rgb(240, 240, 240);"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">CVSS 3.1 分数</span></font></font></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">8.8 (高)</span></font></font></td></tr></tbody></table>  
Dell 已迅速开发并发布了修复版本来解决此漏洞。强烈敦促使用受影响系统的组织升级到以下修复版本：  
  
1.对于 DD OS 8.3：8.3.0.15 版本或更高版本。  
  
2.对于 DD OS 7.13.1：7.13.1.25 版本或更高版本。  
  
3.对于 DD OS 7.10.1：7.10.1.60 版本或更高版本。  
  
对于 PowerProtect DP 系列设备（IDPA）的 2.7.6、2.7.7 和 2.7.8 版本，客户必须升级以集成 DD OS 7.10.1.60。  
  
对于大型机用磁盘库 DLm8500（5.4.0.0 版本或更高版本）和 DLm8700（7.0.0.0 版本或更高版本），也有类似的升级要求。  
### 安全影响  
  
这并非 Dell PowerProtect 产品首次面临安全挑战。此前，PowerProtect 生态系统中的漏洞，如 CVE-2023-44277 和 CVE-2024-22445，也曾导致任意命令执行。  
  
当前的漏洞（CVE-2025-29987）尤其令人担忧，因为一旦被利用，攻击者将获得受影响系统的 root 级访问权限，有可能使他们能够：  
  
1.访问或销毁受保护的备份数据。  
  
2.向备份基础设施中注入恶意代码。  
  
3.渗透到企业网络内的其他连接系统。  
  
4.破坏备份存储库中的数据完整性。  
  
强烈建议各组织优先进行这些安全更新，特别是对于包含敏感或受监管数据的系统。  
  
Dell 一直在积极修订其安全公告文档，在 2025 年 4 月 2 日至 4 日期间进行了六次更新，以便为所有受影响的产品提供全面的修复指导。  
  
客户应查阅 Dell 的知识库文章和修复文档，以获取详细的升级说明和针对特定产品的指导。  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】ChatGPT-4o五分钟生成假护照：传统验证机制面临危机](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068935&idx=1&sn=7502240272ee4848796ef973c3e1bf36&scene=21#wechat_redirect)  
  
  
  
[【安全圈】新的 Sakura RAT 出现在 GitHub 上，成功逃避 AV 和 EDR 保护](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068935&idx=2&sn=bdd6b5701dc1700736e3ba1f07c5b3df&scene=21#wechat_redirect)  
  
  
  
[【安全圈】警惕！虚假通行费短信借 Lucid 平台窃取登录信息](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068935&idx=3&sn=99db2fb12c903a55ca3334bcc15d2b9b&scene=21#wechat_redirect)  
  
  
  
[【安全圈】有关部门严厉打击网上体育“饭圈”问题](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068921&idx=1&sn=635f6e93a0e8d61ed7c8fc91ebc76d26&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
