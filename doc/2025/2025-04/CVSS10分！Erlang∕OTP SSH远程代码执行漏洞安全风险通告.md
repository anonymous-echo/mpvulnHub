#  CVSS10分！Erlang/OTP SSH远程代码执行漏洞安全风险通告   
应急响应中心  亚信安全   2025-04-27 10:07  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iczzp36h0nbHaFTYGxJib9QqWUzhbtW2Oiacgg51SabmkMw9qIDkm0ic4JOvldPnVHLCrrPiaibJM5rdM8MzXaickNnDA/640?wx_fmt=jpeg "")  
  
  
今日，亚信安全CERT监控到安全社区研究人员发布安全通告，Erlang/OTP存在一个远程代码执行漏洞，编号为 CVE-2025-32433。攻击者可以通过构造特定 SSH 协议消息，在未进行身份验证的情况下在受影响的系统上执行任意代码。这一漏洞使得攻击者能够获取系统的控制权，并可能导致敏感数据泄露、系统崩溃或其他恶意活动。  
  
  
**目前官方已发布安全更新，亚信安全CERT建议受影响的客户尽快升级至最新版本。**  
  
  
Erlang/OTP 是一种编程语言和运行环境，专为构建高可用性、并发和分布式系统而设计。Erlang 是基于函数式编程的语言，具有强大的并发和错误处理能力，特别适合实时系统。而 OTP（Open Telecom Platform）则是一个包含一系列库和设计原则的框架，提供了构建、部署和管理 Erlang 应用程序的工具，帮助开发者快速实现可靠的系统。Erlang/OTP 广泛应用于电信、银行、消息传递等领域，以其卓越的容错能力和性能著称。  
  
  
**漏洞编号、类型、等级和评分**  
  
  
  
- CVE-2025-32433  
  
- 远程代码执行漏洞  
  
- 紧急  
  
- CVSS3.0：10分  
  
- CVSS2.0：10分  
  
  
  
  
**漏洞状态**  
  
  
  
<table><tbody style="box-sizing: border-box;"><tr style="box-sizing: border-box;"><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(145, 145, 145);box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="text-align: justify;padding: 0px 5px;font-size: 14px;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="text-align: center;white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;">细节</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(145, 145, 145);box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;">PoC</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(145, 145, 145);box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;">EXP</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(145, 145, 145);box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;">在野利用</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(145, 145, 145);box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;">复现情况</strong></p></section></section></td></tr><tr style="box-sizing: border-box;"><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(62, 62, 62);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">公开</p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(62, 62, 62);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">公开</p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(62, 62, 62);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">公开</p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(62, 62, 62);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">未发现</p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(62, 62, 62);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">未复现</p></section></section></td></tr></tbody></table>  
  
  
**受影响版本**  
  
  
  
- Erlang/OTP <= OTP-25.3.2.19  
  
- Erlang/OTP <= OTP-27.3.2  
  
- Erlang/OTP <= OTP-26.2.5.10  
  
  
  
  
**产品解决方案**  
  
  
  
目前亚信安全怒狮引擎已第一时间新增了检测规则，支持Erlang/OTP SSH远程代码执行漏洞的检测，请及时更新TDA产品的特征库到最新版本。规则编号：106065753，规则名称：Erlang/OTP SSH远程代码执行漏洞(CVE-2025-32433)。  
  
  
更新方式如下：  
  
TDA产品在线更新方法：登录系统-》系统管理-》系统升级-》特征码更新；  
  
TDA产品离线升级PTN包下载链接如下：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbHaFTYGxJib9QqWUzhbtW2OiaAnicCAxOfqViaaF3mJ9Cvk31LpDbcqRxhlh8s0VickryM0bfevOEibAqkg/640?wx_fmt=png "")  
  
详细下载地址请后台咨询  
  
  
**修复建议**  
  
  
  
目前厂商已发布升级补丁以修复漏洞，补丁获取链接：  
  
  
https://github.com/erlang/otp/releases/tag/OTP-27.3.3  
  
  
**参考链接**  
  
  
  
- https://github.com/erlang/otp/security/advisories/GHSA-37cp-fgq5-7wc2  
  
- https://www.cybereason.com/blog/rce-vulnerability-erlang-otp  
  
- https://nvd.nist.gov/vuln/detail/CVE-2025-32433  
  
- https://github.com/ProDefense/CVE-2025-32433/blob/main/CVE-2025-32433.py  
  
- https://www.offsec.com/blog/cve-2025-32433/  
  
  
  
  
本文发布的补丁下载链接均源自各原厂官方网站。尽管我们努力确保官方资源的安全性，但在互联网环境中，文件下载仍存在潜在风险。为保障您的设备安全与数据隐私，敬请您在点击下载前谨慎核实其安全性和可信度。  
  
  
  
  
了解亚信安全，请点击  
**“阅读原文”**  
  
