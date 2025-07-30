#  高危！Vite任意文件读取漏洞安全风险通告   
应急响应中心  亚信安全   2025-04-14 09:54  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iczzp36h0nbGNYXVa2Ric7T7qj71VIzqAP9P9uNW7UPPwNTbVdyNMWQzxohnY6ldXLK6Piar9sz6JCnWAPyvhj9Bg/640?wx_fmt=jpeg "")  
  
  
近日，亚信安全CERT监控到安全社区研究人员发布安全通告，Vite存在一个任意文件读取漏洞，编号为 CVE-2025-31486。由于Vite在处理特定URL请求时缺少对路径的安全检查，这导致攻击者可以通过构造特定的 URL 请求绕过服务器的保护机制，非法访问敏感文件。  
  
  
**目前官方已发布安全更新，亚信安全CERT建议受影响的客户尽快升级至最新版本。**  
  
  
Vite是一种新型前端构建工具，能够显著提升前端开发体验。它主要由两部分组成：  
  
  
- 一个开发服务器，它基于 原生 ES 模块 提供了 丰富的内建功能，如快速模块热更新（HMR）。  
  
- 一套构建指令，它使用 Rollup 打包代码，并且它是预配置的，可输出用于生产环境的高度优化过的静态资源。  
  
  
  
Vite 意在提供开箱即用的配置，同时它的 插件 API 和 JavaScript API 带来了高度的可扩展性，并有完整的类型支持。  
  
  
**漏洞编号、类型、等级和评分**  
  
  
  
- CVE-2025-31486  
  
- 任意文件读取漏洞  
  
- 高危  
  
- CVSS3.0：7.5分  
  
- CVSS2.0：7.8分  
  
  
  
  
**漏洞状态**  
  
  
  
<table><tbody style="box-sizing: border-box;"><tr style="box-sizing: border-box;"><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(145, 145, 145);box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="text-align: justify;padding: 0px 5px;font-size: 14px;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="text-align: center;white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;">细节</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(145, 145, 145);box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;">PoC</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(145, 145, 145);box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;">EXP</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(145, 145, 145);box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;">在野利用</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(145, 145, 145);box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;">复现情况</strong></p></section></section></td></tr><tr style="box-sizing: border-box;"><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(62, 62, 62);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">公开</p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(62, 62, 62);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">公开</p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(62, 62, 62);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">公开</p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(62, 62, 62);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">未发现</p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(62, 62, 62);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">未复现</p></section></section></td></tr></tbody></table>  
  
  
**受影响版本**  
  
  
  
- 6.2.0 <= Vite <= 6.2.4  
  
- 6.1.0 <= Vite <= 6.1.3  
  
- 6.0.0 <= Vite <= 6.0.13  
  
- 5.0.0 <= Vite <= 5.4.16  
  
- Vite <= 4.5.11  
  
  
  
  
**产品解决方案**  
  
  
  
目前亚信安全怒狮引擎已第一时间新增了检测规则，支持CVE-2025-31486漏洞的检测，请及时更新TDA产品的特征库到最新版本。规则编号：106065523，规则名称：Vite任意文件读取漏洞(CVE-2025-31486)。  
  
  
更新方式如下：  
  
TDA产品在线更新方法：登录系统-》系统管理-》系统升级-》特征码更新；  
  
TDA产品离线升级PTN包下载链接如下：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbGNYXVa2Ric7T7qj71VIzqAPlEzlz1jFYCwo0Y9xmsqUyMBCD4ib8pAg1TbQFAYWb6lYK2agurRy6Tw/640?wx_fmt=png "")  
  
详细下载地址请后台咨询  
  
  
**修复建议**  
  
  
  
目前厂商已发布升级补丁以修复漏洞，补丁获取链接：  
  
  
https://github.com/vitejs/vite/releases/tag/v6.2.5  
  
  
**参考链接**  
  
  
  
- https://github.com/vitejs/vite/security/advisories/GHSA-xcj6-pq6g-qj4x  
  
- https://github.com/vitejs/vite/blob/037f801075ec35bb6e52145d659f71a23813c48f/packages/vite/src/node/plugins/asset.ts#L285-L290  
  
- https://github.com/vitejs/vite/commit/62d7e81ee189d65899bb65f3263ddbd85247b647  
  
  
  
  
本文发布的补丁下载链接均源自各原厂官方网站。尽管我们努力确保官方资源的安全性，但在互联网环境中，文件下载仍存在潜在风险。为保障您的设备安全与数据隐私，敬请您在点击下载前谨慎核实其安全性和可信度。  
  
  
  
  
了解亚信安全，请点击  
**“阅读原文”**  
  
