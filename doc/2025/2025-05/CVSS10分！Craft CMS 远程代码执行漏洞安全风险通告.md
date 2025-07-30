#  CVSS10分！Craft CMS 远程代码执行漏洞安全风险通告   
应急响应中心  亚信安全   2025-05-08 10:09  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iczzp36h0nbFEE5em0TrG0jibKI3MtVYpPdDUPicxnGCXOBDwgsvMnD944ib2pA2m9oKz8yj3iavnibkly5FtnWnJv6g/640?wx_fmt=jpeg "")  
  
  
今日，亚信安全CERT监控到安全社区研究人员发布安全通告，Craft CMS 存在一个远程代码执行漏洞，编号为 CVE-2025-32432。该漏洞源于Craft CMS处理用户输入不当，攻击者可以利用Http请求发送恶意代码，服务器将其执行，从而改变系统状态或获取敏感信息。  
  
  
目前官方已发布安全更新，亚信安全CERT建议受影响的客户尽快升级至最新版本。  
  
  
Craft CMS 是一款灵活且用户友好的内容管理系统（CMS），广泛应用于创建定制化的数字体验，支持网页及其他平台的内容管理。它允许用户方便地编辑和发布内容，适用于从小型博客到大型企业网站的各种项目。  
  
  
**漏洞编号、类型、等级和评分**  
  
  
  
- CVE-2025-32432  
  
- 远程代码执行漏洞  
  
- 紧急  
  
- CVSS3.0：10分  
  
- CVSS2.0：9.7分  
  
  
  
  
**漏洞状态**  
  
  
  
<table><tbody style="box-sizing: border-box;"><tr style="box-sizing: border-box;"><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(145, 145, 145);box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="text-align: justify;padding: 0px 5px;font-size: 14px;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="text-align: center;white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;">细节</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(145, 145, 145);box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;">PoC</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(145, 145, 145);box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;">EXP</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(145, 145, 145);box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;">在野利用</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(145, 145, 145);box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;">复现情况</strong></p></section></section></td></tr><tr style="box-sizing: border-box;"><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(62, 62, 62);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">公开</p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(62, 62, 62);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">公开</p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(62, 62, 62);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">公开</p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(62, 62, 62);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">未发现</p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(62, 62, 62);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">未复现</p></section></section></td></tr></tbody></table>  
  
  
**受影响版本**  
  
  
  
- 3.0.0-RC1 <= Craft CMS <= 3.9.14  
  
- 4.0.0-RC1 <= Craft CMS <= 4.14.14  
  
- 5.0.0-RC1 <= Craft CMS <= 5.6.16  
  
  
  
  
**产品解决方案**  
  
  
  
目前亚信安全怒狮引擎已第一时间新增了检测规则，支持CVE-2025-32432漏洞的检测，请及时更新TDA、AE产品的特征库到最新版本。规则编号：106065940，规则名称：Craft CMS 远程代码执行漏洞(CVE-2025-32432)。  
  
  
更新方式如下：  
  
  
TDA产品在线更新方法：登录系统-》系统管理-》系统升级-》特征码更新；  
  
AE产品在线更新方法：登录系统-》管理-》更新-》特征码更新。  
  
TDA、AE产品离线升级PTN包下载链接如下：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbFEE5em0TrG0jibKI3MtVYpPyhFdcz0ibvZucxOrlUicNX1f7H3icWPD6xspoYicEerHiaxmmEvda1dpdxQ/640?wx_fmt=png "")  
  
详细下载地址请后台咨询  
  
  
**修复建议**  
  
  
  
目前厂商已发布升级补丁以修复漏洞，补丁获取链接：  
  
  
https://github.com/craftcms/cms/releases/tag/5.7.4  
  
  
**参考链接**  
  
  
  
- https://sensepost.com/blog/2025/investigating-an-in-the-wild-campaign-using-rce-in-craftcms/  
  
- https://github.com/craftcms/cms/blob/3.x/CHANGELOG.md#3915---2025-04-10-critical  
  
- https://github.com/craftcms/cms/blob/4.x/CHANGELOG.md#41415---2025-04-10-critical  
  
- https://github.com/craftcms/cms/blob/5.x/CHANGELOG.md#5617---2025-04-10-critical  
  
- https://github.com/craftcms/cms/commit/e1c85441fa47eeb7c688c2053f25419bc0547b47  
  
- https://github.com/craftcms/cms/security/advisories/GHSA-f3gw-9ww9-jmc3  
  
  
  
  
本文发布的补丁下载链接均源自各原厂官方网站。尽管我们努力确保官方资源的安全性，但在互联网环境中，文件下载仍存在潜在风险。为保障您的设备安全与数据隐私，敬请您在点击下载前谨慎核实其安全性和可信度。  
  
  
  
  
了解亚信安全，请点击  
**“阅读原文”**  
  
