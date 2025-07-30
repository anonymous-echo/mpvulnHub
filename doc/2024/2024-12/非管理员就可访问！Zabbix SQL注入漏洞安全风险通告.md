#  非管理员就可访问！Zabbix SQL注入漏洞安全风险通告   
应急响应中心  亚信安全   2024-12-02 09:34  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iczzp36h0nbEtdMyHkXbicqic26ib7BybdH7KUZRS0niau6sUXDIuzf5nF1eYQJLPk1yNSqr4DZkhCdc6sbVpycNnQQ/640?wx_fmt=jpeg "")  
  
  
今日，亚信安全CERT监控到安全社区研究人员发布安全通告，在Zabbix中披露了一个SQL注入漏洞（CVE-2024-42327）。Zabbix前端的CUser类中存在一个SQL注入漏洞，具体位于addRelatedObjects函数中。该函数由CUser.get函数调用，任何具有API访问权限的用户都可以访问CUser.get函数。此漏洞可以被默认的非管理员用户或任何拥有API访问权限的用户利用。  
  
  
**目前官方已有可更新版本，亚信安全CERT建议受影响用户升级至最新版本。**  
  
  
Zabbix 是一个开源的、企业级的分布式监控解决方案，用于监控各种 IT 资源，包括服务器、网络设备、应用程序和服务。它提供实时监控、数据收集、可视化、警报和报告功能，帮助用户全面了解其 IT 基础架构的运行状况。  
  
  
  
  
**漏洞编号、类型、等级**  
  
  
  
- CVE-2024-42327  
  
- SQL注入漏洞  
  
- 高危  
  
  
  
  
**漏洞状态**  
  
  
  
<table><tbody style="box-sizing: border-box;"><tr style="box-sizing: border-box;"><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(145, 145, 145);box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="text-align: justify;padding: 0px 5px;font-size: 14px;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="text-align: center;white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;">细节</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(145, 145, 145);box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;">PoC</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(145, 145, 145);box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;">EXP</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(145, 145, 145);box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;">在野利用</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(145, 145, 145);box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;">复现情况</strong></p></section></section></td></tr><tr style="box-sizing: border-box;"><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(62, 62, 62);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">已公开</p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(62, 62, 62);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">已公开</p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(62, 62, 62);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">未公开</p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(62, 62, 62);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">未发现</p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(62, 62, 62);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">未复现</p></section></section></td></tr></tbody></table>  
  
  
**受影响版本**  
  
  
  
-  6.0.0 <= Zabbix <= 6.0.31  
  
-  6.4.0 <= Zabbix <= 6.4.16  
  
-  Zabbix 7.0.0  
  
  
  
  
**产品解决方案**  
  
  
  
目前亚信安全怒狮引擎已第一时间新增了检测规则，支持CVE-2024-42327漏洞的检测，请及时更新TDA、AE产品的特征库到最新版本。**规则编号：106064264，规则名称：  Zabbix SQL注入漏洞(CVE-2024-42327)。**  
  
  
更新方式如下：  
  
  
- TDA产品在线更新方法：登录系统-》系统管理-》系统升级-》特征码更新；  
  
- AE产品在线更新方法：登录系统-》管理-》更新-》特征码更新。  
  
- TDA、AE产品离线升级PTN包下载链接如下：  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbEtdMyHkXbicqic26ib7BybdH7lwnUicwUHt2BpA5yD0CSIMdT0SCBS1uNjaIcFeJUF251PayKZBSmxJw/640?wx_fmt=png "")  
  
（后台私信下载离线升级PTN包）  
  
  
**修复建议**  
  
  
  
目前，官方已发布相关修复公告，建议受影响的用户将Zabbix更新到最新版本或者到官网查询具体补丁信息。  
  
  
https://www.zabbix.com/download  
  
  
**参考链接**  
  
  
  
- https://nvd.nist.gov/vuln/detail/CVE-2024-42327  
  
- https://github.com/zetraxz/CVE-2024-42327  
  
- https://support.zabbix.com/browse/ZBX-25623  
  
  
  
  
本文发布的补丁下载链接均源自各原厂官方网站。尽管我们努力确保官方资源的安全性，但在互联网环境中，文件下载仍存在潜在风险。为保障您的设备安全与数据隐私，敬请您在点击下载前谨慎核实其安全性和可信度。  
  
  
  
  
了解亚信安全，请点击  
**“阅读原文”**  
  
