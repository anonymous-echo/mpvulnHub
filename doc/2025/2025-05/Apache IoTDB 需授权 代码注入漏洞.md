#  Apache IoTDB 需授权 代码注入漏洞   
 上汽集团网络安全应急响应中心   2025-05-20 15:55  
  
漏洞情报  
  
  
  
  
  
**Apache IoTDB 需授权 代码注入漏洞**  
  
  
**【 漏洞编号 】**  
  
CVE-2024-24780,CNNVD-202505-2026  
  
  
**【 情报等级 】**  
  
**高危**  
  
  
**【 漏洞描述 】**  
  
Apache IoTDB是美国阿帕奇（Apache）基金会的一款为时间序列数据设计的集成数据管理引擎，它能够提供数据收集、存储和分析服务等。  
  
360漏洞云检测到Apache IoTDB发布安全公告，其中公开披露了一个代码注入漏洞，该漏洞源于UDF不受信任URI导致远程代码执，具有创建 UDF 权限的攻击者可以从不受信任的 URI 注册恶意函数执行任意代码。  
  
  
**【 影响产品 】**  
  
<table><tbody><tr style="box-sizing: border-box;"><td data-colwidth="99.0000%" width="99.0000%" style="border-width: 1px;border-color: rgb(255, 255, 255);border-style: solid;background-color: rgb(231, 231, 231);padding: 6px;box-sizing: border-box;"><section style="text-align: center;font-size: 14px;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">IoTDB,Iotdb,apache iotdb,iotdb,Apache IoTDB 物联网时序数据库管理系统&gt;=1.0.0&amp;&amp;&lt;1.3.4</span></p></section></td></tr></tbody></table>  
  
**【 解决方案与修复建议 】**  
  
厂商已发布补丁修复漏洞，建议下载相关补丁或联系厂商获取相关支持尽快更新至安全版本。  
  
**安全版本：**  
Apache IotDB >= 1.3.4  
  
安装前，请确保备份所有关键数据，并按照官方指南进行操作。安装后，进行全面测试以验证漏洞已被彻底修复，并确保系统其他功能正常运行。  
  
与此同时，请做好资产自查以及预防工作，以免遭受黑客攻击。  
  
