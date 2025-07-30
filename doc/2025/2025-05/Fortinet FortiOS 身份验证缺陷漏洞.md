#  Fortinet FortiOS 身份验证缺陷漏洞   
 上汽集团网络安全应急响应中心   2025-05-20 15:55  
  
漏洞情报  
  
  
  
  
  
**Fortinet FortiOS 身份验证缺陷漏洞**  
  
  
**【 漏洞编号 】**  
  
CVE-2025-22252  
  
  
**【 情报等级 】**  
  
**高危**  
  
  
**【 漏洞描述 】**  
  
360漏洞云监测到 Fortinet  发布安全公告，披露了一处 Fortinet FortiOS 身份认证绕过漏洞，该漏洞影响 FortiOS、FortiProxy 和 FortiSwitchManager 等多种产品。此漏洞属于关键功能缺失认证漏洞，在配置使用 TACACS + 与 ASCII 认证的系统中出现，攻击者若知晓现有管理员账户，就可能通过认证绕过以管理员身份访问设备。Fortinet 已推出关键安全更新以解决此漏洞，建议受影响用户及时升级到安全版本。  
  
  
**【 影响产品 】**  
  
<table><tbody><tr style="box-sizing: border-box;"><td data-colwidth="99.0000%" width="99.0000%" style="border-width: 1px;border-color: rgb(255, 255, 255);border-style: solid;background-color: rgb(231, 231, 231);padding: 6px;box-sizing: border-box;"><section style="text-align: center;font-size: 14px;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">fortios,FortiSwitchManager,fortiswitchmanager,FortiOS,fortinet fortiproxy,Fortinet Fortiproxy=7.6.0,=7.2.5,&gt;=7.4.4&amp;&amp;&lt;=7.4.6,&gt;=7.6.0&amp;&amp;&lt;=7.6.1</span></p></section></td></tr></tbody></table>  
  
**【 解决方案与修复建议 】**  
  
针对此漏洞，官方已经发布了漏洞修复版本，请立即更新到**安全版本：**  
  
Fortinet FortiOS  >= 7.6.1  
  
Fortinet FortiOS  >= 7.4.7  
  
Fortinet FortiProxy >= 7.6.2  
  
Fortinet  FortiSwitchManager >= 7.2.6  
  
**参考链接：**  
  
https://docs.fortinet.com/upgrade-tool  
  
安装前，请确保备份所有关键数据，并按照官方指南进行操作。安装后，进行全面测试以验证漏洞已被彻底修复，并确保系统其他功能正常运行。  
  
