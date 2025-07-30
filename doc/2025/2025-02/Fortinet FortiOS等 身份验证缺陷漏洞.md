#  Fortinet FortiOS等 身份验证缺陷漏洞   
 上汽集团网络安全应急响应中心   2025-02-15 15:56  
  
**漏洞情报**  
  
  
  
  
  
**Fortinet FortiOS等 身份验证缺陷漏洞**  
  
  
**【 漏洞编号 】**  
  
CVE-2024-55591  
  
  
**【 情报等级 】**  
  
**高危**  
  
  
**【 漏洞描述 】**  
  
360漏洞云监测到一则Fortinet-Fortios组件存在身份验证漏洞的信息，FortiOS和FortiProxy存在一个使用替代路径或通道的身份验证绕过漏洞，未经授权的攻击者可以通过对Node.js websocket模块的伪造请求获取超级管理员权限。Fortinet 已针对此漏洞发布安全更新，建议受影响用户及时升级到安全版本。  
  
  
**【 影响产品 】**  
  
<table><tbody><tr><td colspan="1" rowspan="1" style="border-color: rgb(255, 255, 255);background-color: rgb(231, 231, 231);padding: 6px;" width="99.0000%"><section style="text-align: center;font-size: 14px;"><p>Forti 操作系统,fortios,FortiProxy,FortiOS,fortinet fortiproxy,Fortinet Fortiproxy7.0.0&gt;=&amp;&amp;&lt;=7.0.16,7.2.0&gt;=&amp;&amp;&lt;=7.2.12,7.0.0&gt;=&amp;&amp;&lt;=7.0.19</p></section></td></tr></tbody></table>  
  
**【 解决方案与修复建议 】**  
  
针对此漏洞，官方已经发布了漏洞修复版本，请立即更新到**安全版本：**  
  
Fortinet FortiOS  >= 7.0.17  
  
Fortinet FortiProxy >= 7.0.20  
  
Fortinet  FortiProxy >= 7.2.13  
  
**参考链接：**  
  
https://fortiguard.fortinet.com/psirt/FG-IR-24-535  
   
  
安装前，请确保备份所有关键数据，并按照官方指南进行操作。安装后，进行全面测试以验证漏洞已被彻底修复，并确保系统其他功能正常运行。  
  
