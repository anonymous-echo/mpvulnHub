#  Apache James 未授权 输入验证不当漏洞 可导致拒绝服务   
 上汽集团网络安全应急响应中心   2025-02-14 15:55  
  
**漏洞情报**  
  
  
  
  
  
**Apache James 未授权 输入验证不当漏洞 可导致拒绝服务**  
  
  
**【 漏洞编号 】**  
  
CVE-2024-37358  
  
  
**【 情报等级 】**  
  
**高危**  
  
  
**【 漏洞描述 】**  
  
360漏洞云监测到Apache James发布安全公告，其中公开了一个输入验证不当漏洞，该漏洞与CVE-2024-34055类似，Apache James在IMAP字面量的滥用方面存在输入验证不当漏洞，无论是否经过身份验证的用户都可以利用这一点，这可能导致无限制的内存分配和非常长的计算，导致拒绝服务攻击。  
  
  
**【 影响产品 】**  
  
<table><tbody><tr><td colspan="1" rowspan="1" style="border-color: rgb(255, 255, 255);background-color: rgb(231, 231, 231);padding: 6px;" width="99.0000%"><section style="text-align: center;font-size: 14px;"><p>apache james 邮件服务器,Apache James 邮件服务器,apache james,apache james james,james,apache jamesjames,Apache James James,Apache James,Apache JamesJames&gt;=3.8.0&amp;&amp;&lt;3.8.2,&lt;3.7.6</p></section></td></tr></tbody></table>  
  
**【 解决方案与修复建议 】**  
  
厂商已发布补丁修复漏洞，建议下载相关补丁或联系厂商获取相关支持尽快更新至安全版本。  
  
**安全版本：**  
  
Apache James >= 3.7.6  
  
Apache James >= 3.8.2  
  
与此同时，请做好资产自查以及预防工作，以免遭受黑客攻击。  
  
