> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI0NzE4ODk1Mw==&mid=2652096374&idx=1&sn=aa9233641ab5de3a299f4d20e0b510ea

#  多个 PHP 支持 SQLi 和 DoS 攻击漏洞  
 网安百色   2025-07-06 11:31  
  
安全研究人员披露了 PHP（一种流行的服务器端脚本语言）中的两个重大漏洞，这些漏洞可能允许攻击者发起 SQL 注入 （SQLi） 和拒绝服务 （DoS） 攻击。  
  
根据该报告，敦促管理员和开发人员立即更新他们的 PHP 安装以减轻这些风险。  
  
<table><thead><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong msttexthash="7326319" msthash="35" style="box-sizing: border-box;font-weight: bold;"><span leaf="">CVE 编号</span></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong msttexthash="3995329" msthash="36" style="box-sizing: border-box;font-weight: bold;"><span leaf="">元件</span></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong msttexthash="4044495" msthash="37" style="box-sizing: border-box;font-weight: bold;"><span leaf="">严厉</span></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong msttexthash="19282198" msthash="38" style="box-sizing: border-box;font-weight: bold;"><span leaf="">受影响的版本</span></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong msttexthash="12349922" msthash="39" style="box-sizing: border-box;font-weight: bold;"><span leaf="">修补版本</span></strong></td></tr></thead><tbody><tr style="box-sizing: border-box;background-color: rgb(240, 240, 240);"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">CVE-2025-1735漏洞</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">pgsql 扩展</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">温和</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">&lt;8.1.33、&lt;8.2.29、&lt;8.3.23、&lt;8.4.10</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">8.1.33, 8.2.29, 8.3.23, 8.4.10</span></section></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">漏洞：CVE-2025-6491</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">SOAP 扩展</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">温和</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">&lt;8.1.33、&lt;8.2.29、&lt;8.3.23、&lt;8.4.10</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">8.1.33, 8.2.29, 8.3.23, 8.4.10</span></section></td></tr></tbody></table>## 漏洞概述  
  
**通过 pgsql 扩展进行1. SQL注入和崩溃 （CVE-2025-1735）**  
  
已在 PHP 的 pgsql 扩展中发现一个中等严重性的缺陷，该扩展用于与 PostgreSQL 数据库交互。  
  
出现此漏洞的原因是，该扩展在转义用户提供的数据期间未正确检查错误。  
  
具体来说，PHP 无法将错误参数传递给 PQescapeStringConn（） 函数，从而阻止它报告编码错误。  
  
此外，对 PQescapeIdentifier（） 的多次调用不会检查 NULL 返回，这可能会导致应用程序崩溃或未定义的行为。  
  
**冲击：**  
- **SQL 注入：**  
攻击者可能会利用此漏洞注入恶意 SQL 查询，从而可能获得对敏感数据未经授权的访问或纵数据库。  
  
- **拒绝服务：**  
错误处理不当会导致应用程序崩溃，从而中断服务可用性。  
  
**受影响的版本：**  
- PHP < 8.1.33  
  
- PHP < 8.2.29  
  
- PHP < 8.3.23  
  
- PHP < 8.4.10  
  
**修补版本：**  
- PHP 8.1.33、8.2.29、8.3.23、8.4.10 及更高版本  
  
**2. SOAP 扩展中的 NULL 指针取消引用 （CVE-2025-6491）**  
  
第二个漏洞会影响 PHP SOAP 扩展。如果使用大于 2GB 的完全限定名称创建 SoapVar 实例，则可触发 NULL 指针取消引用，从而导致分段错误和进程崩溃。  
  
这是由于 2.13 之前的 libxml2 版本存在限制，无法处理非常大的 XML 命名空间前缀。  
  
攻击者可以通过发送特制的 SOAP 请求来利用此漏洞，从而导致可靠的 DoS 情况。  
  
**冲击：**  
- **拒绝服务：**  
任何使用 SOAP 扩展的 PHP 应用程序都有被远程攻击者崩溃的风险，从而导致服务中断。  
  
**受影响的版本：**  
- PHP < 8.1.33  
  
- PHP < 8.2.29  
  
- PHP < 8.3.23  
  
- PHP < 8.4.10  
  
**修补版本：**  
- PHP 8.1.33、8.2.29、8.3.23、8.4.10 及更高版本  
  
- **立即更新：**  
将 PHP 升级到上面列出的最新修补版本。  
  
- **审计应用程序：**  
检查代码中是否存在不安全的数据库转义和 SOAP 输入处理。  
  
- **监控系统：**  
注意可能表明漏洞利用尝试的异常崩溃或服务中断。  
  
管理员应紧急处理这些漏洞，因为 SQLi 和 DoS 攻击都会对数据安全和服务可靠性造成严重后果。  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
