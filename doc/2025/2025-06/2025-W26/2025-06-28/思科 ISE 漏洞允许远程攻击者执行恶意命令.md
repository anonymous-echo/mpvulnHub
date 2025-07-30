> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI0NzE4ODk1Mw==&mid=2652096358&idx=2&sn=0bdd6716511352a19ae6a051668361dd

#  思科 ISE 漏洞允许远程攻击者执行恶意命令  
 网安百色   2025-06-28 11:40  
  
思科发布了紧急安全补丁，解决了其身份服务引擎 （ISE） 和 ISE 被动身份连接器 （ISE-PIC） 平台中的两个关键漏洞。  
  
这些缺陷都具有 CVSS 最高严重性评分 10.0，可能允许未经身份验证的远程攻击者以 root 用户身份执行恶意命令，从而有效地完全控制受影响的系统。  
## 漏洞的性质  
  
这些漏洞被跟踪为 CVE-2025-20281 和 CVE-2025-20282，以思科 ISE 和 ISE-PIC 中的特定 API 为目标。  
  
两者都可以在没有任何有效凭证的情况下被利用，这使得它们对于依赖这些平台进行网络访问控制和安全策略实施的组织来说特别危险。  
  
**CVE-2025-20281：API 输入验证缺陷**  
  
此漏洞会影响思科 ISE 和 ISE-PIC 版本 3.3 及更高版本。它是由于对特定 API 中用户提供的输入的验证不足而引起的。  
  
攻击者可以通过发送构建的 API 请求来利用此缺陷，使他们能够以 root 权限在底层作系统上执行任意代码。  
  
无需身份验证，这意味着任何远程攻击者都有可能获得对设备的完全控制权。  
  
**CVE-2025-20282：任意文件上传和执行**  
  
此漏洞仅影响思科 ISE 和 ISE-PIC 版本 3.4，其源于内部 API 中缺少文件验证检查。  
  
攻击者可以将恶意文件上传到特权目录，并以 root 身份执行它们，同样不需要身份验证。  
  
这可能允许攻击者安装恶意软件、创建后门或进一步破坏网络。  
  
**影响和受影响的版本**  
  
这两个漏洞都被认为是关键和独立的;利用一个缺陷不需要利用另一个缺陷，并且每个缺陷的受影响软件版本可能不同。  
  
目前没有关于这些漏洞被在野外利用的报告，但由于成功利用这些漏洞会授予高权限级别，因此风险很大。  
- **CVE-2025-20281 漏洞：**  
ISE 和 ISE-PIC 3.3 及更高版本（在 3.3 补丁 6 和 3.4 补丁 2 中修复）  
  
- **CVE-2025-20282 漏洞：**  
仅限 ISE 和 ISE-PIC 3.4（在 3.4 补丁 2 中修复）  
  
- ISE 和 ISE-PIC 3.2 及更早版本不受影响。  
  
Cisco 已确认没有针对这些漏洞的解决方法。唯一的缓解措施是立即应用提供的软件更新。  
  
强烈建议管理员立即审查其部署并修补所有受影响的系统，以防止潜在的漏洞利用。  
  
<table><thead><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong msttexthash="7326319" msthash="54" style="box-sizing: border-box;font-weight: bold;"><span leaf="">CVE 编号</span></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong msttexthash="6157333" msthash="55" style="box-sizing: border-box;font-weight: bold;"><span leaf="">描述</span></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong msttexthash="19282198" msthash="56" style="box-sizing: border-box;font-weight: bold;"><span leaf="">受影响的版本</span></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong msttexthash="8427770" msthash="57" style="box-sizing: border-box;font-weight: bold;"><span leaf="">CVSS 评分</span></strong></td></tr></thead><tbody><tr style="box-sizing: border-box;background-color: rgb(240, 240, 240);"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">漏洞：CVE-2025-20281</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">API 输入验证缺陷支持未经身份验证的 RCE</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">ISE/ISE-PIC 3.3 及更高版本</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">10.0</span></section></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">漏洞：CVE-2025-20282</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">通过内部 API 上传和执行任意文件</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">仅限 ISE/ISE-PIC 3.4</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">10.0</span></section></td></tr></tbody></table>  
使用思科 ISE 或 ISE-PIC 的组织应：  
- 立即在其环境中识别受影响的版本。  
  
- 按照 Cisco 的建议应用最新的补丁。  
  
- 监控 Cisco 的安全公告以获取更新。  
  
如果不采取行动，可能会使关键网络基础设施暴露在攻击者的完全远程接管之下。  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
