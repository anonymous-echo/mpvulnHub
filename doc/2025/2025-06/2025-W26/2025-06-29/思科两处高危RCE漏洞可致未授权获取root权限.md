> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651324021&idx=3&sn=758ad58f02fcc6eda8eddbd10a0dcc4c

#  思科两处高危RCE漏洞可致未授权获取root权限  
 FreeBuf   2025-06-29 11:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibwMDy3Dr0fhibAvqRneBzRnWkFN561TnlzCSFicibT286pBU2AqMduOazeskQiaX9uSFAYoQiaJJyicicbg/640?wx_fmt=other&from=appmsg "")  
  
  
思科系统公司敦促企业安全官（CSO）立即修补其身份服务引擎（Identity Services Engine，ISE）和被动身份连接器（ISE-PIC）中的多个漏洞。这些漏洞可能使未经身份验证的远程攻击者能够以_root_用户身份在底层操作系统上执行命令。  
  
  
这两个漏洞的根源在于应用程序编程接口（API）存在缺陷。SANS研究所云渗透测试高级讲师Moses Frost强调："必须严肃对待此漏洞。根据我的网络评估经验，许多核心网络设备缺乏必要的补丁和安全加固措施。我曾发现思科ISE部署中存在普通用户可自由访问所有端口（包括管理页面）的情况。攻击者很可能已获得网络内部的横向移动能力。尽管这不符合思科的最佳实践，但许多生产环境确实开放了这些API接口。如果您的系统正在运行ISE，请立即打补丁。"  
  
  
**Part01**  
### 风险等级评估  
  
  
思科ISE通常用作无线认证系统，Frost指出这类系统往往包含访客网络门户，并可能作为高信任度系统与微软Active Directory集成。它还被用于路由器、交换机、防火墙等网络设备管理层的访问认证，同时可作为网络访问控制（NAC）产品使用。  
  
  
DeepCove网络安全公司首席安全架构师Kellman Meghu评价："就影响范围而言，这可能是我见过最严重的漏洞之一。它为未经认证的远程攻击者提供了获取最高权限的途径，严重程度几乎无以复加。"  
  
  
加拿大事件响应公司Digital Defence首席执行官Robert Beggs表示："这对那些未能执行适当安全防护的企业最为致命。"他指的是那些缺乏网络组件硬件清单、不关注厂商漏洞公告或未购买系统升级许可的企业。  
  
  
Beggs特别提醒，虽然思科已发布补丁，但不会自动推送，管理员需按思科流程手动获取。由于ISE是网络访问（有线、无线、VPN及访客接入）的守门人，攻击者获取root权限后将能窃取所有网段的完整凭证。  
  
  
他在给CSO的邮件中警告："目前尚未发现野外利用报告。但这些漏洞属于零交互攻击，可能完全不被察觉。由于无需认证，必须尽快安装补丁——攻击代码可能即将出现（如果尚未被使用）。"  
  
  
**Part02**  
### 关键漏洞详情  
  
  
思科评定为"严重"级别的漏洞（CVSS评分均为10.0分）包括：  
  
  
**CVE-2025-20281：影响3.3及以上版本的思科ISE和ISE-PIC，与设备配置无关。攻击者无需有效凭证即可利用该API漏洞，其成因在于对用户输入验证不足。通过提交特制API请求，攻击者可获取受影响设备的_root_权限；**  
  
****  
**CVE-2025-20282：仅影响3.4版本的思科ISE和ISE-PIC。该API漏洞源于系统未对上传文件进行验证，导致恶意文件可存入特权目录。攻击者通过上传特制文件，能在系统上存储恶意文件并执行任意代码或获取_root_权限。**  
  
  
**Part03**  
### 无临时解决方案  
  
  
思科强调这两个漏洞相互独立，利用其中一个无需依赖另一个，且受影响版本可能不重叠。目前除安装补丁外，没有其他缓解措施。  
  
  
Frost指出："API的致命缺陷在于标准Web应用漏洞同样适用。更糟糕的是，十年前已被框架解决的旧漏洞正在API中重现。如果我现在领导开发团队，会重新审查OWASP（开放Web应用安全项目）历史漏洞清单，确保已修复的漏洞类别（如未认证端点或批量赋值问题）不会重现。"  
  
  
**Part04**  
### API安全防护建议  
  
  
作为连接应用和共享数据的核心通道，API在移动应用、SaaS和Web应用中至关重要。OWASP指出，API天然暴露应用逻辑和敏感数据（如个人身份信息），若未采用安全编码将成攻击目标。其API安全项目建议开发者防范以下风险：  
  
- 对象级授权缺陷：  
所有通过用户ID访问数据源的功能都应实施授权检查；  
  
- 认证机制缺陷：  
确保开发者掌握所有API认证流程，API密钥仅用于客户端认证而非用户认证，OAuth同样不适用于认证场景；  
  
- 无限制的资源消耗：  
可能导致拒绝服务攻击；  
  
- 敏感业务流暴露；  
  
- 服务端请求伪造（SSRF）：  
API获取远程资源时未验证用户提供的URI，即使有防火墙/VPN保护，攻击者仍能诱导应用向非预期目标发送恶意请求；  
  
- 安全配置错误：  
复杂的API配置体系若未遵循最佳实践，会为各类攻击敞开大门。  
  
OWASP建议API生命周期应包含：可重复的加固流程、全栈配置审查（包括编排文件、API组件和云服务权限）、自动化环境配置评估。无论内外网API，所有通信都应采用TLS加密通道。  
  
  
**Part05**  
### 多层防御必要性  
  
  
Meghu指出，随着IT系统自动化程度提升，编码错误不可避免。安全官应部署多层验证机制，例如配置仅允许特定源API调用的Web应用防火墙（WAF）。但他同时警告，随着第三方SaaS服务激增，这些防护措施可能被附带的大量API交互削弱。  
  
  
**参考来源：**  
  
Cisco warns of critical API vulnerabilities in ISE and ISE-PIC  
  
https://www.csoonline.com/article/4013597/cisco-warns-of-critical-api-vulnerabilities-in-ise-and-ise-pic.html  
  
  
###   
###   
###   
  
**推荐阅读**  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651323665&idx=1&sn=15875d40f858538184006215073544fb&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
