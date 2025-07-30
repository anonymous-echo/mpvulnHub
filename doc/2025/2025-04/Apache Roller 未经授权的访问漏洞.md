#  Apache Roller 未经授权的访问漏洞   
 网安百色   2025-04-16 11:37  
  
   
   
![图片](https://mmbiz.qpic.cn/mmbiz_png/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vK9ZGS15PBzhF8gRBMk6V7TXMVsSxyqn3vpLuXTg82nHzLRYicg7QtVJQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们吧~  
  
在 Apache Roller 中发现了一个严重的安全漏洞，允许攻击者在更改密码后保持对博客系统的未经授权的访问。  
  
漏洞 CVE-2025-24859 已获得 CVSS v4 的最高评分 10，表明受影响的系统面临严重风险。  
  
该安全漏洞源于 Apache Roller 版本 1.0.0 到 6.1.4 中的基本会话管理问题。  
  
当用户或管理员更改帐户密码时，系统无法按预期使现有活动会话失效。这种关键监督意味着即使在凭据更改后，所有预先存在的会话仍保持完整功能。  
  
“在 6.1.5 版本之前的 Apache Roller 中存在会话管理漏洞，其中活动用户会话在更改密码后无法正确失效，”公告中写道。  
## Apache Roller 漏洞  
  
“即使在更改密码后，这也允许通过旧会话继续访问应用程序，如果凭据被盗用，则可能会启用未经授权的访问。”  
  
安全研究员 Haining Meng 发现了该漏洞，该漏洞已被确认会影响所有尚未更新到最新版本的 Apache Roller 安装。  
  
对于组织博客部署，其影响尤其令人担忧，因为凭据泄露是常见的第一响应触发因素。  
  
漏洞摘要如下：  
  
<table><tbody><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><strong msttexthash="14330498" msthash="70" style="box-sizing: border-box;font-weight: bold;"><span leaf=""><span textstyle="" style="color: rgb(0, 0, 0);">风险因素</span></span></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><strong msttexthash="3259074" msthash="71" style="box-sizing: border-box;font-weight: bold;"><span leaf=""><span textstyle="" style="color: rgb(0, 0, 0);">详</span></span></strong></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><section><span leaf=""><span textstyle="" style="color: rgb(0, 0, 0);">受影响的产品</span></span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><section><span leaf=""><span textstyle="" style="color: rgb(0, 0, 0);">Apache Roller 1.0.0 &lt; 6.1.5</span></span></section></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><section><span leaf=""><span textstyle="" style="color: rgb(0, 0, 0);">冲击</span></span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><section><span leaf=""><span textstyle="" style="color: rgb(0, 0, 0);">更改密码后通过活动会话进行未经授权的访问;会话劫持风险;机密性、完整性和可用性都处于高风险中。</span></span></section></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font mstmutation="1" msttexthash="17124536" msthash="76" style="box-sizing: border-box;"><span leaf=""><span textstyle="" style="color: rgb(0, 0, 0);">利用先决条件</span></span></font><section><span leaf=""><br/></span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><section><span leaf=""><span textstyle="" style="color: rgb(0, 0, 0);">在更改密码之前访问有效会话;无需用户交互;攻击复杂性低。</span></span></section></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><section><span leaf=""><span textstyle="" style="color: rgb(0, 0, 0);">CVSS 3.1 分数</span></span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><section><span leaf=""><span textstyle="" style="color: rgb(0, 0, 0);">10.0（严重）</span></span></section></td></tr></tbody></table>  
该漏洞造成了标准安全实践失效的场景。  
  
Apache Roller 是一个基于 Java 的博客平台，作为 Web 应用程序在 Java EE 服务器上运行，广泛用于个人博客和企业级发布系统。  
  
它的多用户功能使其在组织部署中很受欢迎，可能会放大此漏洞的影响。Apache 软件基金会已经解决了与披露同时发布的 Apache Roller 6.1.5 中的漏洞。  
  
修补版本实施了适当的集中式会话管理，确保在更改密码或禁用用户帐户时立即终止所有活动会话。  
  
强烈建议 Apache Roller 用户尽快  
更新到  
 6.1.5 版本，以降低此安全风险。  
  
对于无法立即更新的组织，安全专家建议实施额外的保护层：  
- 通过应用程序日志密切监控所有会话活动  
  
- 实施网络级控制以限制对 Roller 实例的访问  
  
- 如果受影响的系统包含敏感信息，请考虑暂时禁用受影响的系统  
  
这不是影响 Apache Roller 的第一个安全问题。以前的漏洞包括 5.0.2 之前版本中通过 OGNL 注入实现的远程代码执行缺陷 （CVE-2013-4212），以及允许在版本 5.0.3 中泄露文件的 XML 外部实体  
注入漏洞  
 （CVE-2014-0030）。  
  
由于该漏洞的严重性以及攻击者很容易利用该漏洞对系统进行初始访问，因此敦促管理员优先考虑此更新。  
  
**免责声明**  
：  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
