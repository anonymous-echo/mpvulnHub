> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI0MDY1MDU4MQ==&mid=2247583318&idx=2&sn=0ba427effcd76b16d408c7d3116a319a

#  Sitecore内容管理系统漏洞链始于在设置硬编码密码时的疏漏  
胡金鱼  嘶吼专业版   2025-06-26 06:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
Sitecore Experience Platform （XP）漏洞链允许攻击者在没有身份验证的情况下执行远程代码执行（RCE）来破坏和劫持服务器。  
  
Sitecore是一个流行的企业CMS，用于企业创建和管理跨网站和数字媒体的内容。由watchtower研究人员发现，近期披露的预认证RCE链包含三个不同的漏洞。它取决于内部用户（sitecore\ServicesAPI）的存在，其硬编码密码设置为“b”，使其易于劫持。  
  
这个内置用户不是管理员，也没有分配角色。然而，研究人员仍然可以使用它通过另一个登录路径（/sitecore/admin）进行身份验证，因为sitecore的仅后端登录检查在非核心数据库上下文中被绕过。  
  
结果是一个有效的".AspNetCookies"会话，使攻击者能够获得通过IIS级授权但不受Sitecore角色检查保护的内部端点的已认证访问权限。  
  
有了这个最初的立足点，攻击者就可以利用第二个漏洞，即Sitecore上传向导中的Zip Slip漏洞。  
  
正如watchtower解释的那样，通过向导上传的ZIP文件可能包含恶意文件路径，如/\/../webshell.aspx。由于路径清理不足和Sitecore映射路径的方式，这导致将任意文件写入web浏览器，甚至不知道完整的系统路径。这使得攻击者可以上传webshell并执行远程代码。  
  
当安装了Sitecore PowerShell Extensions （SPE）模块（通常与SXA捆绑在一起）时，第三个漏洞就会被利用。  
  
此漏洞允许攻击者将任意文件上传到攻击者指定的路径，完全绕过扩展名或位置限制，并提供通往可靠RCE的更简单路径。  
# 影响和风险  
  
watchtower报告的三个漏洞影响了Sitecore XP 10.1到10.4版本。WatchTowr的扫描显示有超过22000个公开暴露的Sitecore实例，这突显出一个显著的攻击面，尽管并非所有实例都一定存在漏洞。  
  
针对这些问题的补丁于2025年5月发布，但CVE id和技术细节要到2025年6月17日才能发布，以便客户有时间更新。  
  
Sitecore被部署在数千个环境中，包括银行、航空公司和全球企业，影响广泛。  
Sitecore表示他们  
已经全程运行了。如果使用Sitecore，在攻击者不可避免地逆向工程修复之前，应立即旋转凭据并进行修补。  
  
截至目前，尚无公开证据表明存在野外利用。然而，watchTowr的技术博客包含了足够的细节来构建一个完整的工作漏洞，因此对于避免滥用的问题仍旧迫在眉睫。  
  
参考及来源：  
https://www.bleepingcomputer.com/news/security/sitecore-cms-exploit-chain-starts-with-hardcoded-b-password/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29hPsJjk0ZibibIrXiaUpqbRgjqcwJicOcibJItwAw5Y6gDdCpFibr27ZqZwjlFO2D1HS6vqCGCXaacI9Dw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29hPsJjk0ZibibIrXiaUpqbRgjMvibkUnC37J2mPJbd6sexqsQEyvibWKcGOArbXHh54Ffsib1GibEAibucWg/640?wx_fmt=png&from=appmsg "")  
  
  
