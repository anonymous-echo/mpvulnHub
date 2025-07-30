#  Cookie-Bite攻击PoC使用Chrome扩展窃取会话令牌   
胡金鱼  嘶吼专业版   2025-04-30 06:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
一种名为“Cookie-Bite”的概念验证攻击利用浏览器扩展程序从 Azure Entra ID 中窃取浏览器会话 Cookie，以绕过多因素身份验证（MFA）保护，并保持对 Microsoft 365、Outlook 和 Teams 等云服务的访问。  
  
此次攻击由 Varonis 安全研究人员设计，他们分享了一种概念验证（PoC）方法，涉及一个恶意的和一个合法的 Chrome 扩展程序。然而，窃取会话 cookie 并非新鲜事，因为信息窃取程序和中间人网络钓鱼攻击通常都会将其作为目标。  
  
虽然通过窃取 Cookie 来入侵账户并非新手段，但“Cookie-Bite”技术中恶意 Chrome 浏览器扩展程序的使用因其隐秘性和持久性而值得关注。  
# Cookie扩展攻击  
  
“Cookie-Bite”攻击由一个恶意的 Chrome 扩展程序构成，该扩展程序充当信息窃取器，专门针对 Azure Entra ID（微软基于云的身份和访问管理（IAM）服务）中的“ESTAUTH”和“ESTSAUTHPERSISTNT”这两个 Cookie。  
  
ESTAUTH 是一个临时会话令牌，表明用户已通过身份验证并完成了多因素身份验证。它在浏览器会话中有效，最长可达 24 小时，在应用程序关闭时过期。  
  
ESTSAUTHPERSISTENT 是在用户选择“保持登录状态”或 Azure 应用 KMSI 策略时创建的会话 Cookie 的持久版本，其有效期最长可达 90 天。  
  
应当注意的是，虽然此扩展程序是为针对微软的会话 Cookie 而创建的，但它可以被修改以针对其他服务，包括谷歌、Okta 和 AWS 的 Cookie。  
  
Varonis 的恶意 Chrome 扩展程序包含用于监控受害者登录事件的逻辑，监听与微软登录网址匹配的标签页更新。  
  
当登录发生时，它会读取所有作用域为“login.microsoftonline.com”的 Cookie，应用过滤以提取上述两个令牌，并通过 Google 表单将 Cookie 的 JSON 数据泄露给攻击者。  
  
“在将该扩展程序打包成 CRX 文件并上传至 VirusTotal 后，结果显示目前没有任何安全供应商将其检测为恶意程序，”Varonis 警告称。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29SJ9JUic965aOucYqfVliaUWK4fLqCVBsOmb7SYnsX5LzMG05YooL4GG2lEBBfEPtkMjwCLicTmS5Ig/640?wx_fmt=png&from=appmsg "")  
  
Chrome扩展窃取微软会话cookie  
  
如果攻击者可以访问设备，他们可以部署一个PowerShell脚本，通过Windows任务调度程序运行，在每次启动Chrome时使用开发者模式自动重新注入未签名扩展。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29SJ9JUic965aOucYqfVliaUWChPxhQh3badd8xHwMGQaGslX6wCx9JXPHcRbGufbJjV1Bp4RSqhibGw/640?wx_fmt=png&from=appmsg "")  
  
PowerShell攻击中使用的例子  
  
一旦cookie被盗，攻击者就会将其注入浏览器，就像其他被盗的cookie一样。这可以通过合法的Cookie-Editor Chrome扩展等工具来实现，该扩展允许威胁行为者将被盗的cookie导入到他们的浏览器“login.microsoftonline.com”下。  
  
刷新页面后，Azure将攻击者的会话视为完全经过身份验证，绕过MFA并给予攻击者与受害者相同的访问级别。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29SJ9JUic965aOucYqfVliaUWnmDK6taepSZ67WyqZh4QPPVmoywmzePknrU9c3yE7N92TYE6Ygw5Cw/640?wx_fmt=png&from=appmsg "")  
  
注入偷来的 cookie  
  
从那里，攻击者可以使用Graph Explorer枚举用户、角色和设备，发送消息或访问Microsoft Teams上的聊天，并通过Outlook Web阅读或下载电子邮件。  
  
通过TokenSmith、ROADtools和AADInternals等工具，还可能进一步利用特权升级、横向移动和未经授权的应用程序注册。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29SJ9JUic965aOucYqfVliaUWBKj6d1ddy4eEiczdkhefSricSJyTwdK9DXuAHVRkNiayibjYSq9YWaOuJg/640?wx_fmt=png&from=appmsg "")  
  
Cookie-Bite攻击概述  
  
微软将研究人员在攻击演示中的登录尝试标记为“atRisk”，因为他们使用了VPN，因此监控异常登录是防止这些攻击的关键。  
  
此外，建议实施条件访问策略（CAP），以限制对特定IP范围和设备的登录。  
  
关于Chrome扩展，建议执行Chrome ADMX策略，只允许预先批准的扩展运行，并完全阻止用户从浏览器的开发者模式。  
  
参考及来源：  
https://www.bleepingcomputer.com/news/security/cookie-bite-attack-poc-uses-chrome-extension-to-steal-session-tokens/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29SJ9JUic965aOucYqfVliaUWib9YgrRRIsibic6ETEwE9W4vp13jdAib1EJa0j1US7UzYMuiazMtJlkGicdw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29SJ9JUic965aOucYqfVliaUWeqvicwiapa0SBClpS879LOn0tD2UfyyMclicV34GCpnPjA1qYYm71MgXw/640?wx_fmt=png&from=appmsg "")  
  
  
