#  【漏洞预警】Jenkins OpenId Connect Authentication Plugin 身份验证缺陷漏洞   
cexlife  飓风网络安全   2024-10-08 22:41  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00moV1AmezM74mM1VQeH7ljc7qZfdt7ax76HDAVnMrULQ6hBE1ictz02ECSKnXxPicwibfsKX5v16jkA/640?wx_fmt=png&from=appmsg "")  
  
**漏洞描述:**Jenkins发布安全公告,其中公开了一个JenkinsOpenId Connect Authentication插件中的身份验证缺陷漏洞,该漏洞由于未检查ID令牌的“aud”（Audience）声明导致允许攻击者破坏身份验证流程并可能获得对Jenkins的管理员访问权限。**修复建议:正式防护方案:**厂商已发布补丁修复漏洞,用户请尽快更新至安全版本:Jenkins OpenId Connect Authentication Plugin>= 4.355.v3a**手动更新:**1.更新 Jenkins OpenId 连接身份验证插件至最新版本。您可以访问Jenkins官方插件页面下载最新的插件版本，下载链接： https://plugins.jenkins.io/oic-auth/**自动更新:**1.在 Jenkins 管理界面中，导航到“系统管理” -> “插件”，然后选择“已安装”的标签页。2.找到 OpenId 连接身份验证插件，点击“更新”按钮，系统会自动下载并安装最新版本。3.更新完成后，确保 Jenkins 服务自动重启以应用更改。如果系统没有自动重启，请手动重启 Jenkins 服务。与此同时,请做好资产自查以及预防工作,以免遭受黑客攻击。  
  
