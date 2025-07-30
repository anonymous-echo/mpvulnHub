#  【漏洞预警】Oracle WebLogic Server 4月多个安全漏洞   
cexlife  飓风网络安全   2024-04-17 23:06  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu01azmpPC83Vze7znjViaRCk3B30mkrSk0JeAKIHvt4ffzO9sVgdnjhy05OAwiaJq69OLVWRzxoAZtAQ/640?wx_fmt=png&from=appmsg "")  
  
**漏洞概述:**  
  
近日监测到Oracle发布了4月安全更新,本次更新共包含441个新安全补丁,涉及Oracle和第三方组件中的漏洞,此次更新中共包含51个针对Oracle融合中间件的新安全补丁,其中 35个漏洞无需身份验证即可被远程利用,其中影响Oracle WebLogic Server和Oracle MySQL相关产品的部分漏洞如下:  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu01azmpPC83Vze7znjViaRCk3y1sCDDtjpcjNUphhWYBricy8c8TqH9Ckx7ZySGoKsQ3QJGxBsS2EDWw/640?wx_fmt=png&from=appmsg "")  
  
**CVE-2024-21006/CVE-2024-21007:Oracle WebLogic Server信息泄露漏洞（高危）**Oracle WebLogic Server 产品（组件：Core）中存在漏洞,未经身份验证的威胁者可通过T3、IIOP进行网络访问来破坏Oracle WebLogic Server,成功利用可能导致对关键数据的未授权的访问或对所有Oracle WebLogic Server可访问数据的完全访问,造成敏感信息泄露。**CVE-2024-21090:MySQL Connectors拒绝服务漏洞（高危）**OracleMySQL的MySQLConnectors产品（组件：Connector/Python）中存在漏洞,可能导致未经身份验证的威胁者通过多种协议进行网络访问来破坏 MySQL连接器,成功利用可能导致MySQL连接器挂起或频繁重复崩溃,从而造成拒绝服务。**CVE-2024-21015:MySQL Server拒绝服务漏洞（中危）**  
  
Oracle MySQL的MySQL Server产品（组件：Server: DML）中存在漏洞,拥有高权限的威胁者可通过多种协议进行网络访问来破坏MySQL服务器,成功利用可能导致MySQL服务器挂起或频繁重复崩溃,以及对某些MySQL Server可访问数据的未经授权更新、插入或删除访问。  
  
**影响范围:**受影响的部分产品及版本（受支持）包括：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu01azmpPC83Vze7znjViaRCk3L04xWZhLian6YkNG0NfWReMdbiciaF7VhSbDHa2YP6A6YkjsKKISb7tgw/640?wx_fmt=png&from=appmsg "")  
  
**安全措施:**升级版本目前Oracle已经发布了相关漏洞的补丁集合,受影响用户可及时更新**参考链接:**https://www.oracle.com/security-alerts/cpuapr2024.html**临时措施:**如非必要,可以选择禁用T3协议、IIOP协议**禁用T3协议:**1）进入WebLogic控制台，在base_domain的配置页面中，进入“安全”选项卡页面，点击“筛选器”，进入连接筛选器配置。2) 在连接筛选器中输入：weblogic.security.net.ConnectionFilterImpl在连接筛选器规则中输入:127.0.0.1 * * allow t3 t3s0.0.0.0/0 * *deny t3 t3s（注：t3和t3s协议的所有端口只允许本地访问）3）保存后需重新启动,规则方可生效。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu01azmpPC83Vze7znjViaRCk3gLxLYdT0pXCXuicAYU8j6nrK22SLkSQtEYRpqygiblNvhAEguehPibSbQ/640?wx_fmt=png&from=appmsg "")  
  
**禁用IIOP协议**在WebLogic控制台中，选择【环境】>>【服务器】>>点击【AdminServer（管理）】>>【协议】>>【IIOP】，取消勾选“启用IIOP”，保存并重启WebLogic项目。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu01azmpPC83Vze7znjViaRCk3IadXGErHo0ib4Fp1nqFmn4JPKqH3yMiaPzOUsMjKVTc8PUzPENhPfyiaw/640?wx_fmt=png&from=appmsg "")  
  
**参考链接:**https://www.oracle.com/security-alerts/cpuapr2024.html  
  
