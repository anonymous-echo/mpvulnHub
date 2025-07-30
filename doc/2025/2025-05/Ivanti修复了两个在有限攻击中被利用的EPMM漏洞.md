#  Ivanti修复了两个在有限攻击中被利用的EPMM漏洞   
鹏鹏同学  黑猫安全   2025-05-15 23:02  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEce9NWVV2Hjs50GRdwe3Gux88jKeVibdLLWhBQMXZD7p7gKk0UFE850UISll3EL48rdxS3IhVe2uibYYA/640?wx_fmt=png&from=appmsg "")  
  
Ivanti发布安全更新修复Endpoint Manager Mobile（EPMM）软件中的两个漏洞。该公司确认威胁攻击者已在有限攻击中串联利用这些漏洞实现远程代码执行。  
  
这两个漏洞编号为CVE-2025-4427和CVE-2025-4428，具体描述如下：  
  
CVE-2025-4427（CVSS评分5.3）——Endpoint Manager Mobile中的认证绕过漏洞，允许攻击者在无有效凭证情况下访问受保护资源。    
  
CVE-2025-4428（CVSS评分7.2）——Endpoint Manager Mobile中的远程代码执行漏洞，允许攻击者在目标系统执行任意代码。    
  
两项漏洞均由CERT-EU向软件厂商报告。  
  
该公司确认威胁攻击者可通过串联这两个漏洞实现无需认证的远程代码执行。  
  
安全公告称："Ivanti已发布Endpoint Manager Mobile（EPMM）更新，修复一个中危和一个高危漏洞。当组合利用时，可能导致未经认证的远程代码执行，我们获悉在漏洞披露时已有极少数客户系统遭到利用。"  
  
受影响软件版本列表如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEce9NWVV2Hjs50GRdwe3Gux88xcxXyR6mJgP4ia2NgGdmmW9on1pcnbACtmlsa9IYn6yjYqqB4SEpcxg/640?wx_fmt=png&from=appmsg "")  
  
漏洞已在11.12.0.5、12.3.0.2、12.4.0.2和12.5.0.1版本中修复。  
  
该公司指出漏洞存在于EPMM使用的两个未具名开源库中，强调问题并非源自其自身代码。目前攻击调查仍在进行中，但截至公告发布时尚未获取"可靠的原子级攻击指标"。  
  
  
