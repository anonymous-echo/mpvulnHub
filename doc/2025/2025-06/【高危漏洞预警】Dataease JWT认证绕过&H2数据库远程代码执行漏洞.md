#  【高危漏洞预警】Dataease JWT认证绕过&H2数据库远程代码执行漏洞   
cexlife  飓风网络安全   2025-06-05 08:22  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu02YlPcsZGmkCNhfRAE3Ax49ydDqu3UPiaLY6MugvpJMU3X8ge0EapNiaSCVDjgPK6VJ05Xs5hIJ22dg/640?wx_fmt=png&from=appmsg "")  
  
1.Dataease JWT 认证绕过漏洞（CVE-2025-49001）   
  
漏洞描述:  
  
DаtаEаѕе是一个开源的业务智能和数据可视化工具,它允许用户通过图形化界面对数据进行分析和展示,在版本2.10.10之前,该工具的密钥验证未能正确实施,导致用户可以使用任意密钥伪造JWT令牌。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu02YlPcsZGmkCNhfRAE3Ax49M47jqAwrTXYWr8FuysKaG9QjicLUub2UiacicUq5zk7H7mUsuZTkdZfrg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu02YlPcsZGmkCNhfRAE3Ax49FekngX3GWA9OKWudic9raCWydSvGE6Dw0BC4TMz6ibpBP4CODIfmx9Sw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu02YlPcsZGmkCNhfRAE3Ax49V5TAIEFq8ZDCwajicXSFB1iazJFDSib3govBRLauzYiasjKia7icoL9qzo4g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu02YlPcsZGmkCNhfRAE3Ax492RF9pM5ePNFPXImrfuX46U9tuHJbCXZHYQGZVJ3MORfSqSSK697BHg/640?wx_fmt=png&from=appmsg "")  
  
攻击场景:  
  
攻击者可能通过绕过身份认证来获取未经授权的访问权限  
  
影响产品:  
  
DataEase <= 2.10.8   
  
修复建议:  
  
补丁名称:  
  
DаtаEаѕе身份认证绕过漏洞的补丁-更新至最新版本2.10.10  
  
目前官方已有可更新版本,建议受影响用户升级至最新版本:  
  
DаtаEаѕе >= 2.1010  
  
官方补丁下载地址:  
  
https://github.com/dataease/dataease/releases/tag/v2.10.10   
  
  
2.Dataease H2数据库远程代码执行漏洞（CVE-2025-49002）  
  
漏洞描述:  
  
DаtаEаѕе是一个开源的业务智能和数据可视化工具,广泛应用于数据展示和分析。该工具在2.10.10版本之前的补丁修复CVE-2025-32966时存在缺陷,由于INIT和RUNSCRIPT被禁止,攻击者可以通过大小写不敏感的方式绕过补丁。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu02YlPcsZGmkCNhfRAE3Ax49MgRVguhQw8X5RKWOQH5xKXU358OrPLftGM8DCH2VD2Cd9FyXf72lRw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu02YlPcsZGmkCNhfRAE3Ax49msDdLicIPgn2icptV0l3icibeNU6znpRIuxzj4Y97K3cquOt4x2jf5ibbgQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu02YlPcsZGmkCNhfRAE3Ax49FCIH0odWdyMKbqnUzrRez1VUibicxnxcYDlLXhZoBPMOXQXGfT2gnqWg/640?wx_fmt=png&from=appmsg "")  
  
攻击场景:  
  
攻击者可能通过大小写不敏感的方式绕过补丁上传恶意文件,执行远程代码。  
  
影响产品:  
  
DataEase <= 2.10.8   
  
修复建议:  
  
补丁名称:  
  
DаtаEаѕе远程代码执行漏洞的补丁—更新至最新版本v2.1010  
  
目前官方已有可更新版本,建议受影响用户升级至最新版本:  
  
DаtаEаѕе >= 2.1010  
  
官方补丁下载地址:  
  
https://github.com/dataease/dataease/releases/tag/v2.10.10   
  
  
  
