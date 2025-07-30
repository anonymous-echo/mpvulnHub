#  【漏洞预警】Splunk Enterprise需授权路径遍历漏洞可导致远程代码执行   
cexlife  飓风网络安全   2024-10-15 22:04  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu02kGdfTMbyScIb2h8FA5zZ8fpECqWJCI0UgKCh3HHpyGoLepGyomlqleNd3QF0yqT40frL1iaabBgA/640?wx_fmt=png&from=appmsg "")  
  
**漏洞描述:**  
  
Splunk发布安全公告,其中公开了一个路径遍历漏洞,在Windows环境中,当Splunk Enterprise安装在单独的驱动器上时低权限用户可以将文件写入Windows 系统根目录,攻击者可以编写恶意DLL到系统根目录,这可能导致攻击者可以在服务器上执行远程代码。**修复建议:正式防护方案:**厂商已发布补丁修复漏洞,用户请尽快更新至安全版本:将Splunk Enterprise升级到版本 9.3.1、9.2.3和9.1.6或更高版本。**升级参考官方文档:**https://docs.splunk.com/Documentation/Splunk/9.3.1/installation/HowtoupgradeSplunk  
  
与此同时,请做好资产自查以及预防工作,以免遭受黑客攻击。  
  
**参考链接:**https://advisory.splunk.com/advisories/SVD-2024-1001  
  
