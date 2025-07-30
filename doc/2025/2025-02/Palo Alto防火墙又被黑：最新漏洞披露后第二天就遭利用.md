#  Palo Alto防火墙又被黑：最新漏洞披露后第二天就遭利用   
e安在线  e安在线   2025-02-18 03:32  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1Y08O57sHWiahTldalExhOyzXNMO6kcO7ULmiclhSZfg8zVMLHEMUGBu3lBjFbjib8vsYDZzplofMSC7epkHHWpibw/640?wx_fmt=png&from=appmsg "")  
  
Palo Alto Networks于2月12日发布了针对CVE-2025-0108的补丁和缓解措施。该漏洞允许未经身份验证的攻击者访问防火墙管理界面并执行特定的PHP脚本。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1Y08O57sHWgO4kZtSR3FenXlrbDZhshrglO5sfVZdjKp1t9Iw4E0dtZHAUL4UdZoZN1vbCt7PKleicRgIiasgRyg/640?wx_fmt=jpeg "")  
  
GreyNoise于2月13日透露，其已开始检测到针对CVE-2025-0108的攻击尝试。截至2月14日上午，该公司已观测到来自5个不同IP地址的攻击活动。  
  
GreyNoise将这些攻击尝试标记为“恶意”，表明这些攻击更可能由威胁行为者发起，而非安全研究人员在评估易受攻击系统的数量。  
  
**此前有安全团队公布细节**  
  
发现该漏洞的研究团队Assetnote，在Palo Alto发布补丁公告当天就公开了漏洞的技术细节。这一举动可能使威胁行为者更容易将CVE-2025-0108纳入其攻击武器库。  
  
不过Assetnote也指出，CVE-2025-0108需要与另一个漏洞组合使用，才能实现远程代码执行。  
  
其中一个可能的相关漏洞是CVE-2024-9474，该漏洞已被积极利用。威胁行为者可能已经发现了一个类似于CVE-2024-9474的新漏洞，或者他们正在针对数月未更新的系统发动攻击（CVE-2024-9474的补丁于2024年11月发布）。  
  
Assetnote还表示，CVE-2025-0108与CVE-2024-0012类似。CVE-2024-0012是一个已被在野利用的身份验证绕过漏洞，通常与CVE-2024-9474联合使用。威胁行为者可能只是调整了CVE-2024-0012的利用代码，以攻击CVE-2024-0108，而无需依赖安全公司发布的具体信息。  
  
外媒SecurityWeek已联系Assetnote，询问其为何在漏洞披露后立即公开技术细节，同时也联系了Palo Alto Networks，以确认CVE-2024-0108是否已被用于实际攻击。  
  
Palo Alto Networks在其针对CVE-2024-0108发布的公告中仍表示，公司尚未发现该漏洞在野外被利用。尽管该漏洞被评为“高危”，但厂商给予的紧急性评级仅为“中等”。  
  
  
  
声明：除发布的文章无法追溯到作者并获得授权外，我们均会注明作者和文章来源。如涉及版权问题请及时联系我们，我们会在第一时间删改，谢谢！文章来源：安全内参  
，  
参考资料：securityweek.com  
  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1Y08O57sHWiaM9uv5Q89hYMT8zuKQtQYuvSPy0HyyLwRShZOMcoGgoBy6qiatgDhW3UhCXGVXiaEbS8ANmZwViaMAw/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
