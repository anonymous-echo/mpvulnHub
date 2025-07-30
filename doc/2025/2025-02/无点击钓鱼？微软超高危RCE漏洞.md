#  无点击钓鱼？微软超高危RCE漏洞   
原创 天启实验室  天启实验室   2025-02-04 11:16  
  
![](https://mmbiz.qpic.cn/mmbiz_png/LDUwxuibGlXKCKM4Syhc3ybVyBr4pfiaq099ibzGRkXmLnq3P7pSW1WZfY8icrBP51ZibI3bZPEncsMLHiaLg84U6FibA/640?wx_fmt=png&from=appmsg "")  
  
**点击 关注我们**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/LDUwxuibGlXKCKM4Syhc3ybVyBr4pfiaq0iaAnMagtCAfhRMd563XOSoKDShGgopHCTOlTzwKyftnkc3Ms3mzqNbg/640?wx_fmt=png&from=appmsg "")  
  
  
漏洞介绍  
  
![](https://mmbiz.qpic.cn/mmbiz_png/LDUwxuibGlXJW6EiaicvK7yguxJoDUtQjecf8Vd6GGEa5OArxyErQrwVRl7WHNs5a6pAdbsEnIXd2N2PB1WexckuQ/640?wx_fmt=png&from=appmsg "")  
  
**CVE-2025-21298****：Windows OLE远程代码执行漏洞。**  
该漏洞的CVSS评分为9.8，可导致远程攻击者通过 Outlook 向受影响系统发送特殊构造的邮件，在目标系统上执行代码。幸运的是预览面板并非攻击向量，但预览附件可触发代码执行。该漏洞位于 RTF 文件的解析中，是因为对用户提供的数据缺乏正确验证造成的，可导致内存损坏条件。用户可将 Outlook 设置为以明文形式读取所有标准邮件，但用户可能反感这么设置，最好的方式是快速测试并部署该补丁。  
  
  
简单来说：黑客发送邮件-->outlook预览-->代码执行上线  
  
影响范围  
  
Win10 20H2~22H2、Win11 21H2~23H2、Server 2019/2022  
  
修复建议  
  
安装微软官方补丁。链接：https://msrc.microsoft.com/update-guide  
  
参考链接  
  
1. https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-21298  
  
2. https://nvd.nist.gov/vuln/detail/CVE-2025-21298  
  
3.https://mp.weixin.qq.com/s/GNyXyqUkNQg02wuqVoZ21g  
  
  
  
  
