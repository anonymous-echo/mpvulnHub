#  思科Secure Client VPN劫持漏洞修复   
THN  知机安全   2024-03-09 10:02  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QGibgZhUnjfOhxqASobwL65UiamWiaLqDGg9q4KzsA09FaGHErxCiaAG3XYibEtaF2ILa2JqkgLyfavzkibw29lxrIDw/640?wx_fmt=png "")  
  
Cisco has released patches to address a high-severity security flaw impacting its Secure Client software that could be exploited by a threat actor to open a VPN session with that of a targeted user.  
  
思科已发布补丁，以解决影响其Secure Client软件的高严重性安全漏洞，黑客可以利用该漏洞打开与目标用户的VPN会话。  
  
The networking equipment company described the vulnerability, tracked as CVE-2024-20337 (CVSS score: 8.2), as allowing an unauthenticated, remote attacker to conduct a carriage return line feed (CRLF) injection attack against a user.  
  
这家网络设备公司描述了该漏洞，被标记为CVE-2024-20337（CVSS评分为8.2），允许未经身份验证的远程攻击者对用户进行回车换行（CRLF）注入攻击。  
  
Arising as a result of insufficient validation of user-supplied input, a threat actor could leverage the flaw to trick a user into clicking on a specially crafted link while establishing a VPN session.  
  
由于对用户提供的输入进行不足的验证而产生，攻击者可以利用该漏洞欺骗用户点击一个特制链接，同时建立VPN会话。  
  
"A successful exploit could allow the attacker to execute arbitrary script code in the browser or access sensitive, browser-based information, including a valid SAML token," the company said in an advisory.  
  
公司在一份咨询中表示：“成功利用可能允许攻击者在浏览器中执行任意脚本代码或访问敏感的基于浏览器的信息，包括有效的SAML令牌。”  
  
"The attacker could then use the token to establish a remote access VPN session with the privileges of the affected user. Individual hosts and services behind the VPN headend would still need additional credentials for successful access."  
  
“然后，攻击者可以使用令牌以受影响用户的权限建立远程访问VPN会话。VPN头端后面的个人主机和服务仍需要额外的凭据才能成功访问。”  
  
The vulnerability impacts Secure Client for Windows, Linux, and macOS, and has been addressed in the following versions -  
  
该漏洞影响Secure Client的Windows，Linux和macOS版本，并已在以下版本中得到解决 -  
- Earlier than 4.10.04065 (not vulnerable)  
  
早于4.10.04065（未受影响）  
  
- 4.10.04065 and later (fixed in 4.10.08025)  
  
4.10.04065及更高版本（在4.10.08025中修复）  
  
- 5.0 (migrate to a fixed release)  
  
5.0（迁移到修复版本）  
  
- 5.1 (fixed in 5.1.2.42)  
  
5.1（在5.1.2.42中修复）  
  
Amazon security researcher Paulos Yibelo Mesfin has been credited with discovering and reporting the flaw, telling The Hacker News that the shortcoming allows attackers to access local internal networks when a target visits a website under their control.  
  
亚马逊安全研究员Paulos Yibelo Mesfin被认为是发现并报告该漏洞的功臣，他告诉The Hacker News，这个缺陷允许攻击者在目标访问他们控制的网站时访问本地内部网络。  
  
Cisco has also published fixes for CVE-2024-20338 (CVSS score: 7.3), another high-severity flaw in Secure Client for Linux that could permit an authenticated, local attacker to elevate privileges on an affected device. It has been resolved in version 5.1.2.42.  
  
思科还为CVE-2024-20338（CVSS分数为7.3）发布了修复，这是Secure Client for Linux中的另一个高严重性漏洞，可能允许经过身份验证的本地攻击者在受影响设备上提升权限。它已在版本5.1.2.42中解决。  
  
"An attacker could exploit this vulnerability by copying a malicious library file to a specific directory in the filesystem and persuading an administrator to restart a specific process," it said. "A successful exploit could allow the attacker to execute arbitrary code on an affected device with root privileges."  
  
公司表示：“攻击者可以通过将恶意库文件复制到文件系统中的特定目录，并说服管理员重新启动特定进程来利用此漏洞。”“成功利用可能允许攻击者以root权限在受影响设备上执行任意代码。”  
  
**参考资料**  
  
[1]https://thehackernews.com/2024/03/cisco-issues-patch-for-high-severity.html  
  
**关注我们**  
  
        欢迎来到我们的公众号！我们专注于全球网络安全和精选双语资讯，为您带来最新的资讯和深入的分析。在这里，您可以了解世界各地的网络安全事件，同时通过我们的双语新闻，获取更多的行业知识。感谢您选择关注我们，我们将继续努力，为您带来有价值的内容。  
  
  
