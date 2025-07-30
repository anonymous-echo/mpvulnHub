#  湾Snews | 微软发现了OpenVPN中存在可能引发远程代码执行(RCE)和本地权限提升(LPE)的安全问题   
 粵港澳大灣區網絡安全協會   2024-08-13 19:33  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bcspRzSia4bnEwFgfiaEibhhG5g9TT38nsrZJYZMyibRcyibqYexYNkhSTf5AdLoGZf3gwnf7VnwHgyJWiadbJVx0xNg/640?wx_fmt=png&from=appmsg "")  
  
Microsoft on Thursday disclosed four medium-severity security flaws in the open-source OpenVPN software that could be chained to achieve remote code execution (RCE) and local privilege escalation (LPE).  
  
"This attack chain could enable attackers to gain full control over targeted endpoints, potentially resulting in data breaches, system compromise, and unauthorized access to sensitive information," Vladimir Tokarev of the Microsoft Threat Intelligence Community said.  
  
That said, the exploit, presented by Black Hat USA 2024, requires user authentication and an advanced understanding of OpenVPN's inner workings. The flaws affect all versions of OpenVPN prior to version 2.6.10 and 2.5.10.  
  
The list of vulnerabilities is as follows -  
- CVE-2024-27459 - A stack overflow vulnerability leading to a Denial-of-service (DoS) and LPE in Windows  
  
- CVE-2024-24974 - Unauthorized access to the "\\openvpn\\service" named pipe in Windows, allowing an attacker to remotely interact with it and launch operations on it  
  
- CVE-2024-27903 - A vulnerability in the plugin mechanism leading to RCE in Windows, and LPE and data manipulation in Android, iOS, macOS, and BSD  
  
- CVE-2024-1305 - A memory overflow vulnerability leading to DoS in Windows  
  
The first three of the four flaws are rooted in a component named openvpnserv, while the last one resides in the Windows Terminal Access Point (TAP) driver.  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bcspRzSia4bnEwFgfiaEibhhG5g9TT38nsrQuXXhYKLACzs9iarCwc2gqO6Qxno96Agoic4DQGUsiaS40IYeseYMRTRw/640?wx_fmt=png&from=appmsg "")  
  
  
All the vulnerabilities can be exploited once an attacker gains access to a user's OpenVPN credentials, which, in turn, could be obtained through various methods, including purchasing stolen credentials on the dark web, using stealer malware, or sniffing network traffic to capture NTLMv2 hashes and then using cracking tools like HashCat or John the Ripper to decode them.  
  
An attacker could then chain these flaws in different combinations -- CVE-2024-24974 and CVE-2024-27903 or CVE-2024-27459 and CVE-2024-27903 -- to achieve RCE and LPE, respectively.  
  
"An attacker could leverage at least three of the four discovered vulnerabilities to create exploits to facilitate RCE and LPE, which could then be chained together to create a powerful attack chain," Tokarev said, adding they could employ methods like Bring Your Own Vulnerable Driver (BYOVD) after achieving LPE.  
  
"Through these techniques, the attacker can, for instance, disable Protect Process Light (PPL) for a critical process such as Microsoft Defender or bypass and meddle with other critical processes in the system. These actions enable attackers to bypass security products and manipulate the system's core functions, further entrenching their control and avoiding detection."  
  
