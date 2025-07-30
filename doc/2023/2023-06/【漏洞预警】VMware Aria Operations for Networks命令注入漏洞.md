#  【漏洞预警】VMware Aria Operations for Networks命令注入漏洞   
安识科技  SecPulse安全脉搏   2023-06-09 11:49  
  
1. **通告信息**  
  
  
  
****  
近日，安识科技  
A-Team团队监测到VMware发布安全公告，修复了Aria Operations Networks 6.x中的一个命令注入漏洞（CVE-2023-20887），该漏洞的CVSSv3评分为9.8，对 VMware Aria Operations for Networks 具有网络访问权限的威胁者可以通过执行命令注入攻击，从而导致远程代码执行。  
  
对此，安识科技建议广大用户及时升级到安全版本，并做好资产自查以及预防工作，以免遭受黑客攻击。  
##   
  
2. **漏洞概述**  
  
  
  
漏洞名称：  
VMware Aria Operations for Networks命令注入漏洞  
  
CVE编号：  
CVE-2023-20887  
  
简述：  
VMware Aria Operations for Networks (以前称为vRealize Network Insight，vRNI)是一款网络可视性和分析工具，可以帮助管理员优化网络性能或管理和扩展各种VMware和Kubernetes部署。  
  
对   
VMware Aria Operations for Networks 具有网络访问权限的威胁者可以通过执行命令注入攻击，从而导致远程代码执行。此外，VMware Aria Operations for Networks 6.x中还修复了一个反序列化漏洞（CVE-2023-20888，CVSSv3评分9.1），对Aria Operations for Networks 具有网络访问权限的经过身份验证的恶意用户可以执行反序列化攻击，从而导致远程代码执行；以及修复了另一个信息泄露漏洞（CVE-2023-20889，CVSSv3评分8.8），对Aria Operations for Networks具有网络访问权限的威胁者可以通过执行命令注入攻击，导致信息泄露。  
##   
  
3. **漏洞危害**  
  
  
  
对   
VMware Aria Operations for Networks 具有网络访问权限的威胁者可以通过执行命令注入攻击，从而导致远程代码执行。  
##   
  
4. **影响版本**  
  
  
  
目前受影响的  
VMware Aria Operations Networks版本：  
  
VMware Aria Operations Networks版本：6.x  
##   
  
5. **解决方案**  
  
  
  
目前  
VMware已经发布了这些漏洞的补丁，Aria Operations for Networks 6.2、6.3、6.4、6.5.1、6.6、6.7、6.8、6.9、6.10版本用户可及时安装补丁。  
  
下载链接：  
https://kb.vmware.com/s/article/92684  
##   
  
6. **时间轴**  
  
  
  
【  
-】2023年0  
6  
月  
07  
日   
安识科技  
A-Team团队监测到漏洞公布信息  
  
【  
-】2023年0  
6  
月  
08  
日   
安识科技  
A-Team团队根据漏洞信息分析  
  
【  
-】2023年0  
6  
月  
0  
9  
日   
安识科技  
A-Team团队发布安全通告  
  
  
         
  
