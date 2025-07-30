#  知名工业WiFi接入点被曝存在20多个漏洞   
 黑白之道   2024-12-01 07:57  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
  
近期，Advantech工业级无线接入点设备被曝光存在近二十个安全漏洞，部分漏洞可被恶意利用以绕过身份验证并执行高权限代码。![](https://mmbiz.qpic.cn/mmbiz_jpg/3xxicXNlTXLickrf68D0Rnk9W3nm0FapcNs03t4jHW7sqQgTKTBFJDgwdrorStbthHbsCicvpIUicy48CRn4OUE0ww/640?wx_fmt=jpeg&from=appmsg "")  
  
  
网络安全公司Nozomi Networks在周三发布的分析报告中警告称：“这些漏洞带来了严重的安全风险，它们允许未经身份验证的远程代码以根权限执行，全面威胁到受影响设备的保密性、完整性和可用性。”  
  
在负责任的披露流程之后，这些安全漏洞已在以下固件版本中得到修复：  
  
- 1.6.5版本，适用于EKI-6333AC-2G和EKI-6333AC-2GD型号；- 1.2.2版本，适用于EKI-6333AC-1GPO型号。  
  
在这些被识别的漏洞中，有六个被标记为关键漏洞，它们使得攻击者能够通过植入后门获得对内部资源的持续访问，触发拒绝服务（DoS）攻击，甚至将受感染的端点转变为Linux工作站，以实现网络内的横向移动和进一步渗透。  
  
在这六个关键漏洞中，有五个（CVE-2024-50370至CVE-2024-50374，CVSS评分为9.8）与操作系统命令中特殊元素的不当处理有关，而CVE-2024-50375（CVSS评分为9.8）则涉及关键功能缺乏身份验证的问题。  
  
特别值得关注的是CVE-2024-50376（CVSS评分为7.3），这是一个跨站脚本（XSS）漏洞，它可以与CVE-2024-50359（CVSS评分为7.2）相结合，后者是一个需要身份验证的操作系统命令注入漏洞，使得攻击者能够通过无线方式执行任意代码。  
  
为了成功实施这种攻击，外部恶意用户需要靠近Advantech的接入点并广播恶意信号。  
  
当管理员访问Web应用程序中的“Wi-Fi分析器”部分时，攻击就会被触发，导致页面自动嵌入攻击者广播的信标帧信息，而未进行任何消毒检查。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/3xxicXNlTXLickrf68D0Rnk9W3nm0FapcNKD17iazub4iazV7PuGYZqTUjIglZ3e5aLFV8r8hJDYiafRTpoD7dWLNEQ/640?wx_fmt=jpeg&from=appmsg "")  
  
Nozomi Networks指出：“攻击者可以通过其恶意接入点广播SSID（即Wi-Fi网络名称）。”因此，攻击者可以在其恶意接入点的SSID中嵌入JavaScript有效载荷，利用CVE-2024-50376触发Web应用程序内的XSS漏洞。  
  
这将导致在受害者的Web浏览器上下文中执行任意JavaScript代码，进而可以与CVE-2024-50359结合，实现具有根权限的操作系统级别的命令注入。这种攻击可能以反向shell的形式出现，为攻击者提供持久的远程访问权限。  
  
该公司进一步解释道：“这将使攻击者能够远程控制受损设备，执行命令，并进一步渗透网络，提取数据或部署额外的恶意脚本。”  
  
> **文章来源：freebuf**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
