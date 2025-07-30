#  Google Cloud研究人员揭露Rsync文件同步工具中的多个安全漏洞   
Hankzheng  技术修道场   2025-01-21 05:31  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wWBwsDOJT4ic1pMvZT4oS46tMXyGGD2c1WPkagXruh5xca8FTX1icyzGW8WXcl0hpXVdnqibX2m6QHbgtpfccuSibw/640?wx_fmt=png&from=appmsg "")  
  
近日，Google Cloud漏洞研究团队的Simon Scannell、Pedro Gallegos和Jasiel Spelman在Unix系统上广泛使用的文件同步工具Rsync中发现了多达六个安全漏洞。这些漏洞中，部分可被攻击者利用在客户端上执行任意代码，甚至窃取敏感数据。CERT协调中心（CERT/CC）已发布公告，提醒用户尽快采取措施修复。  
  
**漏洞详情**  
  
此次披露的漏洞包括：  
1. **CVE-2024-12084（CVSS评分：9.8）**  
：由于校验和长度处理不当导致的堆缓冲区溢出漏洞。  
  
1. **CVE-2024-12085（CVSS评分：7.5）**  
：通过未初始化的堆栈内容导致的信息泄露漏洞。  
  
1. **CVE-2024-12086（CVSS评分：6.1）**  
：Rsync服务器泄露任意客户端文件的漏洞。  
  
1. **CVE-2024-12087（CVSS评分：6.5）**  
：Rsync中的路径遍历漏洞。  
  
1. **CVE-2024-12088（CVSS评分：6.5）**  
：绕过--safe-links  
选项导致的路径遍历漏洞。  
  
1. **CVE-2024-12747（CVSS评分：5.6）**  
：处理符号链接时的竞争条件漏洞。  
  
**潜在风险**  
  
CERT/CC指出，攻击者可以通过控制恶意服务器读取或写入任意客户端文件，窃取SSH密钥等敏感数据，并通过覆盖文件（如~/.bashrc  
或~/.popt  
）执行恶意代码。在最严重的情况下，攻击者仅需对Rsync服务器（如公共镜像）具有匿名读取权限，即可在服务器运行的机器上执行任意代码。  
  
此外，攻击者还可以结合CVE-2024-12084和CVE-2024-12085漏洞，在运行Rsync服务器的客户端上实现任意代码执行。  
  
**修复建议**  
  
Rsync开发团队已发布修复版本**3.4.0**  
，建议所有用户尽快升级至最新版本。对于无法立即升级的用户，可以采取以下缓解措施：  
- **CVE-2024-12084**  
：通过编译时添加CFLAGS=-DDISABLE_SHA512_DIGEST  
和CFLAGS=-DDISABLE_SHA256_DIGEST  
禁用SHA*支持。  
  
- **CVE-2024-12085**  
：通过编译时添加-ftrivial-auto-var-init=zero  
将堆栈内容初始化为零。  
  
**结语**  
  
Rsync作为广泛使用的文件同步工具，其安全性至关重要。此次披露的漏洞可能对用户的数据安全和系统稳定性造成严重威胁。建议所有Rsync用户立即升级至最新版本，或采取推荐的缓解措施，以防止攻击者利用漏洞入侵系统。同时，用户应定期监控系统日志，及时发现并应对潜在的安全威胁。  
  
