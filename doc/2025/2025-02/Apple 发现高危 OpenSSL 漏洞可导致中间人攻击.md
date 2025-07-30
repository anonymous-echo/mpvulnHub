#  Apple 发现高危 OpenSSL 漏洞可导致中间人攻击   
会杀毒的单反狗  军哥网络安全读报   2025-02-12 01:04  
  
**导****读**  
  
  
  
OpenSSL 周二发布针对  
OpenSSL  
两年来首个高严重性漏洞的补丁。   
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaFygU56nYE6HKVkWJVqgNhkia77QxeSXNqWRwj91m0RPFrYYKkViczzyOs59G0jicy2kBr7mRiaIib0tMQ/640?wx_fmt=png&from=appmsg "")  
  
  
OpenSSL  
修补了漏洞  
 CVE-2024-12797  
，这是  
 Apple   
发现的一个高严重性漏洞，可引发中间人攻击。  
  
  
OpenSSL 项目解决了其安全通信库中的一个高严重性漏洞，编号为 CVE-2024-12797。  
  
  
OpenSSL软件库允许在计算机网络上进行安全通信，以防止窃听或需要识别另一端的一方。OpenSSL 包含安全套接字层 (SSL) 和传输层安全 (TLS) 协议的开源实现。  
  
  
由于 SSL_VERIFY_PEER 模式下的服务器身份验证检查失败，使用 RFC7250 原始公钥 (RPK) 的客户端建立的 TLS/DTLS 连接可能容易受到中间人 (MitM) 攻击。  
  
  
苹果研究人员于 2024 年 12 月 18 日报告了该漏洞，并由 Viktor Dukhovni 修复。  
  
  
该漏洞会影响明确启用 RPK 并依赖 SSL_VERIFY_PEER 检测身份验证失败的 TLS 客户端。项目维护人员指出，TLS 客户端和 TLS 服务器默认禁用 RPK。  
  
  
仅当 TLS 客户端明确允许服务器使用 RPK，并且服务器同样允许发送 RPK 而不是 X.509 证书链时，才会出现此问题。受影响的客户端是那些依赖于握手失败的客户端，当服务器的 RPK 无法匹配预期的公钥之一时，通过将验证模式设置为 SSL_VERIFY_PEER 即可。  
  
  
无论如何，启用服务器端原始公钥的客户端仍然可以通过调用 SSL_get_verify_result() 检查原始公钥验证是否失败。此漏洞是在 OpenSSL 3.2 中最初实现 RPK 支持时引入的。  
  
  
此缓冲区溢出可能导致拒绝服务情况或可能导致远程代码执行。  
  
  
OpenSSL 3.4、3.3、3.2、3.1 和 3.0 中的 FIPS 模块不受此问题的影响。  
  
OpenSSL 3.1、3.0、1.1.1 和 1.0.2 也不受此问题的影响。  
  
OpenSSL 3.4、3.3 和 3.2 容易受到此问题的影响。  
  
已修复版本为 3.4.1、3.3.2 和 3.2.4 版本。  
  
  
自 2014 年臭名昭著的 Heartbleed 漏洞披露以来，  
    
OpenSSL 的安全性已经有了很大的发展。  
  
  
2023 年和 2024 年，该项目发现并修补的大多数漏洞都是低严重性级别。2023 年修复了两个中等严重性和一个高严重性漏洞，2024 年修复了一个中等严重性漏洞，其余都是低严重性漏洞。  
  
  
OpenSSL  
安全公告：  
  
https://openssl-library.org/news/secadv/20250211.txt  
  
  
新闻链接：  
  
https://www.securityweek.com/high-severity-openssl-vulnerability-found-by-apple-allows-mitm-attacks/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
