#  Wireshark 漏洞可通过恶意数据包注入发起 DoS 攻击   
会杀毒的单反狗  军哥网络安全读报   2025-06-06 01:00  
  
**导****读**  
  
  
  
流行的网络协议分析器 Wireshark 中发现一个严重漏洞，允许攻击者通过数据包注入或使用格式错误的捕获文件触发拒绝服务 (DoS) 攻击。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaFzCguWmBfRkunibD9zVYN454z8l9FsHDQDZObU18oP8bNyuv4dBjoIXX20ItNQibMWWBAMdfz3eRmg/640?wx_fmt=png&from=appmsg "")  
  
  
该安全漏洞编号为 CVE-2025-5601，影响全球数百万依赖 Wireshark 进行网络故障排除和分析的用户。  
  
  
该漏洞被 Wireshark 基金会正式指定为 wnpa-sec-2025-02，于 2025 年 6 月发布，CVSS 评分为 7.8，严重程度较高。  
  
  
该缺陷源于 Wireshark 的列实用程序模块中的一个错误，该错误导致某些解剖器在处理格式错误的网络流量时崩溃。  
  
  
受影响的版本包括Wireshark 4.4.0至4.4.6以及4.2.0至4.2.12。该漏洞已被归类为CWE-120，表示存在“未检查输入大小的缓冲区复制”或典型的缓冲区溢出情况。  
  
  
安全研究人员称，该漏洞主要通过两种攻击途径利用。  
  
  
首先，攻击者可以将畸形数据包直接注入Wireshark监控的网络基础设施。其次，恶意攻击者可以制作损坏的数据包捕获文件，并诱使用户打开这些文件，从而引发崩溃。  
  
  
安全专家警告说，鉴于 Wireshark 在企业环境中的广泛部署，被利用的可能性很大。一旦成功利用，该漏洞将导致 Wireshark 应用程序崩溃，从而破坏关键的网络分析和监控操作。  
  
  
这可能会对依赖 Wireshark 进行实时网络安全监控和事件响应的组织产生严重影响。  
  
  
Wireshark 基金会已发布补丁程序修复该漏洞。强烈建议用户立即升级至 Wireshark 4.4.7 或 4.2.12 版本，其中包含必要的修复程序。  
  
  
除了更新软件之外，安全专家还建议采取一些额外的预防措施。企业应在 Wireshark 打开捕获文件之前验证其来源，将网络数据包捕获操作限制在可信来源，并实施网络分段以减少暴露。  
  
  
在生产环境中使用 Wireshark 的组织应优先考虑立即修补并检查其网络监控安全协议，以防止潜在地利用此漏洞和未来的漏洞。  
  
  
安全公告：  
  
https://www.wireshark.org/security/wnpa-sec-2025-02.html  
  
  
新闻链接：  
  
https://cybersecuritynews.com/wireshark-vulnerability-enables-dos-attack/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
