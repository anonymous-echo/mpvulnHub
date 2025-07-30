> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg2NjY2MTI3Mg==&mid=2247500866&idx=1&sn=3e6caa7a94d92763e65f4895c1516b20

#  Apache HTTP Server 2.4.64发布，修复8个漏洞  
原创 铸盾安全  河南等级保护测评   2025-07-12 22:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sNicKB84ZxoGla4lWj5yFZYZOicjhbibic1VUyIdy97E0hC1ic3HXumUAel7pcjOSZL3gLwLtkNj0pl23rXen8bJlGA/640?wx_fmt=png&from=appmsg "")  
  
Apache 软件基金会发布了 Apache HTTP Server 版本 2.4.64，解决了影响从 2.4.0 到 2.4.63 版本的八个严重安全漏洞。   
  
此最新更新解决了一系列问题，包括 HTTP 响应拆分、服务器端请求伪造 (SSRF) 和可能危及服务器安全和性能的拒绝服务漏洞。  

```
关键要点1. Apache HTTP Server 2.4.64 修复了所有 2.4.x 版本中的八个漏洞，包括 HTTP 响应拆分和 SSRF 漏洞。2 . SSL/TLS 补丁解决了访问控制绕过、TLS 升级劫持和日志注入问题。3 . SSRF 修复解决了 mod_proxy 漏洞利用和通过 UNC 路径泄漏 Windows NTLM 哈希值的问题。4. 代理配置中的 HTTP/2 DoS 漏洞和内存耗尽需要立即升级。
```

## HTTP 响应和 SSL/TLS 安全漏洞   
  
此版本中修补的最重要漏洞是 CVE-2024-42516，这是 Apache HTTP Server 核心中的一个中等严重程度的 HTTP 响应拆分漏洞。   
  
该漏洞允许能够操纵托管或代理应用程序的 Content-Type 响应标头的攻击者拆分 HTTP 响应。   
  
值得注意的是，此漏洞之前被标识为 CVE-2023-38709，但 Apache HTTP Server 2.4.59 中包含的补丁未能充分解决该问题。  
  
另外两个与 SSL/TLS 相关的漏洞已得到解决。CVE-2025-23048 表示存在中等严重程度的访问控制绕过漏洞，影响 Apache HTTP Server 2.4.35 至 2.4.63 版本上的 mod_ssl 配置。   
  
此漏洞使受信任的客户端能够在具有不同受信任的客户端证书配置的多虚拟主机环境中使用 TLS 1.3 会话恢复来绕过访问控制。   
  
第二个 SSL 问题 CVE-2025-49812 影响使用“SSLEngine 可选”启用 TLS 升级的配置，允许中间人攻击者通过 TLS 升级攻击劫持 HTTP 会话。  
  
解决的另一个安全问题是 CVE-2024-47252，涉及 mod_ssl 中对用户提供的数据的转义不足。   
  
当 CustomLog 配置使用“%{varname}x”或“%{varname}c”来记录 mod_ssl 变量（例如 SSL_TLS_SNI）时，此低严重性漏洞允许不受信任的 SSL/TLS 客户端将转义字符插入日志文件。  
## 服务器端请求伪造缺陷  
  
Apache HTTP Server 2.4.64 修复了两个不同的 SSRF 漏洞，这些漏洞可能使攻击者能够操纵服务器请求。CVE-2024-43204 会影响已加载 mod_proxy 且 mod_headers 配置为使用 HTTP 请求值修改 Content-Type 标头的配置。   
  
这种低严重性漏洞允许攻击者向攻击者控制的 URL 发送出站代理请求，尽管它需要不太可能的配置场景。  
  
第二个 SSRF 漏洞 CVE-2024-43394 专门针对 Windows 上的Apache HTTP Server安装。   
  
此中等严重程度的缺陷可能导致 NTLM 哈希值通过 mod_rewrite 或 Apache 表达式泄漏到恶意服务器，这些表达式处理通过 UNC 路径输入的未经验证的请求。   
  
Apache HTTP 服务器项目已宣布计划实施更严格的标准，以接受有关 UNC 路径的未来 SSRF 漏洞报告。  
## 拒绝服务和性能问题   
  
CVE-2025-49630 影响启用 ProxyPreserveHost 的 HTTP/2 后端的反向代理配置，允许不受信任的客户端触发 mod_proxy_http2 中的断言并导致服务中断。  
  
CVE-2025-53020 表示 HTTP/2 实现中与内存相关的拒绝服务漏洞，影响 Apache HTTP Server 版本 2.4.17 至 2.4.63。   
  
该中等严重程度的问题涉及有效寿命后的内存延迟释放，可能导致内存耗尽攻击。  
  
<table><tbody><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><strong style="box-sizing: border-box;font-weight: bold;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">常见漏洞</span></font></font></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><strong style="box-sizing: border-box;font-weight: bold;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">描述</span></font></font></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><strong style="box-sizing: border-box;font-weight: bold;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">严重程度</span></font></font></strong></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">CVE-2024-42516</span></font></font></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">HTTP 响应拆分 </span></font></font></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">缓和</span></font></font></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">CVE-2024-43204</span></font></font></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">使用 mod_headers 设置 Content-Type 标头的 SSRF </span></font></font></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">低的</span></font></font></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">CVE-2024-43394</span></font></font></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">由于 UNC 路径导致 Windows 上存在 SSRF </span></font></font></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">缓和</span></font></font></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">CVE-2024-47252</span></font></font></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">mod_ssl 中对用户提供的数据转义不足 </span></font></font></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">低的</span></font></font></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">CVE-2025-23048</span></font></font></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">通过会话恢复绕过 mod_ssl 访问控制 </span></font></font></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">缓和</span></font></font></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">CVE-2025-49630</span></font></font></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">mod_proxy_http2 拒绝服务攻击 </span></font></font></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">低的</span></font></font></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">CVE-2025-49812</span></font></font></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">mod_ssl TLS 升级攻击允许通过中间人攻击劫持 HTTP 会话 </span></font></font></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">缓和</span></font></font></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">CVE-2025-53020</span></font></font></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">HTTP/2 DoS 通过内存增加 </span></font></font></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">缓和</span></font></font></td></tr></tbody></table>  
来自帕德博恩大学和波鸿鲁尔大学等多家机构以及多家安全公司的安全研究人员为发现这些漏洞做出了贡献。   
  
Apache 软件基金会强烈建议所有运行受影响版本的用户立即升级到 2.4.64 版本。   
  
系统管理员应优先考虑此更新，特别是对于处理敏感数据或在高安全性环境中运行的生产环境，这些漏洞可能会被利用。  
  
