#  Redis 漏洞导致服务器遭受拒绝服务攻击   
 夜组OSINT   2025-04-25 00:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GLyX5CgG8A1iaTj8eIk1SSvkOGg93dHicZxnUtJGrfvvT0H05mDuuCv0P7M2EmOeNXcIZXiaqcULl1ic0iaAJiavkc3g/640?wx_fmt=png&from=appmsg "")  
  
## 前言  
  
Redis 漏洞导致服务器遭受拒绝服务攻击 流行的开源内存数据结构存储系统 Redis 中发现了一个高危漏洞，该漏洞可能允许未经身份验证的用户耗尽服务器内存并导致拒绝服务 (DoS) 攻击。该漏洞编号为 CVE-2025-21605，影响 Redis 2.6 及以上版本的所有版本，CVSS 评分为 7.5。  
## 正文  
  
根据Redis 维护人员的说法：“未经身份验证的客户端可能会导致输出缓冲区无限增长，直到服务器内存耗尽或被杀死。”  
  
这个问题是由于 Redis 的默认配置没有对普通客户端的输出缓冲区进行限制 (client-output-buffer-limit)。如果没有这些限制，输出缓冲区可能会无限增长，最终导致内存耗尽。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GLyX5CgG8A2Qyvfrgt0M9icvpjPCnG0dqfsqf0EJA8BML2M7iaEF0WFIm3urNCiaWBFAt1H1Z2yeWiclZeFTF9xuRA/640?wx_fmt=png&from=appmsg "")  
  
CVE-2025-21605 尤其令人担忧的是，该攻击无需身份验证即可执行。即使启用了密码身份验证，该漏洞仍然存在：  
  
“当在 Redis 服务器上启用密码验证但未提供密码时，客户端仍然会导致输出缓冲区因‘NOAUTH’响应而增长，直到系统内存耗尽。”  
  
本质上，恶意客户端可以简单地向服务器发送大量未经授权的请求，从而触发连续的 NOAUTH 响应流，这些响应会在输出缓冲区中累积并压垮系统。  
  
Redis 从 2.6 版本开始受此漏洞影响，以下版本已修复此问题：  
```
- 6.2.18
- 7.2.8
- 7.4.3

```  
  
无法立即升级的管理员可以采取其他措施来降低风险：  
  
**“无需修补 redis-server 可执行文件即可缓解此问题的另一种解决方法是阻止访问以防止未经身份验证的用户连接到 Redis。”**  
## 安全建议  
- 实施网络访问控制，例如防火墙、iptables 或云安全组。  
  
- 启用 TLS 并要求客户端证书认证。  
  
  
  
  
  
