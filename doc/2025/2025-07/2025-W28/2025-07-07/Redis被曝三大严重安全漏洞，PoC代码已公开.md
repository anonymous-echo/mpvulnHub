> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651324554&idx=1&sn=bdeb8779451111167a89a91cea7654df

#  Redis被曝三大严重安全漏洞，PoC代码已公开  
 FreeBuf   2025-07-07 11:02  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3iccHKkcenMzvkibHR8MbiaVBk8u3fNnJ4iay2Cn6a4PqhRy4qgksg1NajGo5HeibQaQ0zf1wxwOxVIPUA/640?wx_fmt=png&from=appmsg "")  
  
  
Redis是一个高性能、灵活且易于扩展的键值存储数据库，适用于各种应用场景，可作为缓存、数据库和消息中间件等，具有出色的性能和稳定性。但近日，Redis数据库被曝存在三大严重安全漏洞。  
  
  
**Part01**  
## 漏洞概述  
  
  
Redis数据库被曝存在严重安全漏洞，攻击者可利用该漏洞实现远程代码执行（RCE）。目前相关概念验证（PoC）代码已在安全社区流传。漏洞涉及HyperLogLog（HLL）数据结构实现问题，编号为CVE-2024-51741和CVE-2024-46981。  
  
  
此外，Redis近日发布安全公告还披露一个拒绝服务漏洞（编号CVE-2025-48367，CVSSv4评分7.0）。该漏洞源于认证用户对Redis多批量协议命令的滥用，可能影响服务可用性。  
  
  
**Part02**  
## CVE-2024-51741  
  
  
Redis 存在编号为 CVE-2024-51741 的漏洞，该漏洞于2024年10月31日被分配CVE编号，影响版本为Redis至7.2.6、7.4.1。此漏洞被归类为有问题（棘手），对应CWE-404，即产品在资源可供重新使用之前未释放资源或错误释放资源。  
  
  
该漏洞作用于ACL Selector Handler组件（其具体功能及涉及的处理逻辑未知），危害在于：经身份验证且具备足够权限的攻击者，可通过提供未知输入创建格式错误的ACL选择器，当访问该选择器时会触发服务器panic，最终导致拒绝服务，影响系统可用性。  
  
  
在利用方面，此漏洞需通过本地攻击实施，且需要较高权限的成功身份验证。尽管目前技术细节和漏洞利用方式未公开，但被认为容易利用。漏洞扫描程序Nessus提供了ID为213612（对应插件：Fedora 41：valkey（2025-b332afed45））的插件，可辅助检测目标环境是否存在该漏洞。  
  
  
修复该漏洞的建议是将Redis升级至7.2.7或7.4.2版本，以此消除漏洞带来的风险。  
  
  
**Part03**  
## CVE-2024-46981  
  
  
Redis存在一个代码执行漏洞（CVE-2024-46981），CVSS评分为7.0。该漏洞源于Redis的Lua脚本引擎在内存管理方面的问题，经过身份验证的用户可借助特制Lua脚本操纵内存回收机制，通过EVAL和EVALSHA命令运行恶意脚本，进而可能在Redis服务器上执行任意代码。  
  
  
此漏洞影响Redis < 7.4.2、Redis < 7.2.7、Redis < 6.2.17版本，且若Redis配置未通过ACL限制EVAL和EVALSHA命令以限制Lua脚本执行，使用Lua脚本的Redis会受影响。  
  
  
目前该漏洞已修复，受影响用户可升级至Redis >= 7.4.2、Redis >= 7.2.7或Redis >= 6.2.17版本。  
  
  
**Part03**  
## CVE-2025-48367  
  
  
2025年7月7日，内存数据库Redis发布安全公告，披露了一个拒绝服务（DoS）漏洞（编号CVE-2025-48367，CVSSv4评分7.0）。  
  
  
该漏洞由安全研究员Gabriele Digregorio通过负责任披露流程提交并经Redis开发团队确认，源于认证用户对Redis多批量协议命令的滥用，攻击者在完成认证后，可通过特殊构造的命令协议触发异常行为，导致服务中断，虽未突破Redis“认证用户应被信任”的核心安全假设，但可能影响服务可用性。  
  
  
公告指出，此问题源于对Redis内置命令网络协议的滥用，需攻击者完成身份认证，未违反Redis安全模型。Redis团队因顾虑代码修复可能影响正常功能或降低性能，暂不计划发布修复补丁，仅为8.0.3、7.4.5、7.2.10、6.2.19这四个活跃版本分支发布包含常规稳定性改进及可能缓解措施的更新。  
  
  
针对该漏洞，Redis建议从强化访问控制入手防护，包括实施强认证机制、避免Redis实例暴露于不可信网络，将Redis访问与企业身份提供商集成以增强控制，以及参照Redis安全最佳实践加固部署环境，防范认证滥用风险。  
  
  
**参考来源：**  
  
Redis Vulnerability Opens Door to Remote Code Execution, PoC Releases  
  
https://securityonline.info/redis-vulnerability-opens-door-to-remote-code-execution-poc-releases/  
  
  
###   
###   
###   
  
**推荐阅读**  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651324107&idx=1&sn=f89429997e0347cfe1580cc8ca6e858b&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
   
  
