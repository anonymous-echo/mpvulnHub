#  【漏洞预警】Redis Lua 远程代码执行漏洞   
原创 MasterC  企业安全实践   2025-01-09 01:30  
  
一、漏洞描述  
  
Redis 是开源的键值对存储数据库。  
  
具有 Lua 脚本功能的 Redis 版本(2.6及以上版本)中，经过身份验证的攻击者可构造恶意的Lua脚本控制垃圾回收器，导致远程代码执行。  
  
修复版本通过在关闭 lua VM 之前重置 GC 状态，防止用户数据被错误释放，来修复该漏洞。  
  
可以通过使用ACL来限制EVAL和EVALSHA命令的执行来临时缓解。  
  
二、漏洞等级  
  
高危  
  
三、受影响版本  
  
7.2.0 <= version < 7.2.7  
  
2.6 <= version < 6.2.17  
  
7.4.0 <= version < 7.4.2  
  
四、安全版本  
  
version >= 6.2.17  
  
version >= 7.4.2  
  
version >= 7.2.7  
  
五、修复建议  
  
目前官方已修复该漏洞，建议受影响用户尽快前往官网升级至安全版本。  
  
六、缓解方案  
  
目前暂无缓解方案。  
  
七、参考链接  
  
https://github.com/redis/redis/security/advisories/GHSA-39h2-x6c4-6w4c  
  
https://github.com/redis/redis/commit/ca0a9ab822dcd6d6ec6e2b6dd3a7d7b0dd8fc912  
  
https://nvd.nist.gov/vuln/detail/CVE-2024-46981  
  
https://github.com/redis/redis/commit/781658e44e0b0456a99a1c39f2dc9f9dd834e555  
  
https://github.com/redis/redis/commit/e344b2b5879aa52870e6838212dfb78b7968fcbf  
  
https://www.oscs1024.com/hd/MPS-2hc8-grue  
  
  
