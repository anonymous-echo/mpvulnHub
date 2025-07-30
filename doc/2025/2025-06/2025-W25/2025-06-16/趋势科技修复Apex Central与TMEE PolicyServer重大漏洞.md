> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3OTc0NDcyNQ==&mid=2247494022&idx=2&sn=d88428fa371809299b8d83ef2353c7ed

#  趋势科技修复Apex Central与TMEE PolicyServer重大漏洞  
鹏鹏同学  黑猫安全   2025-06-16 01:48  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEceicbhicIuO4lYKvBV5H8vEOHwQgfqNDNzsVYmZFjg8pID2icQF8w8E2QptzHCPW4FltI07RuyQxIic9pw/640?wx_fmt=png&from=appmsg "")  
  
核心产品影响  
趋势科技近日修补了影响其终端加密解决方案（TMEE PolicyServer）和Apex Central管理平台的远程代码执行（RCE）及身份验证绕过漏洞。TMEE PolicyServer作为企业级加密策略管理核心组件，6.0.0.4013之前版本的Windows系统均受影响；Apex Central则是面向网关、邮件服务器等企业节点的集中式Web管理控制台。  
  
**TMEE PolicyServer漏洞详情**  
趋势科技在安全公告中确认，已发布补丁修复以下关键漏洞（CVSS评分均≥7.7）：  
- **CVE-2025-49211**  
（7.7分）：SQL注入提权漏洞，攻击者需具备低权限代码执行能力  
  
- **CVE-2025-49212/13/17**  
（均9.8分）：预认证反序列化漏洞，可导致远程代码执行（攻击方法各异）  
  
- **CVE-2025-49214**  
（8.8分）：需认证触发的反序列化RCE漏洞  
  
- **CVE-2025-49215/18**  
（均8.8分）：认证后SQL注入提权漏洞  
  
- **CVE-2025-49216**  
（9.8分）：身份验证绕过漏洞，攻击者可获取管理员权限修改配置  
  
**Apex Central漏洞情况**  
该Web控制台存在两个9.8分反序列化漏洞：  
- **CVE-2025-49219/49220**  
：均可在未认证状态下触发远程代码执行，但利用方法存在差异  
  
**风险现状与修复建议**  
厂商强调目前未监测到野外利用案例，但强烈建议立即升级至TMEE PolicyServer 6.0.0.4013（Patch 1 Update 6）版本。由于这些漏洞均无临时缓解措施，完整安装补丁是唯一解决方案。Apex Central用户也应尽快应用最新安全更新。  
  
  
