> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk4ODk4NDEyOA==&mid=2247483856&idx=1&sn=7963b410daa8e6556cf0f0bad2f086af

#  EDUSRC捡漏案例分享 | 某高校系统存在前端敏感信息泄露，成功获取超级管理员权限！  
原创 0xSec笔记本  0xSec笔记本   2025-07-22 03:33  
  
 🔐 安全提醒  
  
   本文所有内容基于公开授权场景进行演示，**请勿在未获得授权情况下对真实系统进行任何操作**  
。  
### 📌 漏洞背景  
  
在一次对高校系统的测试中，在空间搜索引擎中的截图中发现竟然有账号密码的存在：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1ADJCFZ0CSLCJg2A8PdiaicP0nSHrQHncglZkoAialvL1EKBQStdgn7Zk3LpwwtsPpONXS83fZemkHmBfsOW0dvGA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1ADJCFZ0CSLCJg2A8PdiaicP0nSHrQHncgHibZGhOLtuT6DxgZ5XOyDKsOpm4enkESic8JZ59XSk5BwwYsialHq8cuw/640?wx_fmt=png&from=appmsg "")  
  
即发现该系统存在严重安全风险，主要体现在两方面：  
- **a. 超级管理员账号密码直接在前端代码中明文泄露**  
  
- **b. 管理后台存在弱口令，可轻松登录获取最高权限**  
  
该漏洞极易被攻击者利用，造成后台数据泄露、权限滥用甚至网站被控。  
### 🛠️ 漏洞描述与分析  
#### ① 前端代码泄露敏感信息（中高危）  
  
通过访问网站主页源码或浏览器开发者工具，发现某段 JavaScript 中**硬编码了管理员账号密码**  
：  

```
// 示例（实际测试中发现）
var admin_user = &#34;admin&#34;;
var admin_pass = &#34;123456&#34;;

```

  
这意味着只要用户打开浏览器控制台即可直接获取后台登录信息，毫无防护。  
#### ② 管理后台存在弱口令  
  
在已知用户名为“admin”的情况下，尝试常见弱口令组合如：  
- admin / admin  
  
- admin / 123456  
  
- admin / Admin123  
  
成功登录后台，获取到**超级管理员权限**  
。  
### 🎯 漏洞利用效果  
- 成功登录后台管理系统；  
  
- 获取用户数据库、教务系统核心数据；  
  
- 管理员权限下可进一步上传 WebShell、修改页面内容、添加用户等。  
  
### 🔐 修复建议  
1. **前端不应包含任何敏感信息！**  
  
1. 所有账号密码、令牌等敏感参数应由后端安全处理，前端仅作为展示或交互层。  
  
1. **禁止使用默认或弱口令**  
  
1. 管理员账号强制使用强密码；  
  
1. 增加登录验证码、登录失败锁定机制。  
  
1. **定期进行安全审计**  
  
1. 检查源代码中是否存在 hardcode；  
  
1. 使用自动化工具扫描常见配置/逻辑漏洞。  
  
### 📚 总结  
  
本案例再次提醒我们：**前端不是安全区域，所有敏感信息一旦暴露，后果将不堪设想。**  
  
  
  
