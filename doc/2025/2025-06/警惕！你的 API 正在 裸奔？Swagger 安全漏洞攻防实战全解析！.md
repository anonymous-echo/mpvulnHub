#  警惕！你的 API 正在 "裸奔"？Swagger 安全漏洞攻防实战全解析！  
原创 蒸梅狸猫  东方隐侠安全团队   2025-06-06 07:59  
  
网安知识分享  
  
DFYX’s KNOWLEDGE & NEWS  
  
  科普知识 一起成长    
  
东方隐侠·集智堂  
  
引言  
  
  
在前后端分离开发盛行的今天，Swagger 作为 API 文档神器，帮助开发者高效调试接口、生成文档。但你知道吗？超过 60% 的企业存在未授权 API 暴露问题，Swagger 文档一旦泄露，可能成为黑客入侵的 "攻击地图"！  
  
本文将揭秘 Swagger 背后的安全隐患，手把手教你用自动化工具揪出漏洞，并送上硬核防护指南，帮你筑牢 API 安全防线！  
  
Swagger 为何成为黑客 "突破口"？  
  
  
Swagger 基于 OpenAPI 规范，将 API 路径、参数等信息以明文形式存储。一旦开发环境配置不当，黑客可通过简单路径（如/swagger-ui.html、/api-docs/swagger.json）轻松获取敏感接口清单，甚至直接调用接口！  
  
核心风险类型  
- 未授权访问：无需认证即可调用接口（如删除用户、重置密码）。  
  
- SSRF 攻击：接受 URL 参数的接口可能被利用攻击内部服务。  
  
- 认证绕过：篡改请求头或利用逻辑漏洞绕过权限校验。  
  
- 敏感信息泄露：文档中可能硬编码 API 密钥、数据库连接字符串等。  
  
攻击路径曝光  
  
黑客常用路径探测 Swagger 文档，例如：  
  
```
/swagger-ui.html /api/v1/swagger.json /spring-security-rest/api/swagger-ui.html /druid/index.html（附带SQL监控风险）
```  
  
  
  
真实案例  
  
某企业因暴露/api/v1/swagger-ui.html，黑客发现未授权的/admin/backup接口，直接下载数据库备份文件，导致数据大规模泄露！  
  
自动化工具实战：快速定位漏洞  
  
  
想快速检测自家 API 是否存在风险？这两款开源工具堪称 "漏洞扫描仪"，无需复杂配置，一键生成风险报告！  
  
1. swagger-hack：批量接口扫描器  
  
功能：  
爬取 API 列表、自动填充参数、生成漏洞报告。  
  
用法：  
  
python swagger-hack2.0.py -u http://your-domain.com/swagger-ui.json    
  
实战结果：  
  
扫描发现/api/v1/user/delete接口未校验权限，存在越权删除风险；/api/v1/ssrf-endpoint接受 URL 参数，可能引发 SSRF 攻击！  
  
2. swagger-exp：交互式漏洞分析  
  
优势：  
生成可视化 Swagger UI，自动检测认证绕过、敏感参数，支持浏览器直接调试。  
  
攻击演示：  
通过工具调用/api/admin/login接口，无需认证直接返回管理员令牌，证实存在认证绕过漏洞！  
  
防护指南：从开发到运维的全流程方案  
  
  
开发阶段：最小化攻击面  
  
1、禁用文档或限制访问：  
- 生产环境关闭 Swagger，或通过 Nginx 配置 IP 白名单，仅允许内部 IP 访问。  
  
- 示例配置：  
  
```
location /swagger-ui.html { 
  allow 192.168.1.0/24; 
  deny all; 
}
```  
  
  
    
  
2、强制认证与参数校验：  
- 在 Swagger 中集成 API Key 或 OAuth2 认证，拒绝未授权调用。  
  
- 对所有输入参数校验，禁止接收可疑 URL、文件路径等。  
  
运维阶段：持续监控与响应  
- 资产扫描：用 AWVS、Nessus 定期扫描 Swagger 路径，或用 Python 脚本主动探测。  
  
- 流量审计：通过 API 网关（如 Kong）记录接口日志，识别高频异常访问。  
  
- 应急响应：发现 Swagger 暴露后，立即封禁路径，追溯代码配置问题。  
  
  
  
  
总结：API 安全，攻防从来不是单选题  
  
  
Swagger 的便利与风险并存：对开发者是 "效率工具"，对黑客则是 "攻击地图"。但正如文中所说：漏洞不可怕，可怕的是忽视漏洞！  
  
通过自动化工具快速排查风险，结合开发运维全流程防护，才能在 API 便利性与安全性之间找到平衡点。  
  
行动建议：  
  
✅ 今天就检查自家 API 是否暴露 Swagger 路径；  
  
✅ 收藏文中工具，定期进行漏洞扫描；  
  
✅ 转发本文，提醒团队重视 API 安全！  
  
参考工具链：  
- 漏洞扫描：swagger-hack、swagger-exp  
  
- 流量分析：Burp Suite、Charles  
  
- 防护方案：API 网关（Kong）、WAF（ModSecurity）  
  
（完整内容及工具下载地址，请点击左下角【阅读原文】，前往东方隐侠官方网站“隐侠安全客栈”获取详情）  
  
  
关注东方隐侠安全团队 一起打造网安江湖  
  
        
  东方隐侠安全团队，一支专业的网络安全团队，将持续为您分享红蓝对抗、病毒研究、安全运营、应急响应等网络安全知识，提供一流网络安全服务，敬请关注！  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH7zgibKsqKmX3H4AatvwPeXFsrHGpp0RsxLJpzgd0cyiaPH2HDnfv4GMdxf0lkGjAibiaBtFcLmnm2ZkA/640?wx_fmt=png "")  
  
  
  
  
公众号｜东方隐侠安全团队  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH4laNHWaR5yOd2VbInJbO4h3daHtdT7pcSk7zONRMDyl2cht3U4dbbyiaLmMA5DpBBlTgspa3agKyw/640?wx_fmt=png "")  
  
  
  
  
请添加团队微信号  
｜东方隐侠安全团队  
  
用于拉少侠们进团队交流群  
  
