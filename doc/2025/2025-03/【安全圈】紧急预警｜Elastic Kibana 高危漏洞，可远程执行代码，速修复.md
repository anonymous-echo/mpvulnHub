#  【安全圈】紧急预警｜Elastic Kibana 高危漏洞，可远程执行代码，速修复   
 安全圈   2025-03-08 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
漏洞  
  
  
**漏洞背景**  
  
近日，Elastic 官方紧急发布安全更新，修复了 Kibana（Elasticsearch 数据可视化平台） 中一个 CVSS 评分9.9 的严重漏洞（CVE-2025-25012）。该漏洞源于 原型污染缺陷，攻击者可通过构造恶意文件上传和特制 HTTP 请求绕过验证机制，远程执行任意代码，导致数据泄露或服务器完全失陷。  
  
**漏洞详情**  
  
**技术原理**  
  
漏洞类型：原型污染 → 远程代码执行  
  
**攻击路径**  
：  
  
文件上传攻击：通过恶意文件污染对象原型链，触发未授权的代码执行逻辑。  
  
HTTP 请求注入：利用未严格校验的用户输入参数，执行高危操作。  
  
**影响版本**  
：  
  
Kibana 8.15.0 至 8.17.0：仅需基础“Viewer”权限即可利用。  
  
Kibana 8.17.1 至 8.17.2：需同时具备 fleet-all、integrations-all 及 actions:execute-advanced-connectors 权限的角色。  
  
**风险等级**  
  
全球影响：扫描显示全球超 34 万台 Kibana 服务器暴露，国内受影响资产约 14.5 万个，涉及金融、互联网、政府等高危行业。  
  
利用难度：低（无需用户交互，POC 暂未公开但存在快速传播风险）。  
  
**修复与缓解方案**  
  
**1. 官方修复**  
  
升级至 Kibana 8.17.3：此版本已彻底修复漏洞，强烈建议立即升级。  
  
**2. 临时措施**  
  
禁用Integration Assistant：在 kibana.yml 配置文件中添加 xpack.integration_assistant.enabled: false 并重启服务。  
  
权限最小化：严格限制用户权限，避免分配 fleet-all 等高危权限。  
  
**3. 长期防护**  
  
定期更新组件：订阅 Elastic 官方安全公告，部署自动化工具（如 Elastic Agent）监控版本状态。  
  
网络隔离：限制 Kibana 的互联网暴露面，部署 WAF 拦截异常请求。  
  
**历史漏洞关联**  
  
Elastic 产品近年频发高危漏洞，需持续关注：  
  
2024年8月：  
原型污染漏洞 CVE-2024-37287（CVSS 9.9）。  
  
2024年9月：反序列化漏洞 CVE-2024-37288（CVSS 9.9）及 CVE-2024-37285（CVSS 9.1）。  
  
**自查与响应**  
  
企业自查：  
  
通过 Kibana 管理界面或命令行检查当前版本。  
  
使用资产测绘工具扫描内网风险资产。  
  
响应建议：若发现入侵痕迹，立即隔离受影响系统并启动取证流程。  
  
  
   END    
  
  
阅读推荐  
  
  
[【安全圈】多地苹果手机用户称使用“免密支付”遭盗刷，客服：账户或被盗，及时申请拦截有望找回](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068317&idx=1&sn=eb54c7cf9dfc74424aae01869833a8b1&scene=21#wechat_redirect)  
  
  
  
[【安全圈】谷歌静默追踪安卓设备，用户未开启任何应用也无法避免](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068317&idx=2&sn=1c03dd97b25a8b7645deecf5c86c3849&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Qilin 勒索软件团伙宣称入侵乌克兰外交部，敏感数据被窃](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068317&idx=3&sn=625fe3e373a2bb5f2651385767cbbeea&scene=21#wechat_redirect)  
  
  
  
[【安全圈】知名黑客组织付费传播恶意软件，第三方安装服务盛行](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068317&idx=4&sn=1225f29ac1887eb632b9fb71f590cff1&scene=21#wechat_redirect)  
  
  
  
[【安全圈】VMware 修复了 ESX 产品中三个被积极利用的零日漏洞](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068293&idx=1&sn=4072ff26a5a85713e31cd4cf30212887&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
