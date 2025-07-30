#  网络安全人士必知的 AWVS 漏洞扫描工具  
原创 承影  兰花豆说网络安全   2025-06-07 15:51  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/AiaxibnzDXa1asshEnCgBMF2CiayVQfx8e9XK6C8MH2YkouAoA6DRk6ibnPNQ3eSY4Ejfibh8hy8tOGNLnVoicJlWnIg/640?wx_fmt=gif&from=appmsg "")  
![]( "")  
  
随着网络攻击手段的日益复杂，网站安全成为信息安全防护的重要一环。Web 应用作为企业对外开放的重要窗口，也是攻击者的重点目标。SQL 注入、跨站脚本（XSS）、文件包含、命令执行等常见漏洞频频出现在安全事件中。因此，选择一款高效、全面的 Web 漏洞扫描工具对安全人员来说至关重要。AWVS（Acunetix Web Vulnerability Scanner）作为业界广受认可的漏洞扫描工具，凭借其出色的性能和广泛的漏洞覆盖，成为许多企业和安全团队的首选。  
  
01  
  
AWVS 简介  
  
  
  
AWVS 是 Acunetix 公司开发的一款专注于 Web 应用安全的自动化漏洞扫描工具，支持对网站进行全面的安全检测。它可以在不中断业务的前提下，模拟黑客的攻击方式，自动发现 Web 应用中的各种安全漏洞，并提供详细的分析报告与修复建议。  
  
自 2005 年推出以来，AWVS 不断迭代更新，现已发展为支持现代 Web 技术（如 HTML5、JavaScript、AJAX、REST API 等）的高性能扫描工具。AWVS 目前提供 Windows 桌面版和 Web 服务版，支持本地部署和云端管理。  
  
02  
  
核心功能  
  
  
  
1.   
高精度漏洞识别能力  
  
a.   
 AWVS 可识别 7000 多种已知漏洞类型，包括但不限于：  
SQL 注入（包括盲注、延时注入等）  
  
b.   
跨站脚本攻击（XSS）  
  
c.   
本地/远程文件包含（LFI/RFI）  
  
d.   
命令/代码执行  
  
e.   
弱密码、默认账户  
  
f.   
HTTP 头注入、开放重定向  
  
g.   
目录遍历、信息泄露  
  
h.   
Web 服务器配置错误  
  
2.   
爬虫引擎强大  
  
AWVS 内置高智能的爬虫引擎，可模拟用户行为，深度爬取基于 JavaScript 构建的动态页面，甚至支持带认证的网站扫描（Cookie、Session、Form-Based 登录等），确保最大限度发现可被利用的页面与参数。  
  
3.   
扫描速度快、误报率低  
  
采用并发扫描技术和独特的引擎优化机制，在保证扫描深度的同时控制时间成本。并结合手工验证机制，显著降低误报率。  
  
4.多种集成能力  
  
AWVS 支持与 Jira、GitHub、GitLab、Slack 等开发工具对接，实现漏洞自动分派和跟踪。还可通过 REST API 与 CI/CD 流程无缝集成，实现 DevSecOps 的安全自动化。  
  
5.报告系统丰富专业  
  
内置多种格式的安全报告模板（如 OWASP Top 10、PCI DSS、ISO 27001、HIPAA 等），支持 PDF、HTML、CSV 输出，满足不同受众（安全工程师、开发人员、管理层）的需求。  
  
03  
  
典型使用场景  
##   
  
1.   
企业 Web 系统上线前的安全测试  
  
 在 Web 项目部署上线前，使用 AWVS 对系统进行全面漏洞扫描，发现问题及时修复，防止漏洞进入生产环境。  
  
2.   
日常巡检与合规审计  
  
建立周期性扫描任务，形成常态化安全巡检机制，配合合规要求提交漏洞报告，提升组织安全成熟度。  
  
3.红蓝对抗中的资产摸排与漏洞发现  
  
安全团队可将 AWVS 用作初步漏洞扫描工具，对暴露在公网的 Web 资产进行快速摸排，为后续渗透测试提供支持。  
  
4.  
与开发流程集成，打造“左移”安全开发模型  
  
 将 AWVS 集成到 CI/CD 中，实现代码提交后的自动漏洞检测，提升开发阶段的安全把控能力。  
  
04  
  
使用建议与注意事项  
  
  
  
1.   
合理配置扫描范围和深度  
  
不建议对全站无差别扫描生产环境，以防止业务中断。可结合业务特性配置白名单、限速策略。  
  
2.   
做好资产管理与认证信息维护  
  
保证扫描任务使用的目标 URL、登录信息和 Cookie 为最新有效，避免漏扫或误扫。  
  
3.   
结合手工验证结果  
  
尽管 AWVS 误报率低，但自动化工具仍存在一定误判。建议关键漏洞经人工复查确认。  
  
4.   
关注扫描报告中的安全建议  
  
AWVS 不仅报告漏洞，还提供修复建议及参考资料，开发团队应认真研读并及时修复。  
  
5.   
版本更新与补丁维护  
  
 保持 AWVS 处于最新版本，获取最全的漏洞库和扫描能力。  
  
05  
  
与其他工具对比  
  
  
  
<table><tbody><tr><td data-colwidth="106" width="104.53333333333333"><p style="margin-left: 8px;margin-right: 8px;text-align: center;margin-bottom: 8px;line-height: 2em;font-size: 12px;"><span data-font-family="微软雅黑" style=""><span leaf="" style="color: rgba(0, 0, 0, 0.9);font-family: mp-quote, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.034em;font-style: normal;font-weight: normal;"><span textstyle="" style="letter-spacing: 1px;font-weight: bold;">工具</span></span></span><span style="font-family: 微软雅黑;font-weight: normal;font-style: normal;color: rgb(51, 51, 51);letter-spacing: 0pt;vertical-align: baseline;" lang="EN-US"><o:p></o:p></span></p></td><td data-colwidth="262.46666666666664" width="262.46666666666664"><p style="margin-left: 8px;margin-right: 8px;text-align: center;margin-bottom: 8px;line-height: 2em;font-size: 12px;"><span data-font-family="微软雅黑" style=""><span leaf="" style="color: rgba(0, 0, 0, 0.9);font-family: mp-quote, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.034em;font-style: normal;font-weight: normal;"><span textstyle="" style="letter-spacing: 1px;font-weight: bold;">优势</span></span></span><span style="font-family: 微软雅黑;font-weight: normal;font-style: normal;color: rgb(51, 51, 51);letter-spacing: 0pt;vertical-align: baseline;" lang="EN-US"><o:p></o:p></span></p></td><td data-colwidth="200" width="227.06666666666666"><p style="margin-left: 8px;margin-right: 8px;text-align: center;margin-bottom: 8px;line-height: 2em;font-size: 12px;"><span data-font-family="微软雅黑" style=""><span leaf="" style="color: rgba(0, 0, 0, 0.9);font-family: mp-quote, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.034em;font-style: normal;font-weight: normal;"><span textstyle="" style="letter-spacing: 1px;font-weight: bold;">不足</span></span></span><span style="font-family: 微软雅黑;font-weight: normal;font-style: normal;color: rgb(51, 51, 51);letter-spacing: 0pt;vertical-align: baseline;" lang="EN-US"><o:p></o:p></span></p></td></tr><tr><td data-colwidth="106" width="104.53333333333333"><p style="margin-left: 8px;margin-right: 8px;text-align: justify;margin-bottom: 8px;line-height: 2em;font-size: 12px;"><span data-font-family="微软雅黑" style=""><span leaf="" style="color: rgba(0, 0, 0, 0.9);font-family: mp-quote, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.034em;font-style: normal;font-weight: normal;"><span textstyle="" style="letter-spacing: 1px;">AWVS</span></span></span><span style="font-family: 微软雅黑;font-weight: normal;font-style: normal;color: rgb(51, 51, 51);letter-spacing: 0pt;vertical-align: baseline;" lang="EN-US"><o:p></o:p></span></p></td><td data-colwidth="262.46666666666664" width="262.46666666666664"><p style="margin-left: 8px;margin-right: 8px;text-align: justify;margin-bottom: 8px;line-height: 2em;font-size: 12px;"><span data-font-family="微软雅黑" style=""><span leaf="" style="color: rgba(0, 0, 0, 0.9);font-family: mp-quote, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.034em;font-style: normal;font-weight: normal;"><span textstyle="" style="letter-spacing: 1px;">界面友好、误报低、支持多种漏洞类型、报告专业</span></span></span><span style="font-family: 微软雅黑;font-weight: normal;font-style: normal;color: rgb(51, 51, 51);letter-spacing: 0pt;vertical-align: baseline;" lang="EN-US"><o:p></o:p></span></p></td><td data-colwidth="200" width="227.06666666666666"><p style="margin-left: 8px;margin-right: 8px;text-align: justify;margin-bottom: 8px;line-height: 2em;font-size: 12px;"><span data-font-family="微软雅黑" style=""><span leaf="" style="color: rgba(0, 0, 0, 0.9);font-family: mp-quote, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.034em;font-style: normal;font-weight: normal;"><span textstyle="" style="letter-spacing: 1px;">商业软件，费用较高</span></span></span><span style="font-family: 微软雅黑;font-weight: normal;font-style: normal;color: rgb(51, 51, 51);letter-spacing: 0pt;vertical-align: baseline;" lang="EN-US"><o:p></o:p></span></p></td></tr><tr><td data-colwidth="106" width="104.53333333333333"><p style="margin-left: 8px;margin-right: 8px;text-align: justify;margin-bottom: 8px;line-height: 2em;font-size: 12px;"><span data-font-family="微软雅黑" style=""><span leaf="" style="color: rgba(0, 0, 0, 0.9);font-family: mp-quote, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.034em;font-style: normal;font-weight: normal;"><span textstyle="" style="letter-spacing: 1px;">Burp Suite</span></span></span><span style="font-family: 微软雅黑;font-weight: normal;font-style: normal;color: rgb(51, 51, 51);letter-spacing: 0pt;vertical-align: baseline;" lang="EN-US"><o:p></o:p></span></p></td><td data-colwidth="262.46666666666664" width="262.46666666666664"><p style="margin-left: 8px;margin-right: 8px;text-align: justify;margin-bottom: 8px;line-height: 2em;font-size: 12px;"><span data-font-family="微软雅黑" style=""><span leaf="" style="color: rgba(0, 0, 0, 0.9);font-family: mp-quote, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.034em;font-style: normal;font-weight: normal;"><span textstyle="" style="letter-spacing: 1px;">拦截器强大，适合手动测试</span></span></span><span style="font-family: 微软雅黑;font-weight: normal;font-style: normal;color: rgb(51, 51, 51);letter-spacing: 0pt;vertical-align: baseline;" lang="EN-US"><o:p></o:p></span></p></td><td data-colwidth="200" width="227.06666666666666"><p style="margin-left: 8px;margin-right: 8px;text-align: justify;margin-bottom: 8px;line-height: 2em;font-size: 12px;"><span data-font-family="微软雅黑" style=""><span leaf="" style="color: rgba(0, 0, 0, 0.9);font-family: mp-quote, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.034em;font-style: normal;font-weight: normal;"><span textstyle="" style="letter-spacing: 1px;">自动化扫描能力不如 AWVS</span></span></span><span style="font-family: 微软雅黑;font-weight: normal;font-style: normal;color: rgb(51, 51, 51);letter-spacing: 0pt;vertical-align: baseline;" lang="EN-US"><o:p></o:p></span></p></td></tr><tr><td data-colwidth="106" width="104.53333333333333"><p style="margin-left: 8px;margin-right: 8px;text-align: justify;margin-bottom: 8px;line-height: 2em;font-size: 12px;"><span data-font-family="微软雅黑" style=""><span leaf="" style="color: rgba(0, 0, 0, 0.9);font-family: mp-quote, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.034em;font-style: normal;font-weight: normal;"><span textstyle="" style="letter-spacing: 1px;">OpenVAS</span></span></span><span style="font-family: 微软雅黑;font-weight: normal;font-style: normal;color: rgb(51, 51, 51);letter-spacing: 0pt;vertical-align: baseline;" lang="EN-US"><o:p></o:p></span></p></td><td data-colwidth="262.46666666666664" width="262.46666666666664"><p style="margin-left: 8px;margin-right: 8px;text-align: justify;margin-bottom: 8px;line-height: 2em;font-size: 12px;"><span data-font-family="微软雅黑" style=""><span leaf="" style="color: rgba(0, 0, 0, 0.9);font-family: mp-quote, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.034em;font-style: normal;font-weight: normal;"><span textstyle="" style="letter-spacing: 1px;">免费开源、支持网络设备扫描</span></span></span><span style="font-family: 微软雅黑;font-weight: normal;font-style: normal;color: rgb(51, 51, 51);letter-spacing: 0pt;vertical-align: baseline;" lang="EN-US"><o:p></o:p></span></p></td><td data-colwidth="200" width="227.06666666666666"><p style="margin-left: 8px;margin-right: 8px;text-align: justify;margin-bottom: 8px;line-height: 2em;font-size: 12px;"><span data-font-family="微软雅黑" style=""><span leaf="" style="color: rgba(0, 0, 0, 0.9);font-family: mp-quote, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.034em;font-style: normal;font-weight: normal;"><span textstyle="" style="letter-spacing: 1px;">Web 漏洞识别能力不如 AWVS</span></span></span><span style="font-family: 微软雅黑;font-weight: normal;font-style: normal;color: rgb(51, 51, 51);letter-spacing: 0pt;vertical-align: baseline;" lang="EN-US"><o:p></o:p></span></p></td></tr><tr><td data-colwidth="106" width="104.53333333333333"><p style="margin-left: 8px;margin-right: 8px;text-align: justify;margin-bottom: 8px;line-height: 2em;font-size: 12px;"><span data-font-family="微软雅黑" style=""><span leaf="" style="color: rgba(0, 0, 0, 0.9);font-family: mp-quote, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.034em;font-style: normal;font-weight: normal;"><span textstyle="" style="letter-spacing: 1px;">Nikto</span></span></span><span style="font-family: 微软雅黑;font-weight: normal;font-style: normal;color: rgb(51, 51, 51);letter-spacing: 0pt;vertical-align: baseline;" lang="EN-US"><o:p></o:p></span></p></td><td data-colwidth="262.46666666666664" width="262.46666666666664"><p style="margin-left: 8px;margin-right: 8px;text-align: justify;margin-bottom: 8px;line-height: 2em;font-size: 12px;"><span data-font-family="微软雅黑" style=""><span leaf="" style="color: rgba(0, 0, 0, 0.9);font-family: mp-quote, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.034em;font-style: normal;font-weight: normal;"><span textstyle="" style="letter-spacing: 1px;">轻量快速、适合信息收集阶段</span></span></span><span style="font-family: 微软雅黑;font-weight: normal;font-style: normal;color: rgb(51, 51, 51);letter-spacing: 0pt;vertical-align: baseline;" lang="EN-US"><o:p></o:p></span></p></td><td data-colwidth="200" width="227.06666666666666"><p style="margin-left: 8px;margin-right: 8px;text-align: justify;margin-bottom: 8px;line-height: 2em;font-size: 12px;" data-mpa-action-id="mbmeejzvi0r"><span data-font-family="微软雅黑" style=""><span leaf="" style="color: rgba(0, 0, 0, 0.9);font-family: mp-quote, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.034em;font-style: normal;font-weight: normal;"><span textstyle="" style="letter-spacing: 1px;">报告简单、精度低</span></span></span><span style="font-family: 微软雅黑;font-weight: normal;font-style: normal;color: rgb(51, 51, 51);letter-spacing: 0pt;vertical-align: baseline;" lang="EN-US"><o:p></o:p></span></p></td></tr></tbody></table>  
  
  
06  
  
结语  
  
  
  
AWVS 作为 Web 安全测试工具中的佼佼者，适合应用于漏洞挖掘、安全评估、DevSecOps 等多个场景，是网络安全人员的“利器”之一。它不仅帮助我们发现漏洞，更帮助我们建立起面向未来的安全防线。作为网络安全从业者，熟练掌握 AWVS 的使用和原理，是提升自身实战能力的重要一步。  
  
推荐阅读  
  
[网络安全人士必知的sql注入靶场sqli-labs](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247491381&idx=2&sn=3b0ea3eea9271dad4efb2ee0ee85319e&scene=21#wechat_redirect)  
  
  
2025-05-27  
  
[](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247491381&idx=2&sn=3b0ea3eea9271dad4efb2ee0ee85319e&scene=21#wechat_redirect)  
  
  
[网络安全人士必知的字典生成利器：pydictor](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247491263&idx=1&sn=c79282c55b62b710369f415f67b39f17&scene=21#wechat_redirect)  
  
  
2025-05-08  
  
[](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247491263&idx=1&sn=c79282c55b62b710369f415f67b39f17&scene=21#wechat_redirect)  
  
  
[网络安全人士必知的MCP和A2A协议](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247491042&idx=1&sn=b05e37c4ca06231b25d4a531cdd73600&scene=21#wechat_redirect)  
  
  
2025-04-17  
  
[](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247491042&idx=1&sn=b05e37c4ca06231b25d4a531cdd73600&scene=21#wechat_redirect)  
  
  
[网络安全人士必知的AI渗透工具pentagi](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247491025&idx=1&sn=2f63e90105f6d17569b78327fe02343e&scene=21#wechat_redirect)  
  
  
2025-04-13  
  
[](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247491025&idx=1&sn=2f63e90105f6d17569b78327fe02343e&scene=21#wechat_redirect)  
  
  
[网络安全人士必知的密码提取工具Mimikatz](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247490665&idx=1&sn=dbe421cf478406e343273007f983f03a&scene=21#wechat_redirect)  
  
  
2025-03-21  
  
[](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247490665&idx=1&sn=dbe421cf478406e343273007f983f03a&scene=21#wechat_redirect)  
  
  
[网络安全人士必知的子域名挖掘工具Sublist3r](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247490631&idx=1&sn=f35d4cad9d184ce6d520d3c10d6e55c0&scene=21#wechat_redirect)  
  
  
2025-03-17  
  
[](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247490631&idx=1&sn=f35d4cad9d184ce6d520d3c10d6e55c0&scene=21#wechat_redirect)  
  
  
[网络安全人士必知的webshell哥斯拉](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247490584&idx=1&sn=07162841abb8881747cc29c826c72e4e&scene=21#wechat_redirect)  
  
  
2025-03-09  
  
[](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247490584&idx=1&sn=07162841abb8881747cc29c826c72e4e&scene=21#wechat_redirect)  
  
  
[网络安全人士必知的7款网络指纹识别工具](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247490564&idx=1&sn=cf14db458732ace8a34e2a4eb385b1bc&scene=21#wechat_redirect)  
  
  
2025-03-07  
  
[](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247490564&idx=1&sn=cf14db458732ace8a34e2a4eb385b1bc&scene=21#wechat_redirect)  
  
  
[网络安全人士必知的黑客工具NanoCore](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247490547&idx=1&sn=1574d0459983605de74bc81d8fdc82b5&scene=21#wechat_redirect)  
  
  
2025-03-05  
  
[](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247490547&idx=1&sn=1574d0459983605de74bc81d8fdc82b5&scene=21#wechat_redirect)  
  
  
[网络安全人士必知的漏扫工具Nikto](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247490480&idx=1&sn=31599f7570d6846928548423f40cf864&scene=21#wechat_redirect)  
  
  
2025-02-24  
  
[](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247490480&idx=1&sn=31599f7570d6846928548423f40cf864&scene=21#wechat_redirect)  
  
  
[网络安全人士必知的目录爆破工具Dirsearch](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247490475&idx=1&sn=f2a699b341b4006ce5d5846e490b652e&scene=21#wechat_redirect)  
  
  
2025-02-23  
  
[](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247490475&idx=1&sn=f2a699b341b4006ce5d5846e490b652e&scene=21#wechat_redirect)  
  
  
[网络安全人士必知的 Nuclei 工具](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247490462&idx=1&sn=5dd39b5e7a6970a3d6114434661d2aa2&scene=21#wechat_redirect)  
  
  
2025-02-20  
  
[](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247490462&idx=1&sn=5dd39b5e7a6970a3d6114434661d2aa2&scene=21#wechat_redirect)  
  
  
[网络安全人士必知的扫描利器masscan](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247490452&idx=1&sn=e0cc8078b50c3c2811f9311e0ac6978b&scene=21#wechat_redirect)  
  
  
2025-02-19  
  
[](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247490452&idx=1&sn=e0cc8078b50c3c2811f9311e0ac6978b&scene=21#wechat_redirect)  
  
  
[网络安全人士必知的指纹探测技术](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247490447&idx=1&sn=c76f4f8d6bc8c35d6bfa414da48951d4&scene=21#wechat_redirect)  
  
  
2025-02-18  
  
[](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247490447&idx=1&sn=c76f4f8d6bc8c35d6bfa414da48951d4&scene=21#wechat_redirect)  
  
  
[网络安全人士必知的3种数据存储技术](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247490441&idx=1&sn=a3c60e75d258fa1e0bb1aa7b31c90503&scene=21#wechat_redirect)  
  
  
2025-02-16  
  
[](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247490441&idx=1&sn=a3c60e75d258fa1e0bb1aa7b31c90503&scene=21#wechat_redirect)  
  
  
[网络安全人士必知的6款全球实时网络威胁地图](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247490231&idx=1&sn=486bf7f0ed03d9e461183332e8287f01&scene=21#wechat_redirect)  
  
  
2025-01-10  
  
[](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247490231&idx=1&sn=486bf7f0ed03d9e461183332e8287f01&scene=21#wechat_redirect)  
  
  
[网络安全人士必知的社工利器seeker](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247490171&idx=1&sn=136b4f0ecc786eb1396d514e88af5cb6&scene=21#wechat_redirect)  
  
  
2025-01-04  
  
[](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247490171&idx=1&sn=136b4f0ecc786eb1396d514e88af5cb6&scene=21#wechat_redirect)  
  
  
[网络安全人士必知的CMS系统有哪些？](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247490154&idx=1&sn=6f38004748245e584776f5e54a948df4&scene=21#wechat_redirect)  
  
  
2025-01-01  
  
[](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247490154&idx=1&sn=6f38004748245e584776f5e54a948df4&scene=21#wechat_redirect)  
  
  
[网络安全人士必知的渗透工具Viper](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247490097&idx=1&sn=1f49a266fb6279c159ae92b6946889e5&scene=21#wechat_redirect)  
  
  
2024-12-21  
  
[](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247490097&idx=1&sn=1f49a266fb6279c159ae92b6946889e5&scene=21#wechat_redirect)  
  
  
[网络安全人士必知的CSF 2.0安全框架](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247490014&idx=1&sn=aa44ce358e979a33e7ef99cb9da1312e&scene=21#wechat_redirect)  
  
  
2024-12-12  
  
[](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247490014&idx=1&sn=aa44ce358e979a33e7ef99cb9da1312e&scene=21#wechat_redirect)  
  
  
[网络安全人士必知的国产密码知识和行业前景](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247489785&idx=1&sn=b330a66c19bc49250719c645e0a2ea7d&scene=21#wechat_redirect)  
  
  
2024-11-16  
  
[](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247489785&idx=1&sn=b330a66c19bc49250719c645e0a2ea7d&scene=21#wechat_redirect)  
  
  
[网络安全人士必知的10种免费/开源WAF产品](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247489762&idx=1&sn=0b512b7a9593025b0cc326de066832b4&scene=21#wechat_redirect)  
  
  
2024-11-13  
  
[](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247489762&idx=1&sn=0b512b7a9593025b0cc326de066832b4&scene=21#wechat_redirect)  
  
  
[网络安全人士必知的iptables四表五链](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247489750&idx=1&sn=d20172dcbd7d449b9c4c42666d601588&scene=21#wechat_redirect)  
  
  
2024-11-12  
  
[](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247489750&idx=1&sn=d20172dcbd7d449b9c4c42666d601588&scene=21#wechat_redirect)  
  
  
[网络安全人士必知的10种流量采集协议](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247489698&idx=1&sn=55715cba5390f0d3ba713920314654af&scene=21#wechat_redirect)  
  
  
2024-11-02  
  
[](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247489698&idx=1&sn=55715cba5390f0d3ba713920314654af&scene=21#wechat_redirect)  
  
  
[网络安全人士必知的3大访问控制模型](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247488163&idx=1&sn=cc849fc4c3d45cfd9e4ab19404cb6ab6&scene=21#wechat_redirect)  
  
  
2024-06-22  
  
[](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247488163&idx=1&sn=cc849fc4c3d45cfd9e4ab19404cb6ab6&scene=21#wechat_redirect)  
  
  
[网络安全人士必知的AI框架](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247485533&idx=1&sn=cfefef99009b7deea311a5de1f009b48&scene=21#wechat_redirect)  
  
  
2024-02-20  
  
[](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247485533&idx=1&sn=cfefef99009b7deea311a5de1f009b48&scene=21#wechat_redirect)  
  
  
[网络安全人士必知的人工智能对抗模型MITRE ATLAS](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247485379&idx=1&sn=fb91e52fb4f4401c368b1eb034b4e3d2&scene=21#wechat_redirect)  
  
  
2024-01-27  
  
[](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247485379&idx=1&sn=fb91e52fb4f4401c368b1eb034b4e3d2&scene=21#wechat_redirect)  
  
  
[网络安全人士必知的AI专业术语](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247485354&idx=1&sn=c3c5c39e4be46f9ef587d7be4cf50ade&scene=21#wechat_redirect)  
  
  
2024-01-21  
  
[](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247485354&idx=1&sn=c3c5c39e4be46f9ef587d7be4cf50ade&scene=21#wechat_redirect)  
  
  
[网络安全人士必知的14个威胁建模方法](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247485294&idx=1&sn=9b880357547e8c04e5e1e62da33536b5&scene=21#wechat_redirect)  
  
  
2024-01-07  
  
[](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247485294&idx=1&sn=9b880357547e8c04e5e1e62da33536b5&scene=21#wechat_redirect)  
  
  
[网络安全人士必知的5个软件安全开发模型](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247485240&idx=1&sn=a5cb49f868b26ca0d5d2b3cdbbe9c05b&scene=21#wechat_redirect)  
  
  
2023-12-24  
  
[](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247485240&idx=1&sn=a5cb49f868b26ca0d5d2b3cdbbe9c05b&scene=21#wechat_redirect)  
  
  
[网络安全人士必知的三个攻击模型](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247485232&idx=1&sn=cbd42058fa89527a541ef0c7e8fff9d8&scene=21#wechat_redirect)  
  
  
2023-12-22  
  
[](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247485232&idx=1&sn=cbd42058fa89527a541ef0c7e8fff9d8&scene=21#wechat_redirect)  
  
  
[网络安全人士必知的IOA、IOB、IOC指标](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247485016&idx=1&sn=997fffa7a23b48472129417e7cddbb0e&scene=21#wechat_redirect)  
  
  
2023-11-09  
  
[](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247485016&idx=1&sn=997fffa7a23b48472129417e7cddbb0e&scene=21#wechat_redirect)  
  
  
[网络安全人士必知的35个安全框架及模型](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247484982&idx=1&sn=e716ff3e0fa71f7412503314eec8c7d2&scene=21#wechat_redirect)  
  
  
2023-11-02  
  
[](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247484982&idx=1&sn=e716ff3e0fa71f7412503314eec8c7d2&scene=21#wechat_redirect)  
  
  
[网络安全售前人员必知的kali系统](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247490164&idx=1&sn=0b7bf7547488734b8efd080249525fd8&scene=21#wechat_redirect)  
  
  
2025-01-03  
  
[](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247490164&idx=1&sn=0b7bf7547488734b8efd080249525fd8&scene=21#wechat_redirect)  
  
  
[网络安全从业人员必知的yaml语言](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247488569&idx=1&sn=c897bd9d8b8e2b26e39824e831fc2c52&scene=21#wechat_redirect)  
  
  
2024-07-26  
  
[](https://mp.weixin.qq.com/s?__biz=MzI3NzM5NDA0NA==&mid=2247488569&idx=1&sn=c897bd9d8b8e2b26e39824e831fc2c52&scene=21#wechat_redirect)  
  
  
  
**<本文完>**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/AiaxibnzDXa1asshEnCgBMF2CiayVQfx8e9lNvsInJZxAaoYibO7x4BfcGQXRJwYjnLlQIGPqZDSicGW2sEDbamu7bg/640?wx_fmt=gif&from=appmsg "")  
![]( "")  
  
  
**【兰花豆说网络安全】**  
已开通第5群，诚邀广大网络安全同行进群指导。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/AiaxibnzDXa1ZsXsxFibs3t8ag5xTXibJStBjgYWyQvvccibOE8SllXX1AAS2IOjy0coraQtgSUD1mibnBX4FnIc1mnA/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
![]( "")  
  
**【兰花豆说网络安全】**  
已开通知识星球，收集和分享各种网络安全资料。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/AiaxibnzDXa1asshEnCgBMF2CiayVQfx8e9PespdsD4ribxVSZffa6RfSUXkVnRiaPRUpVOqK8OugJCg4NN7q7bf2rQ/640?wx_fmt=jpeg&from=appmsg "")  
![]( "")  
  
  
