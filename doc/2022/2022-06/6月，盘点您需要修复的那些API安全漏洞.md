#  6月，盘点您需要修复的那些API安全漏洞   
 星阑科技   2022-06-29 14:07  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Cc8QqLUKOeiaFHTFtiatmEIxZQcXOHfyr6GOBM88IeMm28ybjSAHEJKicuQxPxN5L5NFZ5mza2NOnuokf9ant2fUQ/640?wx_fmt=gif "")  
  
  
为了让大家的API更加安全  
  
致力于守护数字世界每一次网络调用  
  
小阑公司 PortalLab实验室的同事们  
  
给大家整理了  
  
6月份的一些API安全漏洞报告  
  
希望大家查漏补缺  
  
及时修复自己API可能出现的漏洞  
  
  
No.1  
  
  
**开放自动化软件OAS平台REST API 的RCE漏洞**  
  
  
**漏洞详情：**开放式自动化软件OAS 平台的REST API功能中存在一个不正确的身份验证漏洞。攻击者可发送一系列恶意HTTP请求导致对REST API的未经验证的使用。  
  
**漏洞危害：**一个API端点允许对平台进行远程管理。攻击者可以使用空白用户名和密码访问相关终端，远程任意访问平台。  
  
**影响范围：**OAS平台V16.00.0121  
  
**漏洞评级**：CVSS 评分为 9.4  
  
  
  
**小阑修复建议**  
  
1. 创建自定义安全组和用户帐户，使其仅具有完成所需任务所需的权限，然后尽可能多地限制默认安全组提供的访问权限。  
  
2. 通过OAS配置工具或REST API创建定制的安全组和用户帐户。成功创建自定义帐户后，应该取消默认安全组的所有权限。  
  
3. 完成这项工作最简单的方法是使用OAS配置工具，方法是导航到Configure > Security菜单，选择Default群组，选择Disable All选择功能，最后应用更改。  
  
4. 如果执行成功，则无论何时以默认用户身份发出请求，都会出现错误。  
  
目前此漏洞已修复，建议用户立即为系统打补丁：  
  
https://openautomationsoftware.com/downloads/  
  
  
  
No.2  
  
  
**开放自动化软件OAS平台REST API访问漏洞**  
  
  
**漏洞详情：**开放自动化软件OAS 平台的OAS引擎SecureTransferFiles功能中存在一个文件写入漏洞。巧尽心思构建的一系列网络请求可导致远程代码执行。攻击者可以发送一系列请求来触发此漏洞。该漏洞源于API端点缺少身份验证，与平台安全文件传输模块中的文件写入漏洞有关。  
  
**漏洞危害：**攻击者可以向允许加载任意文件的API端点发送特殊请求，包括向根用户的SSH目录中的一个新的authorized_keys文件，从而实现完全远程访问。  
  
**影响范围：**OAS 平台V16.00.0112  
  
**漏洞评级**：CVSS 评分为 9.1  
  
  
  
**小阑修复建议**  
  
1. 2022年5月22日发布的版本16.00.0.113中得到了修复。  
  
**补丁链接：**  
  
https://openautomationsoftware.com/downloads/  
  
2.  升级到最新版本的平台，要么明确停用受影响的服务端点。  
  
3. 在不主动配置OAS平台时阻止对配置端口(默认为TCP/58727)的访问。此外，使用专用的用户帐户来运行OAS平台，并确保用户帐户没有绝对必要的权限。  
  
  
No.3  
  
  
**云麦智能秤API存在大规模帐户接管漏洞**  
  
  
**漏洞详情：**云麦智能秤应用的Android和iOS版本存在四个与后端API相关的漏洞。通过这些漏洞可成功实现大规模账户接管。  
  
**漏洞危害：**第一个漏洞允许攻击者绕过每个帐户家庭成员数量的限制。该应用程序只允许在一个家庭中创建16个帐户。第二个漏洞允许通过使用Burp Suite自动化猜测ID来任意枚举用户ID。API没有充分授权对猜测ID的访问，而是返回完整的用户信息，包括敏感的、PII。第三个漏洞是允许使用枚举用户ID从其他人的账户中添加和删除用户。第四个漏洞允许在创建新用户时同时获得刷新令牌和访问令牌，通过Burp Suite中的响应泄露令牌，攻击者可以利用这些令牌组合效地获得永久访问平台的权限。  
  
**影响范围：**Android和iOS版本  
  
  
  
**小阑修复建议**  
  
1.   
确保在后端API中强制执行限制。  
  
2. 针对对象所有者对对象的访问进行完全授权。  
  
3. 始终确保所有API端点都经过身份验证。  
  
  
No.4  
  
  
**Travis CI日志API漏洞**  
  
  
**漏洞详情：**Travis CI 是一个持续集成工具，它帮助软件开发者实现自动化地测试新代码，并将新代码集成到开源项目中。Aqua 研究人员发现，通过该软件的一个 API，可以访问来自 Travis CI 免费用户的多达 7.7 亿条“日志”（即使用户的账号已经删除）。  
  
**影响范围：**攻击者可以从明文存储的日志中，提取出用于登录 GitHub、Docker Hub 和 AWS 等云服务的用户身份验证令牌。研究人员在 800 万份日志样本中，发现了 70000 多个敏感令牌和其他机密凭证。  
  
  
  
**小阑修复建议**  
  
1. 为密钥、令牌和其他机密建立轮换策略。  
  
2. 对密钥和令牌应用最小特权原则。  
  
3. 不要在日志中打印机密、令牌或凭证。  
  
4. 使用供应链安全解决方案(如Argon)扫描您的CI/CD环境，以查找暴露的机密、令牌和凭证，并确保您的帐户配置符合最佳实践。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Cc8QqLUKOeiaevmLhg0ja78E4ic6BvE1PsZFCBxbtaqBjxOCichCqQK4wVzcI4W6ga8v8cKCvQrSeicHdA2rK4GibEw/640?wx_fmt=png "")  
  
  
星阑科技“萤火”API安全分析平台可以支持多种API漏洞的检测。有相关需求的可以在公众号进行留言，或添加“小阑本阑”客服微信进行咨询。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Cc8QqLUKOeiaevmLhg0ja78E4ic6BvE1PsibD2wXzntgurvmCIh0Vk23BFR49KnKiaFzPYP1w2vylKv2B3jmnDx5fQ/640?wx_fmt=jpeg "")  
  
（长按或扫描图中二维码即可添加）  
  
  
  
**关于Portal Lab 实验室**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Cc8QqLUKOeiaevmLhg0ja78E4ic6BvE1Psl57HbRH2NaOqnjTHwiatCrm7CEh1AQXm3I9b2ia99B9AAAm0EHn3Nv8Q/640?wx_fmt=png "")  
  
  
星阑科技 Portal Lab 致力于前沿安全技术研究及能力工具化。主要研究方向为API 安全、应用安全、攻防对抗等领域。实验室成员研究成果曾发表于BlackHat、HITB、BlueHat、KCon、XCon等国内外知名安全会议，并多次发布开源安全工具。未来，Portal Lab将继续以开放创新的态度积极投入各类安全技术研究，持续为安全社区及企业级客户提供高质量技术输出。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Cc8QqLUKOeiaevmLhg0ja78E4ic6BvE1PszB7sFPYfHW43pJOz0Bzw8BRKQNkruYlibJLRAicPkryognQzbrZUYldw/640?wx_fmt=jpeg "")  
  
**关注“星阑PortalLab”公众号**  
  
**了解更多关于API安全的技术知识**  
  
  
**往期 · 推荐**  
  
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg5NjEyMjA5OQ==&mid=2247493811&idx=1&sn=3da3fd4a2ee5def7fc8ccc14ee2c2e9e&chksm=c007452ff770cc398ee950de9929f7e26d62b54a55af159b787e2ecdb166ce2eaa21d911176b&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg5NjEyMjA5OQ==&mid=2247493794&idx=1&sn=eeb9027e18ed53e6ed0615046fd936d7&chksm=c007453ef770cc28b654bfe4c7f32be2fcc21ae1d29bb2708f268dda1bdfc3c3aeb164211673&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg5NjEyMjA5OQ==&mid=2247493793&idx=1&sn=e1a0a28f8b07ff345f01142471694956&chksm=c007453df770cc2bc3e36949855893b4969c679d6915aa2d55c39586081be219404570b09316&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg5NjEyMjA5OQ==&mid=2247493581&idx=1&sn=30f1f4f3783ff0f64666cb9340232d1b&chksm=c0074a51f770c3477c9686b426515dfd0f801ff46130eec7002458b4c0129e37e68c968abdbc&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Cc8QqLUKOehwcHoxicoOah5mxDjLHMZ9RHUxNeibERphRXOj3AEupxt7JyOt3LF1RmmWQibYmicTv2DxM93iaEJhLxw/640?wx_fmt=gif "")  
  
