#  我发现了HTTP请求走私并获得了巨大的漏洞赏金！   
 安全狗的自我修养   2025-03-29 13:30  
  
🚀 我是如何发现高薪请求走私漏洞的在我最近的一次漏洞赏金活动中，我发现了一个主要 Web 应用程序中的严重 HTTP 请求走私 （HRS） 漏洞。这个错误对自动扫描程序完全不可见，并导致会话劫持、凭据盗窃，甚至完全帐户接管！💥在本指南中，我将向您展示我是如何找到它、利用它并获得巨额漏洞赏金奖励的！ 💰🔥🕵️ ♂️ 侦察：识别潜在的请求走私目标我正在测试一个使用具有多个后端服务器的反向代理的网站。由于前端和后端服务器之间的 HTTP 解析不匹配，请求走私漏洞经常出现在此类设置中。步骤 1：检查服务器标头使用 和 Burp Suite，我检查了响应标头：curlcurl -I https://target.com响应：HTTP/1.1 200 OK
Server: nginx
X-Backend-Server: apache这表明前端是 nginx，后端是 Apache，使其成为 HTTP 请求走私的完美候选者！🔥 利用 HTTP 请求走私第 2 步：测试 CL.TE 或 TE。CL 异步我使用 Burp Suite 发送了以下格式错误的 HTTP 请求：POST / HTTP/1.1
Host: target.com
Content-Length: 15
Transfer-Encoding: chunked0G
POST /evil HTTP/1.1
Host: target.com
Content-Length: 50malicious_payload_here如果前端服务器读取请求的方式与后端服务器不同，则第二个 POST 请求 （） 可能会被走私并在后端服务器上作为单独的请求执行。/evil第 3 步：观察响应响应显示异常行为，表明可能存在走私漏洞！HTTP/1.1 200 OK
X-Backend-Server: apache
Set-Cookie: session=smuggled_data_here;此时，我知道我有请求走私访问权限！ 🚀⚠️ 现实世界的影响：可以做什么？确认漏洞后，我探讨了其实际影响，其中包括：✅ 会话劫持：窃取用户 cookie 并获得未经授权的访问。✅ 凭据盗窃：注入恶意登录请求以捕获用户名和密码。✅ Web 缓存中毒：纵缓存的响应以提供攻击者控制的内容。✅ 完全帐户接管：走私请求以修改身份验证标头。📩 报告和漏洞赏金奖励我立即向安全团队报告了这个问题。在 48 小时内，他们确认了错误的严重性并授予我巨额赏金！ 💰💥🏆 经验 教训1️⃣ 始终检查 HTTP/1.1 和 HTTP/2 解析不匹配。2️⃣ 寻找 CL.TE 或 TE。CL desync 机会。3️⃣ Burp Suite 的 HTTP Smuggler 扩展是您最好的朋友。4️⃣ 手动测试总是击败自动扫描仪！http://github.com/haidragonhttp://gitee.com/haidragon公众号:安全狗的自我修养bilibili:haidragonx其它相关课程编辑rust语言全栈开发视频教程-第一季(2025最新)详细目录mac/ios安全视频QT开发底层原理与安全逆向视频教程linux文件系统存储与文件过滤安全开发视频教程(2024最新)linux高级usb安全开发与源码分析视频教程linux程序设计与安全开发wwU游iw还windows恶意软件开发与对抗视频教程