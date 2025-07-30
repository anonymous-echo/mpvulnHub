> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI3ODk3ODE2OA==&mid=2247484447&idx=1&sn=bc4dfbb6ff0e2b7d8cfb9f60918bf17a

#  n8n安全：从漏洞利用到防御  
亚历啥都大  增益安全   2025-06-24 05:55  
  
本文在原作者授权的情况下进行转载（原文地址：  
https://docs.theangmarcore.ru/artificial-intelligence/ai-core/n8n/n8n-security-from-exploitation-to-defense  
）  
  
在使用"代理"（Telegram机器人、Webhook、Discord机器人等）的n8n系统中，由于输入验证不当和不安全的节点，可能会发生多种攻击。实际研究表明，过去版本的n8n存在认证绕过、过滤器规避和路径遍历等漏洞。  
  
据ZoomEye（中国网络空间测绘引擎）测绘结果表明，全球约  
108,542个n8n系统，主要分布在美国、中国和德国。端口主要分布在5678、443、80。  
  
链接：  
https://www.zoomeye.org/searchResult/report?q=YXBwPSJuOG4i  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GfgZiaPCOARChia1YlwvIjMjvzJaImxlGNuoHhsic8JFZicyzPtxw57UgIvBaWlJxgT911zVMykHsTuFicmia2njY2sw/640?wx_fmt=png&from=appmsg "")  
  
下面我们将探讨主要的攻击类型、其利用技术以及防御策略。  
# 远程代码执行（RCE）  
  
n8n提供了允许在服务器上执行任意命令的节点——例如执行命令  
节点或函数/代码  
节点。如果攻击者能控制这些节点的输入，就可能获得RCE能力。此外，在用户提供的代码中不安全地使用
```
eval()
```

  
可能导致任意JavaScript执行。  
  
实际案例中，曾出现过通过伪造文件路径利用zip-slip注入实现RCE的情况（记录在CVE-2023-27562中）。  
# 注入攻击（SQL、XSS等）  
  
如果来自聊天或网络钩子端点的输入数据直接插入到查询或HTML中，可能导致注入攻击。典型的例子是SQL注入，即通过将用户提供的输入与字符串拼接来构造数据库查询。  
  
在n8n中使用Postgres节点时，可以使用参数化查询来防止注入。然而，在MySQL节点中，参数化功能尚不可用，因此需要手动转义输入。  
  
如果用户提交的数据显示在Web界面或启用了HTML/Markdown发送功能，也可能发生XSS注入。如果没有正确处理特殊字符（<、>、"等），恶意脚本可能在另一个用户的浏览器中执行。  
# 绕过过滤器和授权  
  
简单的过滤器（基于关键词或用户ID）通常可以被绕过。例如，在Telegram机器人中，命令通常以/开头。攻击者可能会插入不可见的Unicode字符（零宽度空格、非连接符等）来伪装命令或部分单词。  
  
同形异义词（看起来相似但属于不同编码的字符）也可用于绕过精确字符串匹配。此外，基于用户的访问限制也可能被规避：如果机器人没有严格验证
```
user_id
```

  
，任何发现它的人（如在著名的"n8n助手"案例中）都可以开始发送命令。  
# 对HTTP/代码节点的攻击  
  
如果工作流接受用户提供的URL并将其传递给HTTP请求节点，攻击者可以利用此功能执行服务器端请求伪造（SSRF），向内部网络或本地文件发出请求。  
  
路径遍历攻击也已知存在：在CVE-2023-27562中，/rest/credential-translation端点存在绕过，允许读取许可目录之外的文件。  
  
同样，包含
```
eval()
```

  
语句的代码执行节点如果接收外部数据，将非常危险。  
# 令牌和数据泄露  
  
如果工作流错误地将令牌或API密钥包含在传出响应中（例如通过Telegram消息或网络钩子响应发送），攻击者可能窃取这些机密。同样，在没有TLS保护的情况下拦截HTTP流量可能暴露敏感凭据。  
  
以下是攻击类型的总结表：  
<table><thead><tr><th data-colwidth="192" style="color: rgb(64, 64, 64);padding: 10px 10px 10px 0px;border-bottom: 1px solid rgb(187, 187, 187);border-top: none;font-weight: 600;font-size: 15px;line-height: 1.72;border-right-color: rgb(187, 187, 187);border-left-color: rgb(187, 187, 187);text-align: left;"><section><span leaf="">攻击类型</span></section></th><th style="color: rgb(64, 64, 64);padding: 10px;border-bottom: 1px solid rgb(187, 187, 187);border-top: none;font-weight: 600;font-size: 15px;line-height: 1.72;border-right-color: rgb(187, 187, 187);border-left-color: rgb(187, 187, 187);text-align: left;"><section><span leaf="">利用方法</span></section></th><th style="color: rgb(64, 64, 64);padding: 10px;border-bottom: 1px solid rgb(187, 187, 187);border-top: none;font-weight: 600;font-size: 15px;line-height: 1.72;border-right-color: rgb(187, 187, 187);border-left-color: rgb(187, 187, 187);text-align: left;"><section><span leaf="">示例防护措施</span></section></th></tr></thead><tbody><tr><td data-colwidth="192" style="padding: 10px 10px 10px 0px;border-bottom: 1px solid rgb(229, 229, 229);font-size: 15px;line-height: 1.72;border-top-color: rgb(229, 229, 229);border-right-color: rgb(229, 229, 229);border-left-color: rgb(229, 229, 229);min-width: 100px;max-width: max(30vw, 320px);"><strong style="font-weight: 600;"><span leaf="">RCE（远程代码执行）</span></strong></td><td style="padding: 10px;border-bottom: 1px solid rgb(229, 229, 229);font-size: 15px;line-height: 1.72;border-top-color: rgb(229, 229, 229);border-right-color: rgb(229, 229, 229);border-left-color: rgb(229, 229, 229);min-width: 100px;max-width: max(30vw, 320px);"><section><span leaf="">通过执行命令/函数节点：传递受控字符串在服务器上执行</span></section></td><td style="padding: 10px;border-bottom: 1px solid rgb(229, 229, 229);font-size: 15px;line-height: 1.72;border-top-color: rgb(229, 229, 229);border-right-color: rgb(229, 229, 229);border-left-color: rgb(229, 229, 229);min-width: 100px;max-width: max(30vw, 320px);"><section><span leaf="">禁用或限制执行/代码节点，禁止运行时使用</span><code style="font-size: 0.875em;font-weight: 500;font-family: Menlo, &#34;Roboto Mono&#34;, &#34;Courier New&#34;, Courier, monospace, Inter, sans-serif;background-color: rgb(236, 236, 236);border-radius: 4px;padding: 0.15rem 0.3rem;"><span leaf="">eval()</span></code><span leaf="">，隔离进程</span></section></td></tr><tr><td data-colwidth="192" style="padding: 10px 10px 10px 0px;border-bottom: 1px solid rgb(229, 229, 229);font-size: 15px;line-height: 1.72;border-top-color: rgb(229, 229, 229);border-right-color: rgb(229, 229, 229);border-left-color: rgb(229, 229, 229);min-width: 100px;max-width: max(30vw, 320px);"><strong style="font-weight: 600;"><span leaf="">SQL注入</span></strong></td><td style="padding: 10px;border-bottom: 1px solid rgb(229, 229, 229);font-size: 15px;line-height: 1.72;border-top-color: rgb(229, 229, 229);border-right-color: rgb(229, 229, 229);border-left-color: rgb(229, 229, 229);min-width: 100px;max-width: max(30vw, 320px);"><section><span leaf="">将恶意SQL注入查询字段（例如通过消息插入</span><code style="font-size: 0.875em;font-weight: 500;font-family: Menlo, &#34;Roboto Mono&#34;, &#34;Courier New&#34;, Courier, monospace, Inter, sans-serif;background-color: rgb(236, 236, 236);border-radius: 4px;padding: 0.15rem 0.3rem;"><span leaf="">&#34;; DROP ...;</span></code><span leaf="">）</span></section></td><td style="padding: 10px;border-bottom: 1px solid rgb(229, 229, 229);font-size: 15px;line-height: 1.72;border-top-color: rgb(229, 229, 229);border-right-color: rgb(229, 229, 229);border-left-color: rgb(229, 229, 229);min-width: 100px;max-width: max(30vw, 320px);"><section><span leaf="">使用参数化查询，转义并验证所有用户输入</span></section></td></tr><tr><td data-colwidth="192" style="padding: 10px 10px 10px 0px;border-bottom: 1px solid rgb(229, 229, 229);font-size: 15px;line-height: 1.72;border-top-color: rgb(229, 229, 229);border-right-color: rgb(229, 229, 229);border-left-color: rgb(229, 229, 229);min-width: 100px;max-width: max(30vw, 320px);"><strong style="font-weight: 600;"><span leaf="">XSS注入</span></strong></td><td style="padding: 10px;border-bottom: 1px solid rgb(229, 229, 229);font-size: 15px;line-height: 1.72;border-top-color: rgb(229, 229, 229);border-right-color: rgb(229, 229, 229);border-left-color: rgb(229, 229, 229);min-width: 100px;max-width: max(30vw, 320px);"><section><span leaf="">将HTML/JS注入机器人消息（Markdown/HTML）或Web界面</span></section></td><td style="padding: 10px;border-bottom: 1px solid rgb(229, 229, 229);font-size: 15px;line-height: 1.72;border-top-color: rgb(229, 229, 229);border-right-color: rgb(229, 229, 229);border-left-color: rgb(229, 229, 229);min-width: 100px;max-width: max(30vw, 320px);"><section><span leaf="">禁用不必要的HTML/Markdown渲染，转义特殊字符，应用内容安全策略（CSP）头</span></section></td></tr><tr><td data-colwidth="192" style="padding: 10px 10px 10px 0px;border-bottom: 1px solid rgb(229, 229, 229);font-size: 15px;line-height: 1.72;border-top-color: rgb(229, 229, 229);border-right-color: rgb(229, 229, 229);border-left-color: rgb(229, 229, 229);min-width: 100px;max-width: max(30vw, 320px);"><strong style="font-weight: 600;"><span leaf="">过滤器/授权绕过</span></strong></td><td style="padding: 10px;border-bottom: 1px solid rgb(229, 229, 229);font-size: 15px;line-height: 1.72;border-top-color: rgb(229, 229, 229);border-right-color: rgb(229, 229, 229);border-left-color: rgb(229, 229, 229);min-width: 100px;max-width: max(30vw, 320px);"><section><span leaf="">发送带有不可见Unicode字符的命令，深度链接（/start payload），或伪造</span><code style="font-size: 0.875em;font-weight: 500;font-family: Menlo, &#34;Roboto Mono&#34;, &#34;Courier New&#34;, Courier, monospace, Inter, sans-serif;background-color: rgb(236, 236, 236);border-radius: 4px;padding: 0.15rem 0.3rem;"><span leaf="">user_id</span></code></section></td><td style="padding: 10px;border-bottom: 1px solid rgb(229, 229, 229);font-size: 15px;line-height: 1.72;border-top-color: rgb(229, 229, 229);border-right-color: rgb(229, 229, 229);border-left-color: rgb(229, 229, 229);min-width: 100px;max-width: max(30vw, 320px);"><section><span leaf="">验证用户ID/用户名，限制允许的用户/组列表，实施RBAC和2FA</span></section></td></tr><tr><td data-colwidth="192" style="padding: 10px 10px 10px 0px;border-bottom: 1px solid rgb(229, 229, 229);font-size: 15px;line-height: 1.72;border-top-color: rgb(229, 229, 229);border-right-color: rgb(229, 229, 229);border-left-color: rgb(229, 229, 229);min-width: 100px;max-width: max(30vw, 320px);"><strong style="font-weight: 600;"><span leaf="">SSRF/路径遍历</span></strong></td><td style="padding: 10px;border-bottom: 1px solid rgb(229, 229, 229);font-size: 15px;line-height: 1.72;border-top-color: rgb(229, 229, 229);border-right-color: rgb(229, 229, 229);border-left-color: rgb(229, 229, 229);min-width: 100px;max-width: max(30vw, 320px);"><section><span leaf="">使用HTTP请求节点访问内部资源URL或路径遍历（../）</span></section></td><td style="padding: 10px;border-bottom: 1px solid rgb(229, 229, 229);font-size: 15px;line-height: 1.72;border-top-color: rgb(229, 229, 229);border-right-color: rgb(229, 229, 229);border-left-color: rgb(229, 229, 229);min-width: 100px;max-width: max(30vw, 320px);"><section><span leaf="">验证URL（使用域名白名单），更新n8n至已修补CVE的版本</span></section></td></tr><tr><td data-colwidth="192" style="padding: 10px 10px 10px 0px;border-bottom: 1px solid rgb(229, 229, 229);font-size: 15px;line-height: 1.72;border-top-color: rgb(229, 229, 229);border-right-color: rgb(229, 229, 229);border-left-color: rgb(229, 229, 229);min-width: 100px;max-width: max(30vw, 320px);"><strong style="font-weight: 600;"><span leaf="">令牌/机密泄露</span></strong></td><td style="padding: 10px;border-bottom: 1px solid rgb(229, 229, 229);font-size: 15px;line-height: 1.72;border-top-color: rgb(229, 229, 229);border-right-color: rgb(229, 229, 229);border-left-color: rgb(229, 229, 229);min-width: 100px;max-width: max(30vw, 320px);"><section><span leaf="">通过传入/传出数据或日志泄露令牌/API密钥</span></section></td><td style="padding: 10px;border-bottom: 1px solid rgb(229, 229, 229);font-size: 15px;line-height: 1.72;border-top-color: rgb(229, 229, 229);border-right-color: rgb(229, 229, 229);border-left-color: rgb(229, 229, 229);min-width: 100px;max-width: max(30vw, 320px);"><section><span leaf="">将令牌存储在环境变量或安全保险库中，静态加密，避免在响应中暴露，使用HTTPS</span></section></td></tr></tbody></table># 漏洞利用（模拟攻击者）  
  
攻击通常从与Telegram机器人或其他n8n前端的交互开始，无需访问管理面板。攻击者可能会找到一个公共机器人链接（或网络钩子端点）并发送特制的请求。例如：  
## 通过Telegram  
  
向机器人发送各种命令和文本，包括通过深度链接（t.me/  
<bot>  
?start=PAYLOAD）传递数据。值得检查机器人是否处理带有Markdown/HTML的消息——插入特殊字符如*、
```
<code>
```

  
、标签如
```
<i>
```

  
、
```
<a>
```

  
等，看看是否会出现解析错误或XSS。Unicode字符（零宽度空格、非连接符等）有助于隐藏命令内容，绕过简单过滤器。  
## 通过Webhook  
  
如果使用Webhook节点，攻击者可以发送伪造的JSON请求，假装来自Telegram：包含字段如update_id、message等。这允许"伪造"来自机器人任何用户的消息。例如，在JSON中包含from.id、text等字段，并将其发送到公共Webhook地址。  
## 特殊字符和数据格式  
  
攻击者尝试输入意外的字符（修改后的Unicode符号、URL编码、Base64等）以破坏输入验证。如果工作流包含基于文本内容的条件节点（IF），他们可以通过稍微更改字符串（用相似字母替换、添加标记）来绕过它们。  
### 测试业务逻辑  
  
例如，如果机器人允许执行任意代码或查询，注入诸如
```
; DROP TABLE
```

  
用于SQL或
```
payload
```

  
用于JS的有效负载。如果工作流接受用户提供的URL，输入
```
http://localhost/secret
```

  
或
```
file:///etc/passwd
```

  
以测试SSRF/LFI。  
### 工具示例  
  
像BotFuzzer这样的框架可用于全面发现Telegram机器人中的漏洞。它自动枚举机器人命令和状态（类似于DFS），发现未经测试的逻辑路径。模糊测试研究表明，这些技术能有效检测SQL注入和缓冲区溢出。在n8n工作流中，可以通过向Telegram/Webhook和HTTP请求节点发送随机或格式错误的数据来构建类似的"模糊测试器"。  
# 安全测试  
  
对于开发人员和安全专家来说，主动测试工作流的弹性非常重要。  
### 攻击模拟  
  
在单独的安全环境中，模拟攻击者消息。可以编写模拟Telegram Bot API行为的自动化测试，或手动使用Postman/CURL等工具测试Webhook。最重要的是确保没有机密（数据库查询、环境变量）泄露到响应中。  
### 记录可疑活动  
  
设置所有传入消息和响应的日志记录。日志分析（例如通过ELK/Kibana）有助于检测异常模式——多次处理错误、重复失败命令或尝试访问不存在的资源。这与一般监控建议一致："定期检查日志中的可疑活动"。  
### 输入模糊测试  
  
定向模糊测试有助于发现验证缺陷。例如，为Telegram消息字段（文本、标题、JSON参数）自动生成随机字符串。如模糊测试评论所述，此方法能有效检测意外漏洞。现成的框架如BotFuzzer或自定义脚本可以向机器人发送不同的命令和符号。手动审查函数/代码节点的使用也很有用——确保它们不会使用
```
eval()
```

  
运行未知数据。  
# 防护措施  
  
最后，为最小化风险，应采取以下措施。  
## 过滤和验证消息  
  
清理并验证所有传入数据。例如，如果机器人不应接受HTML，从文本中删除
```
</>
```

  
标签。转义特殊字符很重要（将
```
<
```

  
转换为
```
&lt;
```

  
等）。对于SQL查询——强制参数化。如果可能接收用户提供的JSON，严格根据模式（JSON Schema）验证并禁止危险键。在Telegram机器人中，过滤
```
user_id
```

  
并仅允许来自受信任用户/组的命令（白名单）是有意义的。  
## 安全工作流设计  
  
避免潜在危险的节点。n8n允许阻止节点（节点阻止），例如执行命令或代码节点，它们运行第三方代码。如果仍需要函数节点，确保内部没有
```
eval
```

  
。对于计算，首选强类型操作（例如JSON模板而非JS代码）。此外，不要使用HTTP请求直接获取来自用户的变量而不验证。定期更新n8n：许多已知漏洞（CVE-2023-27562、CVE-2023-27564等）已在版本≥0.216.1中修复。  
## 访问和权限限制  
  
实施完整的认证系统。使用基于角色的访问控制和双因素认证。如果机器人在群组中工作，启用私有模式（避免接收外部消息）或验证
```
chat_id
```

  
。连接Webhook时，要求秘密令牌（Webhook Token），以便外部人员无法发送请求。限制运行n8n的帐户权限（例如Linux用户
```
n8n
```

  
不应具有root访问权限）。  
## 令牌和机密保护  
  
切勿以明文存储密钥。n8n在磁盘上加密凭据，因此配置可靠的加密密钥（环境变量
```
NBN_ENCRYPTION_KEY
```

  
）。尽可能使用外部机密存储（HashiCorp Vault、AWS Secrets Manager）。切勿将机器人令牌插入消息文本或日志中。为所有请求（Telegram API、Webhook等）提供HTTPS——这将防止网络中的令牌拦截。  
## 额外措施  
  
对传入的Webhook应用速率限制以防止DoS和暴力攻击。为n8n Web界面使用内容安全策略。定期进行渗透测试：尝试模拟已知攻击者（SQLi、SSRF等）并检查是否被阻止。这种多层防护（"深度防御"）是自动化代理安全的关键。  
# 常见n8n攻击  
## 1. 通过公开暴露的n8n实例攻击  
  
**如何发现n8n实例**  
- **Shodan / Censys / ZoomEye互联网扫描**  
  
公共n8n实例（尤其是在端口5678、80、443上）会被搜索引擎索引，使用如下查询：  
  

```
app=&#34;n8n&#34; (ZoomEye)
title=&#34;n8n&#34;
iconhash=&#34;8ad475e8b10ff8bcff648ae6d49c88ae&#34;
```

#       
# 搜索错误或头信息简单的curl命令：curl -I http://example.com 可能会显示x-powered-by: n8n也可以标识出来。  
# 例如直接使用ZoomEye搜索带有n8n响应header的内容：（http.header="n8n"）  
# 链接：https://www.zoomeye.org/searchResult?q=aHR0cC5oZWFkZXI9Im44biI%3D  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GfgZiaPCOARChia1YlwvIjMjvzJaImxlGNxaKM4ZTFld10micX95GAojOSxa3IN0eianWTxicEfibibHPF0hpQKfHupwQ/640?wx_fmt=png&from=appmsg "")  
#   
# 带有前缀如n8n.或workflow.的域名像n8n.domain.ru、workflow.domain.com这样的域名经常通过DNS暴力破解被发现。  
# 反向IP查找或者Hostname发现如果您的n8n运行在VPS上，且该IP曾出现在其他地方（例如另一个网站或服务），攻击者可以查找相关域名并发现n8n。  
# 例如通过ZoomEye可以通过hostname="n8n"进行搜索  
# 链接：https://www.zoomeye.org/searchResult?q=aG9zdG5hbWU9Im44biI%3D  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GfgZiaPCOARChia1YlwvIjMjvzJaImxlGNLFQv4Aanvw3ibLfGxpZdFy30HfDG6b3oUXj3qArpdVf5IIALGqPgz7Q/640?wx_fmt=png&from=appmsg "")  
#   
  
**攻击者能做什么？？？**  
  
**对您的域名或IP进行DDoS**  
  
没有防护的情况下，大量HTTP请求很容易使n8n崩溃——尤其是在弱服务器上。常见目标：/webbook/或/rest_endpoints。  
  
**暴力破解或自动化API模糊测试**  
  
如果界面暴露，机器人可以在几秒钟内测试数百个路径（/rest/executions、/rest/credentials、/rest/workflows）并尝试提取数据。  
  
**基于CVE的漏洞扫描**  
  
知道是n8n及其版本后，攻击者可能利用已知漏洞，如：  
  
○ CVE-2023-27562（路径遍历）  
  
○ CVE-2023-27564（凭据泄露）  
  
以及其他关键问题。  
  
**通过Docker配置错误自动化利用**  
  
如果您错误地暴露了端口如5678、15672（RabbitMQ）或3306（MySQL），攻击者会发现并访问它们。  
## 2. 通过基于n8n的公共Telegram机器人泄露数据  
  
以这个例子为例：Reddit上的用户发现可以通过搜索"n8n助手"找到其他人的n8n机器人。然后只需发送一条消息——机器人就会回复，将所有者的私人数据（日历事件、会议、电子邮件）暴露给匿名陌生人。  
  
**发生原因：**  
- 机器人公开可访问——未强制执行
```
user_id
```

  
白名单。  
  
- 任何人都可以与之交互并接收响应。  
  
- 没有输入过滤——工作流首先获取数据（例如日历信息），然后才检查权限——但为时已晚。  
  
**后果：**  
- 个人信息（会议、电子邮件地址）暴露。  
  
- 如果响应中包含内部令牌或API密钥，可能导致泄露。  
  
**结论：**  
  
这个案例真实且非常严重。即使没有直接的n8n漏洞，机器人也可能成为数据泄露的完美载体。  
  
