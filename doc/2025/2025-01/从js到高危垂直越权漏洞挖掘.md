#  从js到高危垂直越权漏洞挖掘   
白帽子左一  白帽子左一   2025-01-06 04:01  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFbaUgVwdsriauB77CgQS8lyBNAxtx9IMqJQdhuuoITunu8A5Gp7kFjF7BvEXSaLMuDTYhnu7Nicghg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
**来****Track安全社区投稿~**  
  
**赢千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
# 1. 访问目标  
  
在漏洞挖掘时，我们再次遇到一个仅提供登录表单的目标系统，我们尝试通过 **数据泄露监控平台** 寻找可能存在的凭据信息，以便用于登录目标系统。长话短说，我们找到了一组有效的账户信息，从而能够更好地了解该应用程序中的情况。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEjQ3ga4GZG3p4B8FXGmVicOcJLJgxs1ialXA1qYqxWMnn30lE7JekicL1Ue86CL9l92Sjrib3cqSuSrw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
当我们首次登录时，我们立刻认为这只是一个普通用户账户（因为菜单非常简洁）。如果遇到这种情况，我们应该记住一个基本原则：“只要一个应用中有普通用户，通常就会有一个负责管理所有用户的高权限用户”。然而，问题在于我们对这个高权限用户及其菜单（包括端点）的信息一无所知，因为我们手上只有一个普通账户。  
# 2. 分析 .js 文件 — app.bundle.min.js  
  
在仅拥有一个权限受限的账户时，我们能在这种有限的情况下做些什么？从技术上讲，有许多可以尝试的方法，其中一些包括：  
  
尝试通过更改 ID 值或调整某些“看似”容易猜测的值（例如，常见的电子邮件地址，如 **admin@target.tld[1]**、**support@target.tld[2]** 等）来检查可能的访问控制缺陷。  
  
如果更改 ID 值或上述值无效，可以尝试使用不同的 HTTP 方法重新执行（例如，如果之前用 POST 执行，尝试用 GET 执行）。反之亦然。  
  
尝试观察并分析用户会话的创建方式（例如，创建的会话是否具有可预测性）。  
  
尝试一些注入测试（例如：SQL 注入、XSS 等）。  
  
尝试从“低权限”账户直接访问受保护的 URL（但如果端点命名较为独特，则了解该端点的信息显然是必要的）。  
  
在多次测试尝试中，访问受保护的 URL 取得了积极的成果。  
  
可能会有一个问题随之而来：我们难道不需要了解端点的名称吗？比如通过查看管理员账户或者猜测开发人员是否使用了容易猜测的命名约定？”  
  
通常来说，这种说法是正确的。然而，我们也不能忽视一种情况：开发人员“可能”会将所有端点信息放置在 JavaScript 文件中，这些文件可以从客户端查看——这正是发生的情况。因此，当我们退出登录时，我们发现了一个相对较大的 .js 文件，其大小约 **8.91 MB**。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEjQ3ga4GZG3p4B8FXGmVicOsgLrBJicficqWNxk5YicQm1vAYlUdqcokCvgljnwpHUtjSk3337xez7mw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEjQ3ga4GZG3p4B8FXGmVicO1fibv66sMLYCSG5VicS9ia3FZ12uXNvbIxBDEkOBOEbk8H1r3w5aYHwYw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
在审查这些 .js 文件时，我们在 dashboardroutes变量中发现了 30 多个端点信息。我们再次登录，并立刻尝试通过 URL 访问几个已存在的端点。最终，我们发现了一个可以直接访问的端点（**/invite-user**），其中包含了数万条用户数据。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEjQ3ga4GZG3p4B8FXGmVicOg80WibmGFgu9UnlicrfYoibjg3PsM6OKDJ9ic1AIsrS6IKicu8BvJAUJS2w/640?wx_fmt=png&from=appmsg "null")  
  
img  
# 3. /invite-user 端点 — 包含数万用户数据的端点  
  
当我们访问 **/invite-user** 端点时，应用程序立刻显示了一份相当庞大的用户列表。这显然表明该端点存在访问控制缺陷问题。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEjQ3ga4GZG3p4B8FXGmVicO3ic1HibKU7v9y286J9G2c8kQfVuQyPq1BhviaH6SXCOZEobjicz1JLAs7A/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
通常情况下，即使我们只查看姓名和电子邮件地址，攻击者获得的信息实际上远不止这些。基本上，当我们点击任意用户名时，还可以看到电话号码、分支机构等更多信息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEjQ3ga4GZG3p4B8FXGmVicOFb5hGfj8WmRh75okQqKrVYKHDPp6pZeyEOjqeD0pVgclvD9NWBPiaCA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
从这种情况出发，我们立即尝试创建新用户，其目的无非是想看看是否有可能提升刚创建用户的权限。  
# 4. 创建新用户并尝试提升权限  
  
当我们尝试创建用户时，应用程序会向 **/api/users** 发送一个包含大量 JSON 数据的请求。  
```
POST /api/users HTTP/2
Host: api.url_1.xyz-company.com
Content-Length: 340
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.132 Safari/537.36
Authorization: Bearer <bearer_data_here>
Content-Type: application/json
Accept: application/json, text/javascript, */*; q=0.01
Fngprt: <Fngprt_data_here>
Sec-Ch-Ua-Platform: “macOS”
Origin: [https://url_1.xyz-company.com](https://url_1.xyz-company.com/)
Referer: https://url_1.xyz-company.com/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9

{“name”:”Test Account”,”email”:”haktrak_test_account@haktrak-xyz.tld”,”userCountryCode”:”966",”contact”:”13374444",”designation”:””,”department”:””,”branch”:””,”country”:”Saudi Arabia”,”accessLevel”:”2",”userLimit”:””,”domains”:””,”organisationId”:”5f**********************”,”orgAdmin”:false,”twoFactor”:false}
```  
  
如果我们查看用户创建过程中发生的流程，可以看到 “accessLevel” 参数。为了更确定，我们再次检查之前发现的 .js 文件内容（希望能够找到确切的信息，而不仅仅是推测）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEjQ3ga4GZG3p4B8FXGmVicOlaq99syQOmE4Qiab1ThkOWZWkjZN4VM54AVRQWscr5luUSqv5sF3eicw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
简而言之，我们确认了 **accessLevel 99** 代表超级管理员的权限级别。从这里开始，我们尝试创建用户并研究现有的请求。  
  
以下是修改后的请求示例：  
```
{“name”:”Test Account”,”email”:”haktrak_test_account@haktrak-xyz.tld”,”userCountryCode”:”966",”contact”:”13374444",”designation”:””,”department”:””,”branch”:””,”country”:”Saudi Arabia”,”accessLevel”:”99",”userLimit”:””,”domains”:””,”organisationId”:”5f**********************”,”orgAdmin”:false,”twoFactor”:false}
```  
  
请注意，尽管参数较多，但我们只关注 **email** 和 **accessLevel** 参数。原因非常简单，因为 **email** 是用来接收应用程序密码的，而 **accessLevel** 则用于提升我们的权限。  
  
在这种情况下，我们需要将 **accessLevel** 值从 2 更改为 99（即超级管理员），然后继续将请求发送到服务器。  
  
当我们尝试查看我们创建的账户状态时，会发现该账户已经拥有了“超级管理员”权限（这本应仅能创建经理/维护员账户的权限）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEjQ3ga4GZG3p4B8FXGmVicOC6bvjbX9EdKicuvo81FZrvtQYVgZFWhBiaGbVibkRNYibB9MK0HiaeNGPgw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
请注意：在某一时刻，我们发现当用户首次创建时，修改 **accessLevel** 为 99 并未生效（换句话说，角色被恢复为经理）。  
  
如果发生这种情况，我们只需编辑已创建的用户，拦截请求，点击保存（POST 请求），并再次将 **accessLevel** 修改为 99。通过这种方式，我们成功地将该用户的权限提升为超级管理员。  
  
在用户成功创建后，我们立即查看了电子邮件（因为我们找不到创建密码的表单）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEjQ3ga4GZG3p4B8FXGmVicObQZKYM8GEnvIY4LE6nVjZfxlYXoza2U1mkrh7n6WEWJ1gQ33b5sKBA/640?wx_fmt=png&from=appmsg "null")  
  
img  
# 5. 使用超级管理员账户登录  
  
获取密码后，我们立即登录。登录后，门户要求我们更改之前创建的密码（这当然是首次使用后更改密码的一个非常好的做法）。  
  
如果密码已经更改，则说明我们成功以超级管理员身份登录，并且可以访问其中的所有数据。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEjQ3ga4GZG3p4B8FXGmVicOb6JjicAcfn0cCt3ZBpxBdXA7lJFmDFERXobQWjCVha8x2mXHaFLXPibw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
**声明：⽂中所涉及的技术、思路和⼯具仅供以安全为⽬的的学********习交流使⽤，任何⼈不得将其⽤于⾮法⽤途以及盈利等⽬的，否则后果⾃⾏承担。所有渗透都需获取授权！**  
  
**如果你是一个网络安全爱好者，欢迎加入我的知识星球：zk安全知识星球,我们一起进步一起学习。星球不定期会分享一些前沿漏洞，每周安全面试经验、SRC实战纪实等文章分享，微信识别二维码，即可加入。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFIJlRFYoItlJDrScxuTPmfnqibC1ApJ2OKh5sF41qicCo5AvQ4icuG8kbqQxZ5HVypvJ8jZDzsmD37Q/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
