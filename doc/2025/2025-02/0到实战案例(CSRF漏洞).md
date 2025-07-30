#  0到实战案例(CSRF漏洞)   
 sec0nd安全   2025-02-09 15:01  
  
原理  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ASf2g4J3S7bR8OxzYPQ0Q7FFbCJThIFjsf8r7XEy6icRQQe4icib1R9pJV9kxMSN0ZBZVOkpPWFZVj4iaRZIIHzHzw/640?wx_fmt=png "")  
  
1. 用户登录目标网站 A  
  
用户 C 在浏览器中访问 受信任网站 A，输入用户名和密码成功登录，网站 A 生成 Cookie 存储身份信息。  
  
2. 用户访问恶意网站 B  
  
用户 C 没有退出网站 A，又在同一浏览器中打开另一个网页 网站 B（可能是钓鱼站点或被攻击者控制的页面）。  
  
3. 恶意网站 B 发送伪造请求  
  
网站 B 含有攻击代码，会悄悄触发一个请求，让浏览器向 网站 A 发送请求。  
  
4. 浏览器自动带上 Cookie  
  
由于用户 C 已经登录过网站 A，浏览器会 自动附带 Cookie（身份凭证），导致网站 A 误以为这个请求是用户 C 本人发出的。  
  
5. 网站 A 误执行恶意请求  
  
网站 A 信任 Cookie，以用户 C 的身份处理请求，可能导致账号信息被篡改、资金被转移等安全问题。  
  
例如  
:CSRF 就像你登录了银行账户，但同时点开了一个黑客发的钓鱼网页，这个网页偷偷让你的浏览器向银行发送伪造的转账请求，银行误以为是你本人操作，于是帮黑客把钱转走了。  
  
如何挖掘  
  
挖掘核心功能点：  
  
1.  
用户已登录，浏览器持有有效身份凭证（如 Cookie）。  
  
2  
.存在可被伪造的关键操作，且请求未严格验证来源（如修改信息、转账等）。  
  
实战案例:  
  
商城网站，先进行登入，来到个人中心地址管理处，满足以上两条件，点击新增地址，然后提交进行抓包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ASf2g4J3S7bR8OxzYPQ0Q7FFbCJThIFjd3u7T6zxumcIKXJl9Kxzk7qXjuT3hJ9YlcrdLOzaBVZkQ5bxjXp8zg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ASf2g4J3S7bR8OxzYPQ0Q7FFbCJThIFjQnFGvnxP1MrLRluZibjdxQfficfibnbCQDEkmbtTKl2XDByb4m1DUg3Ow/640?wx_fmt=png "")  
  
这带带有reference以及origin，poc里面直接删掉就行，直接使用burpsuite自带的csrf测试工具，右键选择如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ASf2g4J3S7bR8OxzYPQ0Q7FFbCJThIFjRKDANFbrfBibQicvaicScOznsqzBorDdAxqVicptGsl41PUWquDgnAj53g/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ASf2g4J3S7bR8OxzYPQ0Q7FFbCJThIFj2ksSL7ibC98F6fagTuNNYKEQOsVyrxdHYEicefP4Kzsv0Z21mWm2kuUQ/640?wx_fmt=png "")  
  
新增地址的用户名为test666，直接复制html内容，本地新建一个html复制，并用打开目标网站的浏览器打开  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ASf2g4J3S7bR8OxzYPQ0Q7FFbCJThIFjmxSMbVQB0wBy4y0YiabKcQlROJia0zU00ms8G00IGpLLja6t7nZRibW4g/640?wx_fmt=png "")  
  
点击提交进行抓包，将里面的reference等直接删即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ASf2g4J3S7bR8OxzYPQ0Q7FFbCJThIFjToVDhoiclbUSLTmBXN2zjGOgrfJtCdwJr7PogiaYb4JgGfmnstXMxZhQ/640?wx_fmt=png "")  
  
查看地址  成功添加test666  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ASf2g4J3S7bR8OxzYPQ0Q7FFbCJThIFjiarntTduQm546qRwtyvDsiahXtuNIQYYpKjwWzzTQo2KEvrgSL8iaU5ug/640?wx_fmt=png "")  
  
  
绕过  
  
1、直接移除 CSRF Token  
：部分网站防御不严，缺少 Token 仍可执行请求。  
  
2、令牌未与会话绑定  
：部分网站仅验证 Token 是否有效，攻击者可使用他人 Token 提交请求。  
  
3、修改请求方法  
：部分网站只对 POST 请求验证 Token，攻击者可将 POST 改为 GET 绕过防御。  
  
Json格式下CSRF绕过  
  
1.json格式闭合加修改Content-Type为application/json  
  
2.XHR CSRF POC 通过XHR提交  
  
3.借助flash，利用307跳转实现CSRF  
  
 3.1制作一个Flash文件  
  
 3.2制作一个跨域XML文件  
  
 3.3制作一个具有307状态码的php文件  
  
等等  
  
防御  
  
1.使用 CSRF Token  
：为每个请求生成唯一的、难以猜测的 CSRF Token，并在请求中携带和验证 Token，防止伪造请求。  
  
2.SameSite Cookie 属性  
：设置 SameSite 属性为 Strict 或 Lax，限制浏览器在跨站请求中发送 Cookie，避免在未经授权的请求中泄露身份。  
  
3.Referer 或 Origin 检查  
：验证请求中的 Referer 或 Origin 头部，确保请求来源于受信任的域名。  
  
4.避免使用 GET 请求进行敏感操作  
：确保关键操作（如修改账户信息、转账等）只能通过 POST 请求进行，避免 GET 请求带来潜在的伪造风险。  
  
5.验证请求来源与用户会话  
：确保每个请求的 Token 与当前用户会话绑定，防止其他用户的 Token 被滥用。  
  
  
