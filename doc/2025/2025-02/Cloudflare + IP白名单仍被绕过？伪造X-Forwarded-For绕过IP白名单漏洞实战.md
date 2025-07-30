#  Cloudflare + IP白名单仍被绕过？伪造X-Forwarded-For绕过IP白名单漏洞实战   
原创 zangcc  Eureka安全   2025-02-20 11:39  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/7GhZKSNyIWW7hOPGVGAFdB0LicgBD9QCTEVRdLGXklRmwEsxuNVbR5ibwLzxicafIHsW1U9WpV0Mznib50aAn0mqSQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**点击上方**  
**蓝字**  
**关注我们**  
  
## 0x01 前言  
  
    在正式分享之前，我还是想先说明一下，X-Forwarded-For 请求头是什么？    X-Forwarded-For（XFF） 是一个 HTTP 请求头字段，用于标识客户端的原始 IP 地址。当请求经过代理（如 CDN、负载均衡、反向代理等）时，原始客户端的 IP 可能会被隐藏，代理服务器会将客户端的真实 IP 添加到 X-Forwarded-For头中，方便后端服务追踪来源。   然后是Cloudflare，当用户访问使用Cloudflare的网站时，请求会先经过Cloudflare的服务器，进行缓存、安全过滤等处理，然后再转发到源服务器（比如用户的Nginx服务器）。为了方便理解，假设用户访问链接路是：用户 → Cloudflare → Nginx → Server我简单举个例子：场景：用户（IP 1.1.1.11）访问网站，请求经过 Cloudflare（IP 2.2.2.22），再到达 Nginx（IP 3.3.3.33），最终到服务器。这里的安全风险点就是 X-Forwarded-For 头是可以被伪造的，只需要攻击者在请求包中伪造一个ip，具体的内部逻辑：1️⃣正常情况：    1.用户请求到达 Cloudflare 时，XFF 头变为:X-Forwarded-For: 1.1.1.11    2.Cloudflare 转发请求到 Nginx 时，XFF 头变为:X-Forwarded-For: 1.1.1.11, 2.2.2.22    3.Nginx 转发到最终服务器时，XFF 头变为:X-Forwarded-For: 1.1.1.11,2.2.2.22,3.3.3.33。用户真实 IP 是第一个值（1.1.1.11）。2️⃣异常情况（攻击者伪造 XFF 头）：    攻击者直接发送请求时，手动添加一个伪造的 XFF 头，例如 X-Forwarded-For: 6.6.6.6。    Cloudflare 收到请求后，会追加用户真实 IP，此时 XFF 头变为: X-Forwarded-For: 6.6.6.6, 1.1.1.11    Nginx 继续追加自己的 IP，最终 XFF 头为：X-Forwarded-For: 6.6.6.6, 1.1.1.11, 2.2.2.22如果直接取第一个 IP（6.6.6.6），会得到伪造的 IP。下面的实战就是利用了这个安全风险点。声明：以下是正文内容，可能会有错误的个人理解，我说的不一定对，但一定不会错。——zangcc  
  
  
## 0x02 实战案例  
  
    先正常访问一下这个系统url，因为当前我的出口ip是没有添加白名单的，所以无法显示图形验证码，无法登录。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NN6aytu0hPxHz3C9vpIQIBTkfYSVvc63Z8fz8jVKD4N2FNTg3AwIibjeptlyicjXOyDOGn9ARyqvfAA/640?wx_fmt=png&from=appmsg "")  
  
    通过响应包的Server响应头的结果，判断出是用了cloudflare代理，其他信息就不知道了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NN6aytu0hPxHz3C9vpIQIBTG4IMKjH9tpesQlTPGibqWlOZBKl1dzHicjhG3joKZOkcSIPcHIWuHNbg/640?wx_fmt=png&from=appmsg "")  
  
    这个系统添加白名单的方法是通过用户的出口ip去主动请求一个内部接口，然后这个接口会返回一个用户的唯一key，用户将这个key告诉管理员，只需要管理员把这个key添加，就相当于是给用户加白，网站的服务才能被正常访问（包括登录框的图形验证码）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NN6aytu0hPxHz3C9vpIQIBTxuqD3OINmQKHqzHIpWSiaeTIVCWJlrd0HicnYlWuIdhvGGcHQ2V4c3GQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NN6aytu0hPxHz3C9vpIQIBTUx0NiaoakxcbUxqsyEupOzUT4sRNxRibwAhen2uUic5qejfQKwRY6icqXQ/640?wx_fmt=png&from=appmsg "")  
  
    再重复提一次，这里的data就是用户唯一key，data的值只与出口ip有关，ip一变，data就变。    所以，当一个用户正常请求接口，并获取了这个data(也就是key)，发给管理员，也加了白，如果哪天自己的出口ip变了，那么也是无法访问的，需要用当前的出口ip重新获取一次key，再重复一遍加白操作才行。    好了，系统的加白详细流程就是这样。作为一名白帽子，就得想办法绕过这个限制。思路是这样，如果能获取到白名单用户的出口ip，然后在所有的请求包中自动添加请求头:X-Forwarded-For:whiteList_ip，就可以绕过了。    要获取白名单用户的出口ip其实很简单，钓鱼就行（一个简单的网站链接，通过服务器日志或HTTP请求头获取其IP地址）其他方法这里不细说，后续可以专门出一个钓鱼文案专题文章。    我当前的出口IP 是103.xxx.xxx.21 没有加入到白名单。通过伪造X-Forwarded-For: 31.xxx.xxx.11 （该IP 已经加入了白名单）    利用Burpsuite的HTTP match and replace rules，Match不填，为空。Replace添加一个伪造的X-Forwarded-For，点击OK保存之后，这样每次用Burpsuite请求，请求包都会自动加上这个请求头了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NN6aytu0hPxHz3C9vpIQIBT1bPibiaPlZlDTNlLyNR3q4vPhehfJdTicAKewXkhEdfBrZK0EaL2k94QQ/640?wx_fmt=png&from=appmsg "")  
  
伪造一个X-Forwarded-For之后，成功绕过。  
  
## 0x03 总结  
  
     总结一下就是非白名单用户，任意出口ip，只要获取到白名单用户的出口ip，就可以随便访问。而且这个ip地址只要泄露出去，就可以无限套用，让这个“受保护”的不被外人随意访问的后台系统可以被所有人访问。     又拿了一个逻辑漏洞。因为获取对方的出口ip，相对让ta下载木马来说简单太多，所以报告给了个高危。    再说下修复建议。如果链路是 用户 → Cloudflare → Nginx → 服务器，且 Nginx 不再被其他不可信代理覆盖，那么倒数第二个 IP 必定是 Cloudflare 追加的用户真实 IP。  
  
## 0x04 修复方法的原理  
  
    因为要跟客户说明修复的方法，所以趁着这个机会把我认为合适的这个修复方法也分析一下。    假设用户真实 IP 是 1.1.1.11，Cloudflare 的 IP 是 2.2.2.22，Nginx 的 IP 是 3.3.3.33。一、正常情况：    1.1 用户请求到达 Cloudflare 时：X-Forwarded-For: 1.1.1.11    1.2 Cloudflare 转发请求到 Nginx 时：X-Forwarded-For: 1.1.1.11, 2.2.2.22    1.3 Nginx 转发到最终服务器时：X-Forwarded-For: 1.1.1.11, 2.2.2.22, 3.3.3.33用户真实 IP 是第一个值（1.1.1.11）。二、异常情况（攻击者伪造 XFF 头）：    2.1 攻击者直接发送请求时，手动添加一个伪造的 XFF 头，例如：X-Forwarded-For: 6.6.6.6    2.2 Cloudflare 收到请求后，会追加用户真实 IP，此时：X-Forwarded-For: 6.6.6.6, 1.1.1.11    2.3 Nginx 继续追加自己的 IP，最终如下：X-Forwarded-For: 6.6.6.6, 1.1.1.11, 2.2.2.22如果直接取第一个 IP（ 6.6.6.6），会得到伪造的 IP。通过取倒数第二个 IP 来解决伪造问题，逻辑如下（假设 Cloudflare 是唯一可信代理）：Cloudflare 会强制追加用户真实 IP，即使请求已被篡改。例如，攻击者伪造 XFF 头为 6.6.6.6，但经过 Cloudflare 后，xff头会变为：X-Forwarded-For: 6.6.6.6, 1.1.1.11最终服务器看到的： X-Forwarded-For: 6.6.6.6, 1.1.1.11, 2.2.2.22（Nginx 追加自己的 IP 2.2.2.22）。    在上述例子中，倒数第一个 IP 是 Nginx 的 IP（2.2.2.22），倒数第二个是用户的真实 IP（1.1.1.11）。无论攻击者如何伪造，Cloudflare 总是会将真实 IP 追加到 XFF 头末尾，因此倒数第二个 IP 是可信的。  
  
4.1 修复思路总结      遍历X-Forwarded-For头中的IP地址，不要直接取左边第一个IP，而是从右向左遍历。遍历时可以根据正则表达式剔除掉内网IP和已知的代理服务器本身的IP（例如192.168开头的），那么拿到的第一个非别除IP就会是一个可信任的客户端IP。      这种方法的巧妙之处在于，即使伪造X-Forwarded-For，那么请求到达应用服务器时，伪造的IP也会在X-Forwarded-For值的左边，从右向左遍历就可以避免取到这些伪造的IP地址。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKzq4TFicia2yUjianoH80KtrWfiaAtUngV8rgLh0bIibv9SumD1Y9ZmphGxK9lKiakkOWDp2gRsLjZInPg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
更多 >>  技术分享  
  
欢迎大家关注EureKaSec，无论是技术交流还是有兴趣加入我们团队，都欢迎随时联络沟通。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CibE0jlnugbX5SLGI9312kOrkH7gXIN5NPic75bQ8WbAFMEqvZiaQ0WSk4W9eYUfJJRzlMgibjic8mIGicMvjialoDgmQ/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/BictawU0A1NM9WYO94RZib7HaaibSibMic91gPq8qbxL1jdjlslceibTEgJaLzvA1QVIkJ1sdaLJpYRzyw25hVIlxNkw/640?wx_fmt=jpeg "")  
  
如有问题  
  
联系作者      
  
EureKaSec  
  
  
点个   
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/BictawU0A1NN6aytu0hPxHz3C9vpIQIBTOjyvsXKPVQEPqdHQCXWfVGoTaGXyABSUL3HBgjPHHYlnqJE4LzRUTQ/640?wx_fmt=jpeg&from=appmsg "")  
，挖洞必高危！  
  
人划线  
  
  
