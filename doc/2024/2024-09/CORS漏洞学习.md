#  CORS漏洞学习   
Whoisa  黑客白帽子   2024-08-31 10:42  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJG3jJlPv0w6V8YUTyNSuV2udfyY3rWyR6V1UeHWuiab6T80I5ldZicZswCnrbicD4ibpaDMqCZ6UvFmhWLyTzptSA/640?wx_fmt=png&random=0.6636094571400317&random=0.6219011309810436&random=0.21191420540585404 "")  
  
**感谢师傅 · 关注我们**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJG3jJlPv0w6V8YUTyNSuV2udfyY3rWyR6V1UeHWuiab6T80I5ldZicZswCnrbicD4ibpaDMqCZ6UvFmhWLyTzptSA/640?wx_fmt=png&random=0.9829534454876507&random=0.2787622380037358&random=0.29583791053286834 "")  
  
  
由于，微信公众号推送机制改变，现在需要设置为星标才能收到推送消息。大家就动动发财小手设置一下呗！啾咪~~~  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJG3jJlPv0y50hQk1TiaBIAnSjzqkmZcPS4TWvohHfHPTVUBWM2mFxcqwhiaZKaQM6S7t11fuiajZ2zZqXD5hJJmA/640?wx_fmt=png "")  
  
# CORS漏洞  
  
CORS（Cross-Origin Resource Sharing）是一种用于Web应用程序的安全机制，用于控制在浏览器中一个网页能够访问来自另一个源（域名、协议或端口）的资源。CORS漏洞指的是在CORS机制实现上存在的安全问题。  
1. 简介  
  
CORS漏洞指的是当一个网站未正确配置CORS策略时可能会导致的安全问题。如果服务器未正确配置CORS规则，攻击者可以通过在恶意网站上的JavaScript代码，利用用户在浏览器中登录受害网站的凭据，从而发送跨域请求到受害网站并获取敏感信息。这种漏洞可能会导致信息泄露等安全问题。  
  
下面用AB两个网站举例，A网站表示正常网站，B网站是攻击者的网站。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0yjGzUiaEL4UEoEugkcgwlVLogqhqn7OsYiaHwnTP1rmMkqic7apRSsOg9YLtvMwEq7mzQ4q5iaumaYWg/640?wx_fmt=png&from=appmsg "")  
  
A网站有个接口，是返回用户个人信息的。先判断用户是否登录，如果登录那么就会返回登录信息，如果没有登录则返回未登录的消息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0yjGzUiaEL4UEoEugkcgwlVLJoSELHLs1ib6JarxZUCtIcoUqMBibNAxgAa6BH5biceyuPeC8X6y4fzQw/640?wx_fmt=png&from=appmsg "")  
  
登录代码如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0yjGzUiaEL4UEoEugkcgwlVLibjLQicu0KSF7ZUGAo2AWVdr3ygfktiaWLs6D8SxAfJDd5sbIVRj5pOtA/640?wx_fmt=png&from=appmsg "")  
  
如果登录成功，那么访问getinfo会得到一个json数据，登录失败则是提示重新登录。  
  
登录成功如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0yjGzUiaEL4UEoEugkcgwlVLhicF82lnKWeRkwkjZeT3JESweSpNbTjFKoh1fpbA7X9dy7ic8ddocXMw/640?wx_fmt=png&from=appmsg "")  
未登录情况如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0yjGzUiaEL4UEoEugkcgwlVLwL7hAYyGvzsKPaYJ7RWKuQUZlLbu7eUmiayDQK85nyqBthIwhFNAKDA/640?wx_fmt=png&from=appmsg "")  
那么假设我们在a网站登录成功的状态下，这时候访问getinfo接口的时候返回了身份信息。那么这时候又去访问b网站。b网站是一个恶意网站，b网站的js会发送一个请求，请求的是a网站的getinfo接口。b网站的代码如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0yjGzUiaEL4UEoEugkcgwlVLAFGTOnRQBoSyqFNHROBHUQdeibMphXR8KchsjyuszCplf41quGCJosg/640?wx_fmt=png&from=appmsg "")  
  
很简单就是一个img标签，通过src属性对getinfo接口发送请求，那么这时候是不是会附带a网站的cookie过去，然后就可以劫持a网站的用户信息。示意图下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0yjGzUiaEL4UEoEugkcgwlVLSVNVbmKYcdo4EFHDricOZ9LXeHK40AAEpEBut5lyr9RMwCBuA9PWQJQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0yjGzUiaEL4UEoEugkcgwlVLlC1WTRhahia4nHODHgGEUEg9rpULEiasjpcId8E8r22yd27ccBRUNaZg/640?wx_fmt=png&from=appmsg "")  
  
步骤1：登录A网站  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0yjGzUiaEL4UEoEugkcgwlVLqCsNXAMsVqxXYy4pTKTb9VDsibUGwA8eA8EppvgMvCRh8ktKmLiaOr9g/640?wx_fmt=png&from=appmsg "")  
  
步骤2：打开B网站  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0yjGzUiaEL4UEoEugkcgwlVLr8oI0em2hFKhfOiaYic83GxAyJwSXI5MQoGg8jVicYKC8vRrRCvD2HMMA/640?wx_fmt=png&from=appmsg "")  
  
也没有返回信息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0yjGzUiaEL4UEoEugkcgwlVLg0PlBXczYUiaH1xk45puToGibba6OpFPianR3uDAjNkUEJG4Dhibibjic6TQ/640?wx_fmt=png&from=appmsg "")  
  
可以发现其实是不能劫持a网站用户信息的。这是由于浏览器同源策略做了限制。实际上也就是浏览器不会把cookie携带过去。  
  
同源策略（Same-Origin Policy）是一种浏览器安全机制，用于限制不同源之间的交互，以防止恶意网站通过跨域请求获取用户的敏感信息或进行其他攻击。  
  
同源指的是协议（Protocol）、域名（Domain）和端口（Port）相同。如果两个页面的协议、域名和端口都相同，则它们被认为是同源的，可以自由地进行数据交互。而如果其中任意一项不相同，就被视为跨域请求。  
  
同源策略限制了以下行为：  
1. Cookie、LocalStorage 和 IndexDB 等存储的读取：跨域请求无法访问目标网站的存储信息。  
  
1. DOM 的访问限制：跨域请求无法获取目标网站的 DOM 元素。  
  
1. AJAX 请求限制：跨域请求无法直接发送 AJAX 请求。  
  
然而，同源策略也允许一些特定的跨域行为：  
1. 跨域资源共享（CORS）：服务器可以通过设置响应头来允许特定的跨域请求。  
  
1. JSONP：利用script标签的跨域特性，通过动态插入  
  
在真实场景下比如多了一个子域名pay.a.com，这个子域名需要获取到a.com/getinfo.php这个接口的信息，那么这时候getinfo接口就需要配置一下CORS头。  
  
pay.a.com代码如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0yjGzUiaEL4UEoEugkcgwlVLE4FpzicZR03icyOcibuXjAlEZIvhhTzUicreJz8LRQ8XoXkHr9nLBhI73Q/640?wx_fmt=png&from=appmsg "")  
  
执行效果是失败了的，pay.a.com并没有获取到数据，这个是因为a.com还没有配置CORS头信息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0yjGzUiaEL4UEoEugkcgwlVLAQzNAcBQlsDNkX6T58LdKlUicMSzfCejuHxiaqdz2JeibuOOxsd3UkX0g/640?wx_fmt=png&from=appmsg "")  
  
在getinfo代码上配置一下CORS头  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0yjGzUiaEL4UEoEugkcgwlVLGmUWms7JfvlTdfhddXHl3vvEq1tAou7QBmAVhibJbjTZUgNm3AKC9jg/640?wx_fmt=png&from=appmsg "")  
  
再次请求发现能够获取到数据了，表示跨域成功。解释一下两个请求头Access-Control-Allow-Origin 用于指示哪些源站有权限访问特定资源。当一个网页试图通过JavaScript从另一个源站加载数据时，浏览器会执行跨来源HTTP请求。在这种情况下，服务器需要设置Access-Control-Allow-Origin标头来明确指定哪些源站具有权限访问资源。比如Access-Control-Allow-Origin这里设置的是http://pay.a.com:8081 就是表示允许http://pay.a.com:8081进行跨域请求。  
  
Access-Control-Allow-Credentials 可以控制是否允许跨域请求携带凭据信息,跨域时要设置为true。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0yjGzUiaEL4UEoEugkcgwlVLUQ6jibKYaKleEAO6c1z6aolRazFTu7e3ufOnROHNA4Zn6PQiaw25JEibQ/640?wx_fmt=png&from=appmsg "")  
## 第一种情况  
  
漏洞成因, 往往都是开发或者运维人员为了实现业务需求从而导致了配置不当造成CORS漏洞。比如配置如下  
<table><thead><tr style="background-color: var(--color-canvas-default);border-top: 1px solid var(--color-border-muted);"><th style=" padding: 6px 13px;text-align: left ; ; ; ; ; ; ; ; ; ; ; ">HTTP头</th><th style=" padding: 6px 13px;text-align: left ; ; ; ; ; ; ; ; ; ; ; ">配置</th></tr></thead><tbody><tr style="background-color: var(--color-canvas-default);border-top: 1px solid var(--color-border-muted);"><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">Access-Control-Allow-Origin</td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">&#34;Origin&#34;</td></tr><tr style="background-color: var(--color-canvas-subtle);border-top: 1px solid var(--color-border-muted);"><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">Access-Control-Allow-Credentials</td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">true</td></tr></tbody></table>  
导致如上情况的后端代码可能如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0yjGzUiaEL4UEoEugkcgwlVLwGrJvIXWRGCLq14NCPh7HrHrljfUkK4L4X7wHraQpnHYeXhFQHuYOA/640?wx_fmt=png&from=appmsg "")  
  
注意：这种情况下其实也是不能成功利用CORS漏洞的。  
  
攻击网站b.com代码如下（就是把pay.a.com网站的代码复制过去，但是发现pay.a.com能够成功访问到getinfo接口，但是b.com访问getinfo接口不成功）：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0yjGzUiaEL4UEoEugkcgwlVLe70ziamsp10buFPULjfmaoMenSX6MicbBv30iaCMUl8aEiab44ltCdH9Ag/640?wx_fmt=png&from=appmsg "")  
  
b.com攻击结果  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0yjGzUiaEL4UEoEugkcgwlVLwXGeXu3wMDK88HufaXD5NicefhAludIWRXvOhLeXCMHZwpIttQOPpnA/640?wx_fmt=png&from=appmsg "")  
  
然后查看b.com向getinfo接口发送的http请求。从header来说确实是允许跨域的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0yjGzUiaEL4UEoEugkcgwlVLA2icn2o0ua3uicBhz2jeusjLkgFMuHd3M77pecynicnUY1jGlzE5EAzqQ/640?wx_fmt=png&from=appmsg "")  
  
因为除了CORS保护cookie之外浏览器还有一个SameStie的保护策略，控制是否随跨站点请求发送 cookie，从而提供一些针对跨站点请求伪造攻击 (CSRF) 的保护。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0yjGzUiaEL4UEoEugkcgwlVL3PAoA0XIWl41MEMgXNS53g3yr2zLhCpQBePNS3BLd7oCJcTNL2WYFw/640?wx_fmt=png&from=appmsg "")  
  
SameStie可能的属性值有三个：  
<table><thead><tr style="background-color: var(--color-canvas-default);border-top: 1px solid var(--color-border-muted);"><th style=" padding: 6px 13px;text-align: left ; ; ; ; ; ; ; ; ; ; ; ">属性名</th><th style=" padding: 6px 13px;text-align: left ; ; ; ; ; ; ; ; ; ; ; ">含义</th></tr></thead><tbody><tr style="background-color: var(--color-canvas-default);border-top: 1px solid var(--color-border-muted);"><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">Strict</td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">Cookie 只能在第一方环境中发送；也就是说，当获取该 Cookie 的网站与浏览器地址栏中显示的网站匹配时，才会发送 Cookie。</td></tr><tr style="background-color: var(--color-canvas-subtle);border-top: 1px solid var(--color-border-muted);"><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">Lax</td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">默认值，意味着 Cookie 不会在跨站点请求（例如加载img或iframe的请求）上发送，而是在用户从外部站点导航到源站点（例如，点击a标签）时发送。</td></tr><tr style="background-color: var(--color-canvas-default);border-top: 1px solid var(--color-border-muted);"><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">None</td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">意味着浏览器会通过跨站点和同站点请求发送 cookie。(必须同时设置Secure属性) Cookie 只能通过 HTTPS 协议发送。</td></tr></tbody></table>  
可以看见SameStie严格程度：Strict > Lax > None那么想使得b.com跨域获取getinfo接口的信息，那么getinfo接口还得配置一下cookie。而且要把a.com换成https协议，否则Secure属性不生效。  
  
a.com添加两行代码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0yjGzUiaEL4UEoEugkcgwlVLQKrEkscW5T3EibAup8yroG3Ydic8NPZGUCzjnLoxFXic0wpZyrwHibBY6Q/640?wx_fmt=png&from=appmsg "")  
  
可以看到b.com成功跨域访问了getinfo接口并且携带了cookie。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0yjGzUiaEL4UEoEugkcgwlVLQQh6Hibnyh6ZzRFoPicnInLuIv0BnCibBjLMBIAK21hXY5VQ8G63CSwCw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0yjGzUiaEL4UEoEugkcgwlVLh78dJN8bWkkeb2UibaKicmydDw8Pl7XANk4JkG6A2icLpPeUTmsuAjWXg/640?wx_fmt=png&from=appmsg "")  
  
那么得出的结论就是，想要实现CORS劫持，要满足两个条件。  
1. Access-Control-Allow-Origin可以是任意值且Access-Control-Allow-Credentials为true。2.Cookie设置了samesite为None。  
## 第二种情况  
  
第二种情况其实是第一种情况下面的一些限制使用。比如在实际业务中会限制跨域请求只允许子域名，但是校验却没有那么严格的情况就会出现问题。比如域名为a.com但是跨域请求校验不严格的情况大致有如下三种：  
<table><thead><tr style="background-color: var(--color-canvas-default);border-top: 1px solid var(--color-border-muted);"><th style=" padding: 6px 13px;text-align: left ; ; ; ; ; ; ; ; ; ; ; ">校验方式</th><th style=" padding: 6px 13px;text-align: left ; ; ; ; ; ; ; ; ; ; ; ">校验内容</th><th style=" padding: 6px 13px;text-align: left ; ; ; ; ; ; ; ; ; ; ; ">绕过方式</th></tr></thead><tbody><tr style="background-color: var(--color-canvas-default);border-top: 1px solid var(--color-border-muted);"><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">前缀校验</td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">检测前缀是否是a.com</td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;color: rgb(199, 37, 78);background-color: var(--color-neutral-muted);border-radius: 6px;">Origin</code>：http://a.com.b.com</td></tr><tr style="background-color: var(--color-canvas-subtle);border-top: 1px solid var(--color-border-muted);"><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">后缀校验</td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">检测后缀是否是a.com</td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;color: rgb(199, 37, 78);background-color: var(--color-neutral-muted);border-radius: 6px;">Origin</code>：http://xxxxxxa.com</td></tr><tr style="background-color: var(--color-canvas-default);border-top: 1px solid var(--color-border-muted);"><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">包含校验</td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">检测是否包含a.com</td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;color: rgb(199, 37, 78);background-color: var(--color-neutral-muted);border-radius: 6px;">Origin</code>：http://xxxxxxa.com</td></tr></tbody></table>  
比如代码如下，判断了origin是否包含了a.com：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0yjGzUiaEL4UEoEugkcgwlVLA5ILbIv5cYlq1wh3hkQAGjramNO1m6lfVosCS3Y0I7Wlic0QiaiarXqicw/640?wx_fmt=png&from=appmsg "")  
  
原本的方式已经失效了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0yjGzUiaEL4UEoEugkcgwlVL9rmZDsCQ9yz9zno6cvdicUuKSLJZjrM761ziaeY2FPTNRUoKyCZnQCdA/640?wx_fmt=png&from=appmsg "")  
  
那么就可以使用a.com.b.com这个域名去进行绕过过滤  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0yjGzUiaEL4UEoEugkcgwlVLeUb8eeichF0OgKGzeF9q50Z6DGcVnjTT8jk3qMHia5nU6C6fIK9Y5p7Q/640?wx_fmt=png&from=appmsg "")  
## 第三种情况  
  
这是对第二种情况的一个扩展，当过滤非常严格，确实只允许子域名访问的情况，但是子域名出现了xss漏洞。这个情况使用就可以使用xss植入javascript代码，让子域名替我们完成CORS劫持，并且把数据返回给到攻击网站。  
  
比如创建一个有xss的子域名bug.a.com。代码如下。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0yjGzUiaEL4UEoEugkcgwlVLFljAV7KiaHo2OeLpMhldTakaw8WEIRQoEmv7O3bDibq8Bnq9UkSeB9DA/640?wx_fmt=png&from=appmsg "")  
  
然后可以使用xss使得bug.a.com发送跨域请求。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0yjGzUiaEL4UEoEugkcgwlVL6cR8htlK0OfX56vxhiaeR7PVQxDG0mLTGztp6lia2tNib4NrrxAuxSBhQ/640?wx_fmt=png&from=appmsg "")  
  
然后只需要iframe标签的src属性变成xsspayload即可。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0yjGzUiaEL4UEoEugkcgwlVLOGhwSHILMIcYDnl24M4QDWcrnP3tJInO9ic3sSsvHDE16eGGBVX4IFg/640?wx_fmt=png&from=appmsg "")  
## 第四种情况  
  
这种情况是当Access-Control-Allow-Origin为null时的情况， 通常是开发者在网站上配置信任null源，用于调试代码。然后调试完成后没正确配置直接上线业务。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0yjGzUiaEL4UEoEugkcgwlVLma0qPU0WIwhCjCXTS8smqDOu37xJZE8FARgSbmk2Us5NlLia89ba9Ww/640?wx_fmt=png&from=appmsg "")  
  
这种情况可以使用iframe来完成攻击，攻击者可从通过iframe的sandbox构造Origin为null的跨域请求。  
  
sandbox 属性则是用来定义一个沙盒，它可以限制 <iframe> 中加载的内容的行为，从而增加安全性。  
  
使用 sandbox 属性时，可以设置不同的值来启用不同的安全策略，例如：  
- sandbox="allow-same-origin"：允许 <iframe> 内容与父页面具有相同的源 (origin)，这意味着 <iframe> 内容可以访问与父页面相同的资源。  
  
- sandbox="allow-scripts"：允许 <iframe> 内容执行脚本。  
  
- sandbox="allow-forms"：允许 <iframe> 内容提交表单。  
  
- sandbox="allow-top-navigation"：允许 <iframe> 允许嵌套的页面通过顶级窗口来导航或打开新的顶级浏览器上下文。  
  
- sandbox="allow-modals"：允许 <iframe> 内容打开模态窗口。  
  
比如可以使用如下Payload发送请求<iframe sandbox="allow-scripts" src='data:text/html,xxxxxxx'>  
  
这里的base64其实就是，index.html页面的javascript编码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0yjGzUiaEL4UEoEugkcgwlVLsPQyAkTDQ2l3DoeegEETrFeeYE5XhUERahxw4NicRJ5ft3lNzWPxcpA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0yjGzUiaEL4UEoEugkcgwlVLiao6SY8s11A1EiamoLcibuqmegQQ0lMW2LZoCt2mXfhWbdg8pWgnWicvOQ/640?wx_fmt=png&from=appmsg "")  
  
发现确实能够跨域拿到数据，并且origin设置为null。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0yjGzUiaEL4UEoEugkcgwlVLIk46kZrdNFZRiaMgAZqESYialCdamvTz4ibkLZmtbYRrTFZtMK3wvbpaA/640?wx_fmt=png&from=appmsg "")  
# 总结  
  
CORS（跨域资源共享）是一种浏览器机制，它允许 Web 应用程序在浏览器中向其他域发送跨域 HTTP 请求，以实现跨域数据访问。但是，如果 CORS 配置不当，可能导致安全漏洞。以下是一些与 CORS 相关的漏洞和安全注意事项的总结：  
  
CORS漏洞类型：  
- 允许Origin为任意值：如果服务器配置允许任意来源的请求，则存在风险，因为攻击者可以通过发送恶意请求来获取敏感信息。  
  
- Origin为空值：如果Origin为null，攻击者可以使用ifrmae标签进行绕过。  
  
CORS前提条件：  
- Access-Control-Allow-Origin可以控制 （或者说可以被绕过）  
  
- Access-Control-Allow-Credentials 为true  
  
- SameSite为Low  
  
特殊条件：  
- Access-Control-Allow-Origin为null  
  
- 子域名存在xss  
  
# 资源  
> CORS的详细介绍：https://developer.mozilla.org/zh-CN/docs/Web/HTTP/CORS#access-control-request-headers  
> SameSite的详细介绍https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#samesitesamesite-value  
  
  
所用代码如下：getinfo.php  
```
<?php
ini_set('session.cookie_secure', "1");
ini_set('session.cookie_samesite', 'None');

session_start();

//$origin = $_SERVER['HTTP_ORIGIN'];
//$allowed_domain = 'a.com';
//
//if (strpos($origin, $allowed_domain) !== false) {
//    header('Access-Control-Allow-Origin: ' . $origin);
//    header('Access-Control-Allow-Credentials: true');
//}

header('Access-Control-Allow-Origin: null');
header('Access-Control-Allow-Credentials: true');

header('Content-Type: application/json');
if (isset($_SESSION['isLogin'])) {
    $data = array(
        'name' => 'admin',
        'pass' => 'admin'
    );
    $json = json_encode($data);
    echo $json;
} else {
    echo json_encode(array('msg' => '未登录'));
}

```  
  
login.php  
```
<?php
ini_set('session.cookie_secure', "1");
ini_set('session.cookie_samesite', 'None');

session_start();
var_dump($_POST["username"]);
if ($_POST["username"] === "admin" && $_POST["password"] === "admin") {
    $_SESSION['isLogin'] = true;
    header("Location: getinfo.php");
}

?>

<form action="login.php" method="post">
    <input type="text" placeholder="username" name="username">
    <input type="password" placeholder="password" name="password">
    <input type="submit">
</form>

```  
  
b.com的index.html  
```
<script>
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'https://a.com:8081/getinfo.php', true);
    xhr.withCredentials = true;
    xhr.onreadystatechange = function () {
        if (xhr.status === 200) {
            console.log(xhr.responseText);
        }
    };
    xhr.send();
</script>

```  
  
xss.html  
```
<iframe src="https://bug.a.com:8081/index.php?name=%3Cscript%3E%20var%20xhr%20=%20new%20XMLHttpRequest();%20xhr.open(%27GET%27,%20%27https://a.com:8081/getinfo.php%27,%20true);%20xhr.withCredentials%20=%20true;%20xhr.onreadystatechange%20=%20function%20()%20{%20if%20(xhr.status%20===%20200)%20{%20console.log(xhr.responseText);%20}%20};%20xhr.send();%20%3C/script%3E">

</iframe>

```  
  
iframe.html  
```
<iframe sandbox="allow-scripts" src="data:text/html;base64,PHNjcmlwdD4KICAgIHZhciB4aHIgPSBuZXcgWE1MSHR0cFJlcXVlc3QoKTsKICAgIHhoci5vcGVuKCdHRVQnLCAnaHR0cHM6Ly9hLmNvbTo4MDgxL2dldGluZm8ucGhwJywgdHJ1ZSk7CiAgICB4aHIud2l0aENyZWRlbnRpYWxzID0gdHJ1ZTsKICAgIHhoci5vbnJlYWR5c3RhdGVjaGFuZ2UgPSBmdW5jdGlvbiAoKSB7CiAgICAgICAgaWYgKHhoci5zdGF0dXMgPT09IDIwMCkgewogICAgICAgICAgICBjb25zb2xlLmxvZyh4aHIucmVzcG9uc2VUZXh0KTsKICAgICAgICB9CiAgICB9OwogICAgeGhyLnNlbmQoKTsKPC9zY3JpcHQ+"></iframe>

```  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650939865&idx=1&sn=773462fd879df4c210ad316ed538483a&chksm=8bac6d26bcdbe4302b3b28dac2f62deaa16dc687bff0062a8ca5d90f6b124e3d2685544fdc03&scene=21#wechat_redirect)  
  
**下载地址**  
  
****  
**二个月前资源汇总**  
  
https://kdocs.cn/l/cq  
EYzWfs0kUS  
  
  
  
声明：本公众号所分享内容仅用于网安爱好者之间的技术讨论，禁止用于违法途径，**所有渗透都需获取授权**  
！否则需自行承担，本公众号及原作者不承担相应的后果  
  
  

								  

									  

										  

											  
往期推荐  

										  

									  

									  

								[ 闪电搜索是一个用户友好的多平台资产测绘客户端，支持Fofa、hunter、360quake、Zoomeye、零零信安等平台界面化 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650958060&idx=1&sn=4c3a377c0e8a1bf56d243c973efcb490&chksm=8bac2413bcdbad052edce4dc3406a174e01e9570dd918934cb96fb0eb3363a828ff11b34eee5&scene=21#wechat_redirect)  

							  
  

								[ AVEC！开源在线免杀生成平台 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650957908&idx=1&sn=63f136835b23945cca1fd92a80dbc29b&chksm=8bac24abbcdbadbdc32249dd63ea82e1b753179965e6a420fc56f5b9198b9fdadda394cf115f&scene=21#wechat_redirect)  

							  
  

								[ 推荐一款功能炸裂的自动化反编译微信小程序工具 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650957860&idx=1&sn=50edfece01132672d04b00bbe06222c7&chksm=8bac24dbbcdbadcdcb1d9ec7cc0f8161df151dc122f8343e03809d3d1811845bbc92a2e258de&scene=21#wechat_redirect)  

							  
  

								[ 推荐一款非常炸裂的shell工具箱 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650957773&idx=1&sn=32db2b116cf2b7b8542a1264e9ae20b9&chksm=8bac2b32bcdba22439db0d9daf2f8ce79623a29ff613f9d86c9d025039b32000fe654d035676&scene=21#wechat_redirect)  

							  
  

								[ 自动化分析网络安全应急响应工具 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650957709&idx=1&sn=b7fce8303ea5b7b8bf2243fda78c25f4&chksm=8bac2b72bcdba264d7cd2f0d523931cdd47562150622d4d7249f3481e132f8463e3a0071fd64&scene=21#wechat_redirect)  

							  
  

								[ 自动识别Web蜜罐Chrome插件 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650957616&idx=1&sn=888a1f3a2c5c1fad9220f4d8a8423ebd&chksm=8bac2bcfbcdba2d98dbcba81060712ad997766fec015b2cf61b5e12020aa58ef3539dcdc5927&scene=21#wechat_redirect)  

							  
  

								[ 一款对资产重点系统指纹识别、精准漏扫的工具 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650957562&idx=1&sn=06fa6a61483d7cd8018299e5252a614f&chksm=8bac2a05bcdba313a60ebc7541412261b7310505dd5aa8b9d86ae8dac486a74a000046000ca2&scene=21#wechat_redirect)  

							  
  

								[ 2024 HVV情报速递合集 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650957503&idx=1&sn=48d58a502335f6097f8e25ec13c0eba2&chksm=8bac2a40bcdba356de1f265964a5748c4b15d9d342b9ef25e7d10e44809e1ce861884375bb51&scene=21#wechat_redirect)  

							  
  

								[ 织梦全版本漏洞扫描 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650957446&idx=1&sn=614d231ff449ef0c96ed8b8e6c61cef5&chksm=8bac2a79bcdba36f35557984a00212202ff92ff679ce56c06a0300b247a294569af488af060b&scene=21#wechat_redirect)  

							  
  

								[ 蓝队值守利器-IP溯源工具 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650957390&idx=1&sn=35ca101a591a8a2d96ff707999577163&chksm=8bac2ab1bcdba3a766234e24558359aba0be0d753dafa773a51fb2a2ba5855474903e40cd17e&scene=21#wechat_redirect)  

							  
```
```  
  
