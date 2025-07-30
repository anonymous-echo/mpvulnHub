#  CORS跨域资源共享漏洞   
原创 young  SDL安全   2024-05-24 19:24  
  
CORS（Cross-Origin Resource Sharing）是一种浏览器安全机制，它允许 Web 应用程序从不同源加载所需的 Web 资源。由于浏览器的同源策略限制，Web 应用程序只能访问与其自身源相同的资源，因此需要 CORS 来解决跨域资源访问的问题。CORS 是通过 HTTP 头来进行控制的，主要涉及到以下几个头部：  
- Access-Control-Allow-Origin：授权访问的源站  
  
- Access-Control-Allow-Credentials：是否允许发送 Cookie 等凭据信息  
  
- Access-Control-Allow-Methods：授权访问的 HTTP 方法  
  
- Access-Control-Allow-Headers：授权访问的自定义头部  
  
## 一、漏洞原因  
  
因为同源策略的存在，不同源的客户端脚本不能访问目标站点的资源，如果目标站点配置不当，没有对请求源的域做严格限制，导致任意源都可以访问时，就存在cors跨域漏洞问题。  
### 什么是同源策略？  
  
同源策略用于限制应用程序之间的资源共享，确保一个应用里的资源只能被本应用的资源所访问。如果要跨域通信，就必须要引入跨域资源共享。如果没有正确配置，就会导致漏洞产生。同源是指协议，域名，端口三个都相同，即使是同一个ip，不同域名也不是同源，同源策略里允许发出请求，但是不允许访问响应。**同源示例**设 http://test.com/a/123.html 源  
  
<table><thead><tr><th style="font-size: 15px;line-height: 1.5em;letter-spacing: 0.02em;text-align: left;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);width: auto;height: auto;border-top-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;min-width: 85px;">URL</th><th style="font-size: 15px;line-height: 1.5em;letter-spacing: 0.02em;text-align: left;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);width: auto;height: auto;border-top-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;min-width: 85px;">是否同源</th><th style="font-size: 15px;line-height: 1.5em;letter-spacing: 0.02em;text-align: left;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);width: auto;height: auto;border-top-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;min-width: 85px;">不同处</th></tr></thead><tbody style="font-size: 15px;line-height: 1.5em;letter-spacing: 0.02em;border-width: 0px;border-style: initial;border-color: initial;"><tr style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(255, 255, 255);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">http://test.com/a/asd.html</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">同源</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">路径不同</td></tr><tr style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(248, 248, 248);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">http://test.com/abcvb/123.html</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">同源</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">路径不同</td></tr><tr style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(255, 255, 255);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">https://test.com/a/1234.html</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">不同源</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">协议不同</td></tr><tr style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(248, 248, 248);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">http://test.com:88/a/1234.html</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">不同源</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">端口不同</td></tr><tr style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(255, 255, 255);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">http://bbb.test.com/a/1234.html</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">不同源</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">域名不同，子域名不算同源</td></tr></tbody></table>  
## 二、漏洞种类  
  
CORS 存在漏洞主要有以下几种  
### 2.1 未正确设置 Access-Control-Allow-Origin  
  
如果 Access-Control-Allow-Origin 头未正确设置，攻击者可以通过构造特定的请求，绕过同源策略，从而获取到需要访问的数据。攻击者可以将自己的网站伪装成合法的源站，然后在自己的网站中通过 XMLHttpRequest 发送跨域请求，获取到需要的数据。  
### 2.2 Access-Control-Allow-Origin 设置为 *  
  
Access-Control-Allow-Origin 头部设置为 * ，表示所有站点都可以访问该资源，这可能会导致安全问题。攻击者可以通过伪造 HTTP 请求头中 Origin 字段的值，绕过同源策略，获取到需要的数据。  
### 2.3 未正确设置 Access-Control-Allow-Credentials  
  
Access-Control-Allow-Credentials 头部用于指示是否允许发送 Cookie 等凭据信息。如果未正确设置该头部，攻击者可以伪造 HTTP 请求头中的 Origin 和 Cookie 字段，从而绕过同源策略，获取到需要访问的数据。  
### 2.4 使用不安全的 HTTP 方法和头部  
  
Access-Control-Allow-Methods 和 Access-Control-Allow-Headers 用于授权访问的 HTTP 方法和头部。如果未正确设置这两个头部，攻击者可以通过构造特定的请求，使用不安全的 HTTP 方法和头部，获取到需要访问的数据。  
### 2.5 CSRF  
  
由于 CORS 的存在，攻击者可以利用 CSRF 漏洞发起跨域请求，进而绕过同源策略，获取到需要的数据。在这种情况下，应该使用 CSRF Token 等措施来防止 CSRF 攻击。  
## 三、CORS跨域漏洞的危害  
  
CORS跨域资源共享漏洞可以导致恶意网站或者应用程序通过跨域请求访问用户敏感信息、执行非授权操作等，对用户隐私和数据安全造成威胁。具体危害包括：  
1. 窃取用户敏感信息：攻击者可以通过CORS跨域请求窃取用户敏感信息，例如cookie等身份认证信息，用于身份冒充或者进行其他攻击。  
  
1. 执行未授权操作：攻击者可以利用CORS跨域请求执行未授权的操作，例如发起POST请求进行数据修改、发起DELETE请求进行数据删除等，从而对服务器和应用程序造成破坏。  
  
1. 数据篡改：攻击者可以利用CORS跨域请求修改数据内容，例如通过跨域POST请求篡改数据库中的数据，从而对应用程序造成破坏。  
  
1. 资源耗尽：攻击者可以通过CORS跨域请求耗尽服务器资源，例如发起大量跨域请求占用服务器带宽、内存等资源，导致服务不可用。  
  
2016年开始，Chrome **51**版本对Cookie新增了一个 SameSite属性，为了防止CSRF攻击，陆续的各大厂商的浏览器也都适配了该属性，该属性有什么用呢？如下图所示，展示了SameSite和其它跟cookie有关的设置的基本用途  
  
samesite属性有三个值  
- **Strict：**最为严格，完全禁止第三方 Cookie，跨站点时，任何情况下都不会发送 Cookie。  
  
- **Lax：**当开发开发人员没有设置samesite的值得时候，Lax是默认值，规则稍稍放宽，大多数情况也是不发送第三方 Cookie，详细如下图  
  
## 四、配置种类  
  
<table><thead><tr><th style="font-size: 15px;line-height: 1.5em;letter-spacing: 0.02em;text-align: left;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);width: auto;height: auto;border-top-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;min-width: 85px;">Access-Control-Allow-Origin</th><th style="font-size: 15px;line-height: 1.5em;letter-spacing: 0.02em;text-align: left;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);width: auto;height: auto;border-top-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;min-width: 85px;">Access-Control-Allow-Credentials</th><th style="font-size: 15px;line-height: 1.5em;letter-spacing: 0.02em;text-align: left;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);width: auto;height: auto;border-top-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;min-width: 85px;">结果</th></tr></thead><tbody style="font-size: 15px;line-height: 1.5em;letter-spacing: 0.02em;border-width: 0px;border-style: initial;border-color: initial;"><tr style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(255, 255, 255);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">*</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">TRUE</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">不存在漏洞(浏览器会认为这是一个不安全的配置，因此在跨域请求中将不能将包含凭据（如cookies、HTTP认证信息等）的请求发送到服务端)</td></tr><tr style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(248, 248, 248);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;"><br/></td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">TRUE</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">存在漏洞</td></tr><tr style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(255, 255, 255);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">&lt;safe_host&gt;</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">TRUE</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">安全-不存在漏洞</td></tr><tr style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(248, 248, 248);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">null</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">TRUE</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">存在漏洞</td></tr></tbody></table>  
  
上图这种是明显存在问题的
使用burpsuite抓包对http请求添加**Origin: http://www.attacker.com**进行测试：  
- 如果返回头是以下情况，那么就是漏洞，这种情况下漏洞最好利用：  
  
Access-Control-Allow-Origin: https://www.attacker.com
Access-Control-Allow-Credentials: true  
- 如果返回头是以下情况，那么也可以认为是漏洞，只是利用起来麻烦一些：  
  
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true  
- 如果返回以下，则不存在漏洞，因为Null必须是小写才存在漏洞：  
  
Access-Control-Allow-Origin: Null
Access-Control-Allow-Credentials: true  
- 如果返回以下，可认为不存在漏洞，因为CORS安全机制阻止了这种情况下的漏洞利用，也可以写上低危的CORS配置错误问题。  
  
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true  
- 如果返回以下，可认为不存在漏洞，也可以写上低危的CORS配置错误问题。  
  
Access-Control-Allow-Origin: *  
## 五、安全建议  
  
经过上面的知识普及，应该对CORS漏洞有所了解，可快速用curl命令检测  
```
curl https://www.test.com -H "Origin: https://test.com" -I

```  
  
检查返回包的** Access-Control-Allow-Origin 字段是否为https://test.com,以及Access-Control-Allow-Credentials是否为true**
后端设置应该参考如下方式：  
- Access-Control-Allow-Origin不应该设置为null，也不建议设置为*，做好设置成受信的站点  
  
- Access-Control-Allow-Methods的值可以控制尽量少一些，只留需要用到的请求方法  
  
- 开发人员尽量将cookie安全性设置高一些，例如Httponly,Security，SameSite  
  
  
  
  
