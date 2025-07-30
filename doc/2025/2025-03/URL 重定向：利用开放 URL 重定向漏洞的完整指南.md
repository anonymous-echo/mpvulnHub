#  URL 重定向：利用开放 URL 重定向漏洞的完整指南   
原创 visionsec  安全视安   2025-03-01 18:21  
  
开放 URL 重定向漏洞很容易找到，因为它们在应用程序中很常见。这种漏洞类型通常也被认为是一个唾手可得的果实。但是，随着现代应用程序变得越来越复杂，漏洞也越来越复杂。这也使得将这些唾手可得的成果升级为更严重的安全问题成为可能。正如我们已经看到如何将 XSS 升级为远程代码执行漏洞(  
https://www.intigriti.com/researchers/blog/hacking-tools/7-ways-to-achieve-remote-code-execution-rce#6-injection-attacks  
)一样，我们也可以将开放 URL 重定向升级为完全帐户接管。在本文中，我们将深入探讨什么是开放 URL 重定向漏洞，如何识别它们，利用这些漏洞类型，并将其升级为更严重的安全问题。  
## 什么是开放 URL 重定向漏洞？  
  
当易受攻击的 Web 应用程序以不安全的方式处理您的用户输入时，就会出现开放 URL 重定向漏洞，允许您将用户从受信任的主机重定向到外部（不受信任的）位置。重定向有两种主要类型，服务器端重定向（最常见的）和客户端重定向（也称为基于 DOM 的重定向）。让我们深入了解这两种类型。  
### Server-side redirects 服务器端重定向  
  
服务器端重定向是由易受攻击的应用程序引起的，该应用程序允许未经净化的用户可控制输入来控制  
**位置**  
 HTTP 响应标头。为了帮助更好地了解服务器端开放 URL 重定向漏洞，请查看以下代码片段：  
```
```  
  
开发人员常犯的一个错误是将未经审查的用户输入传递到 Location HTTP 响应标头中。在此特定情况下，将读取   
**redirect_url**  
 查询参数，并在稍后的代码中添加到 Location HTTP 响应标头。这是服务器端开放 URL 重定向的一个简单示例。  
### Client-side redirects 客户端重定向  
  
客户端重定向是由浏览器（通过客户端 JavaScript 代码）调用的重定向。查看下面的易受攻击的代码片段，以更好地了解客户端重定向。  
```
```  
  
在这个简单的示例中，代码检查是否设置了查询参数   
**redirectURL**  
。之后，它将用户可控制的 input 参数传递给 DOM sink。在本文后面，我们还将介绍如何将这个简单的问题升级为跨站点脚本漏洞。现在让我们更深入地研究如何轻松识别开放重定向漏洞。  
## 识别开放 URL 重定向漏洞  
  
应用程序内重定向通常用于增强最终用户的应用程序体验。例如，如果用户尝试访问受保护的页面，他/她可能会首先被重定向到登录页面。因此，开发人员通常会发送一个重定向参数，以确保用户在身份验证后被重定向到受保护的页面。  
  
![An example of a redirect after authentication](https://mmbiz.qpic.cn/sz_mmbiz_png/Pf9NC3AaQF79kLYylezCkqUYianLAIWySUOKNZNXqrH7LZt1icLL9S0VFOcfBM5tmMwBKuWCu5VKRTp9MhV8ELOA/640?wx_fmt=png&from=appmsg "")  
  
  
在完成重要作后，也会使用重定向。一个常见的示例是在应用程序中注册新账户，并在创建账户后重定向到控制面板。在不太常见的情况下，重定向还用于优化用户的内容，开发人员根据用户的设备重定向用户。  
  
总而言之，您应该在目标的以下区域寻找开放的 URL 重定向：  
- 登录 & 注册页面  
  
- 注销应用程序路由或 API 终端节点  
  
- 密码重置（还要检查生成的令牌链接，因为它可能包含重定向参数）  
  
- Profile account 页面  
  
- 电子邮件验证链接  
  
- 错误页面  
  
- 应用程序内需要多个步骤的任何重要作  
  
到目前为止，我们已经探索了什么是开放 URL 重定向以及它们通常存在的位置。让我们来看看如何利用它们，甚至将这些唾手可得的漏洞升级为高度严重的安全问题！  
## 利用开放 URL 重定向漏洞  
### 简单的开放 URL 重定向  
  
您遇到的大多数重定向参数要么保护有限，要么根本没有保护。当不存在安全措施时，我们可以轻松地提供任意 URI 作为参数值，并被重定向到该特定主机。  
  
看看前面的 PHP 代码片段：  
  
![Vulnerable code snippet](https://mmbiz.qpic.cn/sz_mmbiz_png/Pf9NC3AaQF79kLYylezCkqUYianLAIWySFaDpw3Vu2NZicIC9MBqDNP57ViapoWLyv2Iibibr97yQviabSRBe4GBrR5w/640?wx_fmt=png&from=appmsg "")  
  
在这种特定情况下，我们只需填充   
**redirect_url**  
 查询参数并将最终用户重定向到任何特定主机。  
  
请求：  
```
```  
  
响应：  
```
```  
  
这是开放 URL 重定向漏洞的最简单示例，它可能导致许多攻击向量（取决于上下文），我们将在本文的下一节中介绍。让我们继续讨论更高级的情况，在这些情况下，我们将主动绕过弱 URL 验证！  
### 高级开放 URL 重定向  
  
防止开放 URL 重定向的正确方法是维护允许重定向的严格白名单。但是，由于应用程序内的重定向通常并不总是预先可预测的，因此开发人员倾向于验证 URL 的一部分，并在此基础上允许重定向发生。  
#### 利用高级服务器端重定向  
  
让我们看一下验证 host part 的上下文：  
```
```  
  
任何替换允许的主机的尝试都会导致应用程序使用默认路径作为回退。要绕过此验证，我们可以使用以下开放 URL 重定向有效负载之一：  
```
```  
  
  
将上述负载中的   
**example.com**  
 替换为目标允许的主机名或域名，  
**将 attacker.com**  
 替换为您控制的域名。  
  
**TIP! PortSwigger has an extensive**  
   
**URL validation bypass cheat sheet**  
(  
https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet  
)   
**that can help you bypass weak URL validations!**  
  
**提示！ PortSwigger 有一个广泛的**  
   
**URL 验证绕过备忘单**  
(  
https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet  
)  
**，可以帮助您绕过弱 URL 验证！**  
#### 利用基于 DOM 的高级重定向  
  
正如我们之前提到的，基于 DOM 的重定向是从浏览器启动的。如果我们以不安全的方式处理我们的输入并传递到 DOM 接收器，我们可以将开放的 URL 重定向升级为基于 DOM 的跨站点脚本 （XSS） 漏洞。  
  
如果我们看一下之前的易受攻击的代码片段：  
  
![Vulnerable code snippet](https://mmbiz.qpic.cn/sz_mmbiz_png/Pf9NC3AaQF79kLYylezCkqUYianLAIWySz47FSicV3ENiaUyOGUIqms51gnMUfEwym4hQeEgLzMYUSFZhMeicZBBcg/640?wx_fmt=png&from=appmsg "")  
  
我们可以轻松地发送以下有效负载来执行   
alert（）  
 函数调用：  
```
```  
  
此有效负载将传递给   
**window.location.href**  
 DOM-sink 并执行我们的任意代码。  
  
以下是使用 JavaScript 协议的更多旁路列表，以防我们的基本有效负载被过滤：  
```
```  
## 不断升级的开放 URL 重定向漏洞  
  
开放 URL 重定向漏洞通常被认为是唾手可得的果实。一些漏洞赏金计划甚至拒绝开放 URL 重定向漏洞，除非您能证明影响。  
  
幸运的是，这种漏洞类型在某些情况下可能会升级，具体取决于具体情况。以下是一些深入描述的示例。  
### 基于 DOM 的跨站点脚本 （XSS）  
  
正如我们在本文前面提到的，如果我们的重定向是从客户端（基于 DOM）发起的，则有可能将我们的低严重性漏洞升级为更高级别的安全问题。有几种方法可以识别重定向的类型。通常，服务器端重定向始终使用  
**位置**  
 HTTP 响应标头以及 3XX HTTP 状态代码（例如 301、302 或 307）。如果您遇到缺少   
**Location**  
 HTTP 响应标头但仍重定向您的页面（在短暂延迟后），这通常表示执行了基于 DOM 的重定向。追溯负责重定向的代码片段还可以帮助您识别重定向类型。此外，您还可以查看是否对您的输入执行了任何验证。  
**提示！ 使用**  
   
**DOMInvador**  
(  
https://portswigger.net/burp/documentation/desktop/tools/dom-invader  
)   
**和**  
   
**Untrusted Types**  
(  
https://github.com/filedescriptor/untrusted-types  
) 等工具  
**来帮助您追踪将任意输入传递到 DOM 接收器的易受攻击的代码！**  
### 基于 GET 的跨站点请求伪造  
  
开放的 URL 重定向也可以与某些类型的 CSRF 漏洞(  
https://www.intigriti.com/researchers/blog/hacking-tools/csrf-a-complete-guide-to-exploiting-advanced-csrf-vulnerabilities  
)链接在一起，以进一步升级它！  
  
请看下面的漏洞代码示例：  
  
![Vulnerable code snippet](https://mmbiz.qpic.cn/sz_mmbiz_png/Pf9NC3AaQF79kLYylezCkqUYianLAIWyS5FKVqIJ4r9fst7PFEdwYwRNFUe2CnzSYjzaFfzNjI7hliaE0Ch4jyPw/640?wx_fmt=png&from=appmsg "")  
  
  
在这里，我们可以注意到 2 个问题。/  
api/account/profile  
 端点上缺少 CSRF 保护，并且   
/redirect  
 API 端点上缺少开放的 URL 重定向。我们可以将这两个问题链接起来，并制作以下概念验证，以最终更改访问我们恶意链接的任何用户的用户名和简介：  
```
```  
  
每个目标都不同，因此我们建议您在应用程序中查找缺乏 CSRF 保护的其他关键作。根据上下文，将其与开放的 URL 重定向链接可能会增加初始问题的严重性。  
### 通过 OAuth 接管帐户  
  
如果您的目标允许您使用第三方帐户（如 Microsoft、Facebook 或 Apple ID）登录，则很可能使用的是流行的身份验证框架，如 OAuth 2.0。如果您的目标未遵循实施最佳实践，您或许可以泄露访问令牌并实现帐户接管。  
  
如果您遇到过 OAuth 实现，例如下面显示的请求：  
```
```  
  
尝试将   
**redirect_uri**  
 参数更改为您控制的任意主机，然后继续执行 OAuth 流程。如果实现确实容易受到攻击，它会使用访问令牌将您重定向到受控主机，从而允许您手动调用回调终端节点并启动与受害者账户的会话。  
### 服务器端请求伪造  
  
开放 URL 重定向也可用于利用服务器端请求伪造(  
https://www.intigriti.com/researchers/blog/hacking-tools/ssrf-a-complete-guide-to-exploiting-advanced-ssrf-vulnerabilities  
)。一些容易受到服务器端请求伪造攻击的应用程序仅允许您访问列入白名单或受信任的主机。如果易受攻击的应用程序也遵循重定向，您可以使用开放 URL 重定向漏洞来利用 SSRF 并升级您的初步发现！  
  
![Vulnerable code snippet](https://mmbiz.qpic.cn/sz_mmbiz_png/Pf9NC3AaQF79kLYylezCkqUYianLAIWySrRCB5SOImWv6qQZhBb8BHFOe6bdnr23JpM8JickhbErqtNGfN5piczwQ/640?wx_fmt=png&from=appmsg "")  
  
  
在上述情况下，  
/api/image-loader  
 似乎容易受到 SSRF 漏洞的攻击。但是，它仅向受信任的域发出请求。使用开放 URL 重定向，我们可以诱骗易受攻击的应用程序，使其相信我们正在尝试加载受信任的主机，但由于 fetch API 默认遵循重定向，因此它会跟随重定向并返回 AWS 元数据终端节点：  
```
```  
## 结论  
  
尽管开放 URL 重定向漏洞很容易找到并且在大多数复杂的应用程序中很常见，但它们通常被认为是唾手可得的成果。在本文中，我们介绍了几种如何利用这些漏洞类型并将它们升级为具有更高接受机会的更严重性安全漏洞的方法！  
  
  
