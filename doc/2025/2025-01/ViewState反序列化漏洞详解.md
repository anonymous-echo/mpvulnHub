#  ViewState反序列化漏洞详解   
原创 信安路漫漫  信安路漫漫   2025-01-21 23:00  
  
## 前言  
  
在一次测试过程中遇到了这个ViewState的反序列化漏洞，当时对于利用方式以及原理都不太清楚，因此有了这边文章，学习一下viewstate的漏洞原理以及利用方式。  
## ViewState基础介绍  
### ViewState机制  
  
ViewState 是 ASP.NET（Active Server Pages .NET）框架用来保持页面状态的一种机制。ASP.NET 是微软开发的用于动态网页服务器端开发的框架，ViewState 是其中用于维护和管理页面状态的一部分。它在客户端和服务器之间存储页面和控件的状态。  
  
**问题1：ViewState是在页面生成的时候创建的吗？**  
  
ViewState原始状态是一个 字典类型。在响应一个页面时，ASP.NET 会把所有控件的状态序列化为一个字符串，然后作为 hidden input 的值 插入到页面中返还给客户端。当客户端再次请求时，该hidden input 就会将ViewState传给服务端，服务端对ViewState进行反序列化，获得属性，并赋给控件对应的值。  
  
**问题2：可以举个例子保存了什么样的页面状态?**  
  
假如服务端在处理第n+1次请求时，想使用第n次传给服务器的值进行计算，而这时第n次请求所对应的page实例早已被销毁，要去哪里找上一次传给服务器的值呢？为了满足这种需求，就出现了多种状态管理技术，而VewState正是ASP.NET 所采用的状态管理技术之一。  
### ViewState工作原理  
  
1）保存页面状态：每次页面请求和响应，服务器端控件的状态信息需要保存在客户端，待下一次请求时恢复。ViewState 就是在页面生成过程中将控件状态编码并嵌入到页面的隐藏字段中。  
  
2）在客户端存储和传输：ViewState 的数据以 Base64 编码格式存储在页面中的一个名为 __VIEWSTATE 的隐藏字段里，随每次表单提交一起传输到服务器。  
  
3）恢复页面状态：页面在提交到服务器后，ASP.NET 会将 __VIEWSTATE 字段的数据提取出来进行解码并恢复控件的状态  
### 实现细节  
  
在典型的 ASP.NET 页面上，ViewState 数据通常类似如下：  
```
```  
  
__VIEWSTATE 的 value 属性存储了编码后的数据，这些数据包含了控件的状态信息。  
  
如下面的一个VIEWSTATE信息，包含了一个时间戳  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Rzo6rPw2nBzwXGfhLjZib1FnTQF1mupwfHq3wBjUvcmiax45tsyhzyxDDFJTynkfebf3OshJDdSF3a9CibVevpqAg/640?wx_fmt=jpeg&from=appmsg "")  
### 出现viewstate的原因  
  
HTTP模型是无状态的，这意味着，每当客户端向服务端发起一个获取页面的请求时，都会导致服务端创建一个新的page类的实例，并且一个往返之后，这个page实例会被立刻销毁。假如服务端在处理第n+1次请求时，想使用第n次传给服务器的值进行计算，而这时第n次请求所对应的page实例早已被销毁，要去哪里找上一次传给服务器的值呢？为了满足这种需求，就出现了多种状态管理技术，而VewState正是ASP.NET 所采用的状态管理技术之一。  
## viewstate保证安全性的方式  
  
viewstate里面可能保存了敏感信息，因此为了防止信息泄露和篡改，引入了加密和签名的机制。  
  
原始的ViewState仅仅是用base64编码了序列化后的binary数据，未使用任何类型的密码学算法进行加密，可以使用LosFormatter（现在已经被ObjectStateFormatter替代）轻松解码和反序列化。  
LosFormatter formatter = new LosFormatter(); object viewstateObj = formatter.Deserialize("/wEPDwULLTE2MTY2ODcyMjkPFgIeCHBhc3N3b3JkBQlzd29yZGZpc2hkZA==");  
反序列化的结果实际上是一组System.Web.UI.Pair对象。  
### 引入加密机制  
  
为了保证ViewState不会发生信息泄露，ASP.NET 2.0 使用 ViewStateEncryptionMode属性 来启用ViewState的加密，该属性可以通过页面指令或在应用程序的web.config 文件中启用。  
```
```  
  
ViewStateEncryptionMode 可选值有三个：Always、Never、Auto  
### 引入签名机制  
  
加密不能防止篡改 ，即使使用加密数据，攻击者仍然有可能翻转加密书中的位。所以要使用数据完整性技术来减轻篡改威胁，即使用哈希算法来为消息创建身份验证代码（MAC)。可以在web.config 中通过EvableViewStateMac来启用数据校验功能。  
```
```  
  
注意：从.NET 4.5.2 开始，强制启用ViewStateMac 功能，也就是说即使你将 EnableViewStateMac设置为false，也不能禁止ViewState的校验。安全公告KB2905247（  
https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2013/2905247?redirectedfrom=MSDN  
）(于2014年9月星期二通过补丁程序发送到所有Windows计算机)将ASP.NET 设置为忽略EbableViewStateMac设置。  
### 开启签名以后得生成viewstate的大致步骤  
  
(1)页面和所有参与控件的状态被收集到状态图对象中。  
  
(2)状态图被序列化为二进制格式  
  
a. 密钥值将附加到序列化的字节数组中。  
  
b. 为新的序列化字节数组计算一个密码哈希。  
  
c. 哈希将附加到序列化字节数组的末尾。  
  
(3) 序列化的字节数组被编码为base-64字符串。  
  
(4)base-64字符串将写入页面中的__VIEWSTATE表单值。  
## web.config 中关于ViewState 的配置  
  
ASP.NET 通过web.config 来完成对网站的配置。下面来看一些关于viewstate的常见配置：  
```
```  
  
**1）enableViewState：开启或者关闭ViewState**  
  
enableViewState：用于设置是否开启viewState，但是请注意，根据 安全通告KB2905247 中所说，即使在web.config中将enableViewState 设置为false，ASP.NET服务器也始终被动解析 ViewState。也就是说，该选项可以影响ViewState的生成，但是不影响ViewState的被动解析。实际上，viewStateEncryptionMode也有类似的特点。  
  
**2）enableViewStateMac：是否开启viewState Mac（校验）功能**  
  
enableViewStateMac：用于设置是否开启ViewState Mac (校验)功能。在 安全通告KB2905247 之前，也就是4.5.2之前，该选项为false，可以禁止Mac校验功能。但是在4.5.2之后，强制开启ViewState Mac 校验功能，因为禁用该选项会带来严重的安全问题。不过我们仍然可以通过配置注册表或者在web.config 里添加危险设置的方式来禁用Mac校验。  
  
**3）viewStateEncryptionMode：是否开启ViewState Encrypt (加密)功能**  
  
viewStateEncryptionMode：用于设置是否开启ViewState Encrypt (加密)功能。该选项的值有三种选择：Always、Auto、Never。  
  
•Always表示ViewState始终加密；  
  
•Auto表示 如果控件通过调用 RegisterRequiresViewStateEncryption() 方法请求加密，则视图状态信息将被加密，这是默认值；  
  
•Never表示 即使控件请求了视图状态信息，也永远不会对其进行加密。  
  
  
**在实际调试中发现，viewStateEncryptionMode 影响的是ViewState的生成，但是在解析从客户端提交的ViewState时，并不是依据此配置来判断是否要解密。**  
  
  
在web.config 中通过machineKey节 来对校验功能和加密功能进行进一步配置：  
```
```  
  
**validationKey 和 decryptionKey 分别是校验和加密所用的密钥**  
  
**validation和decryption则是校验和加密所使用的算法（可以省略，采用默认算法）**  
  
**校验算法包括：SHA1、 MD5、 3DES、 AE、 HMACSHA256、 HMACSHA384、 HMACSHA512**  
  
**加密算法包括：DES、3DES、AES。**  
  
由于web.config 保存在服务端上，在不泄露machineKey的情况下，保证了ViewState的安全性。  
## 伪造ViewState  
  
viewstate的生成原理，下面这篇文章讲解的很详细，感兴趣的可以去看一下：  
https://cloud.tencent.com/developer/article/1745275  
  
当然了伪造 ViewState 仍然需要 泄露web.config，知晓其 密钥与算法。  
  
1.如果签名算法不是AES/3DES，无论是否开启加密功能，我们只需要根据其签名算法和密钥，生成一个签名的ViewState。由于发送该ViewState的时候没有使用"__VIEWSTATEENCRYPTED" 字段，导致ASP.NET 在解析时直接进入GetDecodedData() 进行签名校验，而不再执行解密步骤。  
  
2.如果签名算法是 AES/3DES，无论是否开启加密功能，我们只需按照先前所讲，对数据先签名一次，再加密一次，再签名一次。然后发送给服务端，ASP.NET 进入 GetDecodedData()，然后先进 EncryptOrDecryptData() 进行一次校验和解密，出来后再进行一次校验。  
  
换种表达方式，无论使用什么签名算法，无论是否开启加密功能，我们伪造ViewState时，就按照没有开启加密功能情况下的正常步骤，去伪造ViewState。  
## ViewState反序列化漏洞  
  
.NET 相关漏洞中，ViewState也算是一个常客了。Exchange CVE-2020-0688，SharePoint CVE-2020-16952 中都出现过ViewState的身影。其实ViewState 并不算漏洞，只是ASP.NET 在生成和解析ViewState时使用ObjectStateFormatter 进行序列化和反序列化，虽然在序列化后又进行了加密和签名，但是一旦泄露了加密和签名所使用的算法和密钥，我们就可以将ObjectStateFormatter 的反序列化payload 伪装成正常的ViewState，并触发ObjectStateFormatter 的反序列化漏洞。  
### 漏洞形成的原因  
  
1）ViewState 未加密和未签名或者加密签名不严密：这种情况下我们可以篡改 ViewState 内容植入恶意代码，触发反序列化漏洞  
  
2）泄露了加密和签名所使用的算法和密钥：当泄露了加密和签名的密钥时，也可以伪造viewstate进行利用。  
### 利用原理  
  
利用 ViewState 反序列化漏洞，攻击者可以通过伪造序列化对象，使得 ViewState 执行其嵌入的恶意代码，从而在服务器端执行任意代码（RCE - Remote Code Execution）  
## 漏洞复现  
  
需要的内容：  
  
1）验证密钥validationKey，验证算法validation，解密密钥decryptionKey，解密算法decryption （其实在实际利用过程发现解密密钥decryptionKey和解密算法decryption无用，这两个选项加不加生成的payload没有区别）  
  
如下  
- 验证密钥validationKey配置为B3C2624FF313478C1E5BB3B3ED7C21A121389C544F3E38F3AA46C51E91E6ED99E1BDD91A70CFB6FCA0AB53E99DD97609571AF6186DE2E4C0E9C09687B6F579B3  
  
- 解密密钥decryptionKey配置为EBA4DC83EB95564524FA63DB6D369C9FBAC5F867962EAC39  
  
- 验证算法validation配置为SHA1  
  
- 解密算法decryption配置为AES  
  
2）工具：ysoserial.net （用来生成viewstate）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Rzo6rPw2nBzwXGfhLjZib1FnTQF1mupwfia3cUe54ZFR2jp8R0dauZibB5GN35qTwZFcR1KJSbjFFk9M05quqDYkg/640?wx_fmt=png&from=appmsg "")  
  
  
如利用下面的命令生成viewstate：  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Rzo6rPw2nBzwXGfhLjZib1FnTQF1mupwf6t6yRhzxYFGJT6oclCvHYWk40fgjWUmaO3P9H02uxQJPxAYtzQLuAw/640?wx_fmt=jpeg&from=appmsg "")  
  
然后重放该数据包，就可以在相应的目录下查找是否有文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Rzo6rPw2nBzwXGfhLjZib1FnTQF1mupwff9tZ4XOl4dPVWLicE2iaqpReaicEQ9gViaTMtLJ2WnQdLXHg0kf4tAuSYg/640?wx_fmt=jpeg&from=appmsg "")  
## MacKeyModifier的获取  
  
高版本的fx添加了MacKeyModifier作为Salt，由ClientId和ViewStateUserKey两部分拼接而成。在默认情况下，ViewStateUserKey为空；ClientId的算法为当前页面虚拟目录路径与当前页面类型名称的HashCode之和，同时会以十六进制形式存放于名为__VIEWSTATEGENERATOR的隐藏表单中返回。  
  
如果ViewStateUserKey不为空，ViewStateUserKey 是一个随机字符串值，且要保证与用户关联。如果网站使用了ViewStateUserKey，我们应当在SessionID 或 cookie 中去猜。在CVE-20202-0688 中，便是取 SessionID 作为ViewStateUserKey。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Rzo6rPw2nBzwXGfhLjZib1FnTQF1mupwf6pibuc6ib0er9ksWoGUhAt0dpDxskHiaj1xfLe6LJgcZ9Oia5g3UuuNquQ/640?wx_fmt=jpeg&from=appmsg "")  
  
获取流程  
```
```  
  
而即使ClientId不返回实际上也几乎没有影响：在不存在反向代理的情况下，最坏的黑盒情况依然可通过url逐级爆破获得当前页面虚拟路径；当前页面的类型名称则是固定的将请求路径中的句点(.)以及斜杠(/)替换为下划线(_)，例如  
  
/a/b/c.aspx最终的类型名为a_b_c_aspx。  
## 黑盒模式下如何获取密钥和加密算法  
  
1）报错或者文件读取可以获取到web.conf的内容  
  
2）使用了默认密钥或者密钥已经泄露  
  
如下面的一些密钥：  
https://github.com/yuanhaiGreg/Fuzz-Dict/blob/master/ViewState.txt  
  
验证密钥的时候可以使用下面的工具：viewgen  
  
github地址：  
https://github.com/0xacb/viewgen/tree/main  
  
  
如下图所示，先从web页面中获取到一个viewstate和modifier  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Rzo6rPw2nBzwXGfhLjZib1FnTQF1mupwfw8pKA5Ad29c5AibjmY3NWCr5NN2MTweLcnEPiaxXWAJoEUkTEfORM8ibA/640?wx_fmt=jpeg&from=appmsg "")  
  
然后运行下面的命令  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Rzo6rPw2nBzwXGfhLjZib1FnTQF1mupwfHcza74VlYLNLkpvVGER77JBUxqaKL9beLXzmz6EwniaH0MozsHlwEPg/640?wx_fmt=jpeg&from=appmsg "")  
## 总结  
  
本文大概总结了一下viewstate反序列化漏洞的利用方式以及可能使用到的工具，如果大家有什么好的想法或者工具，欢迎来交流  
## 参考链接  
  
https://blog.csdn.net/qq_33163046/article/details/141549823  
  
https://cloud.tencent.com/developer/article/1745275  
  
https://www.anquanke.com/post/id/199921#h3-4  
  
https://www.cnblogs.com/zpchcbd/p/15112047.html  
  
  
  
