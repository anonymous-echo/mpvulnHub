#  实战 | 测试文件上传漏洞的5个小tips   
 渗透安全团队   2024-09-07 21:49  
  
作为红队成员、渗透测试人员和 赏金猎人——我们都喜欢在我们的目标中看到文件上传功能。  
  
但有时我们必须处理不寻常的应用程序，这些应用程序可能会受到“简单”Webshell 上传的良好保护（即存在过滤），因此我们需要采用更具创意的方法。  
  
**大多数人都已经熟悉以“传统方式”（文件扩展名、内容类型等）测试上传功能**  
，  
**那么本文将涵盖不太传统的上传漏洞**  
。  
  
 让我们开始吧！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEPibaDicF8h6uXfq6bHb4IvyCEHPxB3jovdFp3B689WahH9rkbpwVgicZCeCrMw80jgkWj7vLMS2x4A/640?wx_fmt=png&from=appmsg "")  
# 首先检查PHP的disabled_functions  
  
我知道这可能有点简单，但我见过很多案例，黑客设法将一些 PHP 文件上传到目标应用程序，但他们却没法进一步利用。原因通常是因为  
.ini  
文件中的 PHP 功能禁用了“危险函数”，例如  
system、exec、shell_exec  
和其他运行直接操作系统命令的函数。这种情况在托管环境中非常流行。  
  
我通常使用Acunetix 脚本：  
https://www.acunetix.com/blog/articles/web-shells-101-using-php-introduction-web-shells-part-2/  
来检查未禁用且可用于为我们的 webshell 提供服务的 PHP 函数：  
```
<?php
print_r(preg_grep("/^(system|exec|shell_exec|passthru|proc_open|popen|curl_exec|curl_multi_exec|parse_ini_file|show_source)$/", get_defined_functions(TRUE)["internal"]));
?>
```  
  
这个脚本给了我们答案。脚本在屏幕上打印已启用的函数名，我们可以利用它们来运行操作系统命令或读取服务器上的文件 (例如curl_exec)。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEPibaDicF8h6uXfq6bHb4IvyXWMhlGMV77hHSQ3QqiaAicTUvjncBU1pTIibePEODD5J5Ke9vrYNKdrrQ/640?wx_fmt=png&from=appmsg "")  
# 通过上传文件进行路径遍历  
  
另一个有时被忽视的漏洞是文件上传的路径遍历。与让我们读取目标服务器上的文件的经典路径遍历不同，在文件上传中，我们的目标是将文件上传到服务器其他的位置。  
  
为什么它很重要？有时，上传目录包含“特殊规则”。例如，我见过服务器管理员通过在  
.htaccess  
文件中配置特定目录来完全禁用 PHP 对特定目录的支持的情况。在这种情况下，我们应该尝试将“../”添加到我们的请求中，就添加在在文件名之前，并尝试将我们的 webshell 上传到服务器上的其他位置。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEPibaDicF8h6uXfq6bHb4Ivyh6NjlekMCFia0LIlqDicXxIp4loQcyPy7X6UKqCWHPR7caVo7sQqs4nQ/640?wx_fmt=png&from=appmsg "")  
  
在其他情况下，上传的文件可能无法通过网络访问，所以我们也可以尝试这种方法。  
  
还有一件事需要注意，  
**即使我们出于任何原因无法上传恶意文件，仍然值得测试路径遍历**  
。如果我们可以将文件（例如图像）上传到其他位置，  
**则意味着我们可以尝试覆盖服务器的现有文件！**  
# 更改目录配置（.htaccess文件上传，这个就比较常见了）  
  
前面我们提到了一个非常重要的文件：.htaccess。以下是来自  
apache.org  
的文件定义：“ .htaccess文件提供了一种在每个目录的基础上进行配置更改的方法。”  
  
换句话说，该文件用于配置给定目录的特定属性，而不涉及整个 Web 服务器的配置。例如，我们可以只从本地主机访问我们网站的  
/adimn  
路径，这样它就不会暴露给外部登录。  
  
你明白我的意思了吧？如果我们遇到一个对恶意文件（PHP/ASPX/JSP/等）具有良好防护的网站，我们可以尝试上传我们自己的上传目录配置文件！  
  
我们可以使用以下指令创建一个.htaccess文件：  
```
AddType application/x-httpd-php .png
```  
  
这行代码告诉服务器将  
.png  
文件作为 PHP 运行。所以现在我们应该能够上传我们的“image”   
.png  
文件并将我们的payload注入其中。在许多情况下，对恶意  
.htaccess  
文件的过滤并不像恶意文件扩展名那么强。  
  
如果上传目录中已有  
.htaccess  
文件，则上传我们的文件将覆盖现有文件，并可能导致服务器出现问题。因此，不要忘记在上传恶意配置文件后检查服务器是否正常工作。  
# 上传存储的 XSS 和 XXE payload  
  
假设我们尝试了一切方法来上传“经典”webshell，最终得出的结论是我们的目标网站非常了解如何防止恶意 php/aspx/jsp/etc 文件。它只接受管理员希望您上传的任何预期文件类型。  
  
现在我们需要使用网站的管理卡来玩（并获胜）。假设我们假设只上传图像，我们可以使用 SVG 文件作为合法文件。神奇之处就在这里：SVG 是一种基于 XML 的格式。它对我们有两个主要影响：  
- XML 格式可能会导致 XXE 攻击  
  
- 这种格式支持Javascript，所以我们可以测试XSS  
  
**我们先从XSS部分开始**  
  
如果网站希望我们上传图像，例如个人资料图片，我们可以尝试这样的 SVG payload：  
```
<svg xmlns="http://www.w3.org/2000/svg" width="300" height="300">
        <circle cx="150" cy="147.5" r="50" fill="#DA3A00" />
        <script>console.log("@chux13786509 on X for more content!")</script>
</svg>
```  
  
该payload将创建一个红色圆圈，并在后台打印（console.log）我们想要使用 Javascript 的任何内容。结果如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEPibaDicF8h6uXfq6bHb4Ivy12zp8vCicFYRfF7MvIJ8VS7Guxa0o12CHHKRZqgZ2OlSVfQ1aKcAarw/640?wx_fmt=png&from=appmsg "")  
  
这是我最近测试的一个目标的示例：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEPibaDicF8h6uXfq6bHb4IvyibCtzfmjma0S2iaKmfIZWLYicyBp4l7v9dvQUpRulFw3ibc3ic9jLIl1lRQ/640?wx_fmt=png&from=appmsg "")  
  
**通过文件名存储XSS**  
  
在某些情况下，当我们有文件上传功能时，上传文件的原始名称会显示在 DOM 上。在这种情况下，我们希望通过上传带有标签的文件来检查存储的 XSS。就像下面的例子一样：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEPibaDicF8h6uXfq6bHb4IvyHYAGF0ojiaq16yVKsAUWvFWsP2CVU4f7k0TyZibhRibTu0zibpKD6QsLMA/640?wx_fmt=png&from=appmsg "")  
  
创建名称中包含 HTML 标签的文件  
  
上传这样的文件后，我们将在 DOM 上查找无效图像：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEPibaDicF8h6uXfq6bHb4IvyYwXboTQh4nHXUicD2Zy9BMttI7UFIdvCibGY2dZWZYujpia5kh9CQnLUA/640?wx_fmt=png&from=appmsg "")  
  
它的渲染方式正如我们所期望的，DOM 包含恶意文件名：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEPibaDicF8h6uXfq6bHb4IvyXKT4ibXsdzeBZ7qZ6XeME3X1qQ0s8UiahorHnEmW5xqTiaPes1SVRq8Qg/640?wx_fmt=png&from=appmsg "")  
  
这个漏洞在许多网站中出人意料地流行，其影响介于自我 XSS 和帐户接管之间。如果由于网站的 CSP 良好而无法利用 XSS，请尝试通过利用带有   
<form>  
 标记的 HTML 注入来强制用户执行操作（例如创建其他用户、更改详细信息等）来增加影响。  
  
**现在是 XXE 部分**  
，它有点复杂。  
  
我们已经说过 SVG 是基于 XML 的格式，因此我们应该考虑 XXE 攻击。对于包含 XML 的其他格式（例如 Office 文件、DOCX 和 XLSX）也是如此。  
  
您是否尝试过获取 DOCX 文件并将其扩展名从  
.docx  
更改为  
.zip  
 ？打开文件后，它看起来像这样：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEPibaDicF8h6uXfq6bHb4Ivy7icyr0ibu76HAabr8a33Itjfvkn8CrRChoYb6MibM8WrBibdNMIhpENhyQ/640?wx_fmt=png&from=appmsg "")  
  
浏览目录后，您将找到一些 XML 文件：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEPibaDicF8h6uXfq6bHb4IvybhIib0fR5ebgtxlxGLIxBqcqYkTGXe0LRHfMMiaU2sKfcY7n0GxXKCSQ/640?wx_fmt=png&from=appmsg "")  
  
了解了一些合法上传常见的 XML 格式之后，我们来谈谈它们的利用。  
  
我们的目标需要在页面上呈现我们的payload或以某种方式处理它。两个最常见的例子：  
- 上传在个人资料页面上呈现的个人资料图片  
  
- 以某种模式上传文档（如简历）并从其内容中提取特定详细信息（如姓名）  
  
如果网站满足这些条件，则意味着它处理了 XML 内容，我们可以尝试注入外部实体进行测试。  
# 压缩文件  
  
有许多网站允许我们在一个存档文件中上传一堆文件，例如税务报告。它不仅是 ZIP 文件，还包括其他存档格式，如 7z、tar、war、jar、rar 和 apk。  
  
从存档中提取文件让我们有机会测试漏洞 - 使用目录遍历名称保存文件，并检查文件是否被提取到预期上传目录之外的其他位置。因此，如果我们制作一个 ZIP 文件，其中包含名为“   
../../../mal.php  
 ”的文件，则在提取过程中，该文件将被提取到上面的两个目录，文件名为  
mal. php  
 .  
  
这和我们之前提到的路径遍历漏洞非常相似，只是这次我们必须使用另一个工具来使用特殊的文件名来制作这个存档,vilarc：  
https://github.com/ptoomey3/evilarc  
。  
  
此外，这里还有一篇关于该漏洞的Snyk ：  
https://security.snyk.io/research/zip-slip-vulnerability  
其中包含更多详细信息，甚至是不同编码语言的代码片段，用于在项目中查找漏洞。  
# 总结  
  
文件上传功能是我最喜欢测试的功能。除了涉及内容类型或文件扩展名的经典上传漏洞之外，还有一些开发人员不太了解的其他技术，您很可能可以在您的活动中利用它们。  
  
通过了解文件上传漏洞的全部潜力，我们可以实现高度严重的影响，即使它不是使用 Webshell 的直接 RCE，它仍然可以通过其他方式损害服务器：读取文件 (curl_exec)、XXE、XSS 和覆盖现有文件。  
  
在我的大部分工作中，简单的 Webshell 必须被一些更复杂的攻击所取代。所以我相信读完这些方法后你会发现一些你之前没有想到的新漏洞:)  
  
 祝你好运！  
  
  
以上内容由白  
帽子左一翻译并整理。原文  
：https://medium.com/@red.whisperer/5-advanced-ways-i-test-for-file-upload-vulnerabilities-5b01358f87d1  
  
**声明：⽂中所涉及的技术、思路和⼯具仅供以安全为⽬的的学********习交流使⽤，任何⼈不得将其⽤于⾮法⽤途以及盈利等⽬的，否则后果⾃⾏承担。所有渗透都需获取授权！**  
  
  
**★**  
  
**付费圈子**  
  
  
**欢 迎 加 入 星 球 ！**  
  
**代码审计+免杀+渗透学习资源+各种资料文档+各种工具+付费会员**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.4447566002908574&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**进成员内部群**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/pPVXCo8Wd8AQHAyOTgM5sLrvP6qiboXljGWG0uOdvcNR8Qw5QJLxSVrbFds2j7MxExOz1ozb9ZoYwR68leoLdAg/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.09738205945672873&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**星球的最近主题和星球内部工具一些展示******  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/pPVXCo8Wd8Doq0iczyRiaBfhTQyfzqSGuia4lfHfazabEKr2EDe7sGVoxUhLrNRA4FbI1yef6IkWdmzxvZrTiaJncg/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8BmE6FAA8Bq7H9GZIRt1xYZpmYNWxrrzolt71FtX5HyM03H0cxkiaYelv7ZSajLtibEdBXUpCibdItXw/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8ADSxxicsBmvhX9yBIPibyJTWnDpqropKaIKtZQE3B9ZpgttJuibibCht1jXkNY7tUhLxJRdU6gibnrn0w/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8DKZcqe8mOKY1OQN5yfOaD5MpGk0JkyWcDKZvqqTWL0YKO6fmC56kSpcKicxEjK0cCu8fG3mLFLeEg/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8DAc8LkYEjnluf7oQaBR9CR7oAqnjIIbLZqCxwQtBk833sLbiagicscEic0LSVfOnbianSv11PxzJdcicQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8B96heXWOIseicx7lYZcN8KRN8xTiaOibRiaHVP4weL4mxd0gyaWSuTIVJhBRdBmWXjibmcfes6qR1w49w/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8DAc8LkYEjnluf7oQaBR9CRBgpPoexbIY7eBAnR7sWS1BlBAQX51QhcOOOz06Ct2x1cMD25nA6mJQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8AqNwoQuOBy9yePOpO5Kr6aHIxj7d0ibfAuPx9fAempAoH9JfIgX4nKzCwDyhQzPrRIx4upyw5yT4Q/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.4447566002908574&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**加入安全交流群**  
  
  
[                ](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247513602&idx=1&sn=98045772ff9aebe8792552e32523bf83&chksm=c1764badf601c2bbcc199da519611ac8c36c17e5a0554fe32ab9d9769403a495187058f19f3d&scene=21#wechat_redirect)  

			                  
  
  
**信 安 考 证**  
  
  
  
需要考以下各类安全证书的可以联系我，下方扫码回复  
**考证**  
进交流群，价格优惠、组团更便宜，还送【  
渗透安全团队  
】知识星球**1**年！  
<table><tbody style="outline: 0px;"><tr style="outline: 0px;"><td width="557" valign="top" style="outline: 0px;word-break: break-all;hyphens: auto;"><p style="outline: 0px;"><span style="outline: 0px;font-size: 14px;letter-spacing: 0.51px;">CISP、PTE、PTS、DSG、IRE、IRS、</span><span style="outline: 0px;font-size: 14px;letter-spacing: 0.51px;">NISP、</span><span style="outline: 0px;font-size: 14px;letter-spacing: 0.51px;">PMP、CCSK、CISSP、ISO27001...</span></p></td></tr></tbody></table>  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8AOzYX7kxefGbGGZg3g1ltkN30q9hceg23PiczgUqMT0EE9w0fLK9uw1eKWwQX9TljXQe1OQeHRZ2Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**教程如下图**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8C3Gu1libJC0muV1WmOFa3XM3fTyOiaOJYPgCiaHV6gkJJBia6Fjeds9w9pxxyyPNJhbcfK3I1tcGueTg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ndicuTO22p6ibN1yF91ZicoggaJJZX3vQ77Vhx81O5GRyfuQoBRjpaUyLOErsSo8PwNYlT1XzZ6fbwQuXBRKf4j3Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
**推荐阅读**  
  
  
  
[干货｜史上最全一句话木马](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247489259&idx=1&sn=b268701409ad4e8785cd5ebc23176fc8&chksm=c175eb44f60262527120100bd353b3316948928bd7f44cf9b6a49f89d5ffafad88c6f1522226&scene=21#wechat_redirect)  
  
  
  
[干货 | CS绕过vultr特征检测修改算法](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247486980&idx=1&sn=6d65ae57f03bd32fddb37d7055e5ac8e&chksm=c175f3abf6027abdad06009b2fe964e79f2ca60701ae806b451c18845c656c12b9948670dcbc&scene=21#wechat_redirect)  
  
  
  
[实战 | 用中国人写的红队服务器搞一次内网穿透练习](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247488628&idx=1&sn=ff2c617cccc00fe262ed9610c790fe0e&chksm=c175e9dbf60260cd0e67439304c822d28d510f1e332867e78a07d631ab27143309d14e27e53f&scene=21#wechat_redirect)  
  
  
  
[实战 | 渗透某培训平台经历](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247488613&idx=1&sn=12884f3d196ac4f5c262a587590d516d&chksm=c175e9caf60260dcc0d5d81a560025d548c61fda975d02237d344fd79adc77ac592e7e562939&scene=21#wechat_redirect)  
  
  
  
[实战 | 一次曲折的钓鱼溯源反制](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247489278&idx=1&sn=5347fdbf7bbeb3fd37865e191163763f&chksm=c175eb51f602624777fb84e7928bb4fa45c30f35e27f3d66fc563ed97fa3c16ff06d172b868c&scene=21#wechat_redirect)  
  
  
  
**免责声明**  
  
由于传播、利用本公众号渗透安全团队所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号渗透安全团队及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
好文分享收藏赞一下最美点在看哦  
  
