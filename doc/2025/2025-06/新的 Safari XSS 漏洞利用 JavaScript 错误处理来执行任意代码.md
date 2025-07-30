#  新的 Safari XSS 漏洞利用 JavaScript 错误处理来执行任意代码   
 网安百色   2025-06-04 11:30  
  
Safari 中新增的跨站点脚本 （XSS） 漏洞，可利用浏览器的 TypeError 异常处理机制来执行任意 JavaScript 代码。  
  
该漏洞是在 Gareth Heyes 研究有效负载隐藏技术期间发现的，它表明 Safari 对 TypeError 消息中引号转义的不当处理如何成为恶意代码执行的武器。  
  
此漏洞代表了一个重大的安全问题，因为它通过利用浏览器自己的错误处理基础设施绕过了传统的 XSS 预防机制。  
## TypeError XSS 漏洞  
  
该漏洞源于 Safari 对 TypeError 异常消息中单引号和双引号的处理存在缺陷。  
  
当开发人员尝试对包含混合引号的字符串文本使用 new 运算符时，Safari 会生成一个 TypeError，该错误无法充分转义错误消息中的引号字符。  
  
核心问题在执行诸如 new 'foo“bar' 之类的代码时显现出来，它会产生 TypeError 消息：”foo“bar” 不是构造函数。  
  
关键缺陷存在于 Safari 的转换过程中，其中单引号被转换为双引号，但字符串中嵌入的双引号保持未转义。  
  
这将创建一个场景，其中生成的错误消息包含三个双引号，从而有效地打破了字符串边界并允许将任意 JavaScript 注入到异常文本中。  
  
与语法错误不同，TypeErrors 不会阻止后续的 JavaScript 执行，从而为恶意代码在错误消息的上下文中运行创建路径，因此可以利用该漏洞。  
  
该利用技术将 TypeError 生成与 JavaScript 的全局错误处理程序机制相结合。  
  
通过设置 onerror=eval，攻击者可以将所有未捕获的异常定向到 eval（） 函数，然后该函数将格式错误的 TypeError 消息作为 JavaScript 代码执行。  
  
实际的有效负载演示涉及代码 new 'foo“-alert（1）//'，它生成 TypeError：”foo“-alert（1）//” 不是构造函数。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1QIbxKfhZo5z2URYg8kLBEJWmWdnzFJyyWrDWiaSicIx7QVPPCuXwDR64kIS4p990OseJ307JZVXCfRyRBev2IZw/640?wx_fmt=png&from=appmsg "")  
  
当通过 eval 函数将此错误消息作为 JavaScript 处理时，TypeError： 部分将变为 label 语句，第一个双引号将结束字符串，alert（1） 函数将执行，随后的注释语法 （//） 将中和剩余的错误文本。  
  
通过将 window.name 用作有效负载传递机制，可以进一步增强此技术，尽管 Safari 基于导航的 window.name 清除需要使用 target 属性或 window.open（） 方法的解决方法。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1QIbxKfhZo5z2URYg8kLBEJWmWdnzFJyYKonCgAQWU8Kk2BfUfSicy7KyzmJBbHzQL9OuMMvcF8XXdA4QaNu5MA/640?wx_fmt=png&from=appmsg "")  
  
  
此漏洞表示一种复杂的攻击媒介，它通过将恶意代码嵌入合法的错误处理进程中来绕过传统的 XSS 过滤机制。  
  
该漏洞对基本 JavaScript 错误处理的依赖使其特别令人担忧，因为它在浏览器的核心功能内运行，而不是利用应用程序级漏洞。  
  
**免责声明**  
：  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
