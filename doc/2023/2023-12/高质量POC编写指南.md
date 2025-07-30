#  高质量POC编写指南   
Longlone  Yak Project   2023-12-07 17:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/f7AtEgJhMZfCSs0zKcMmDXyJt76PDpGiataSbajd3BpbZnPXBCqFaA3icu2mY1LGqAmJHIiaCq5N9qCBv47ktQEYA/640?wx_fmt=gif&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/f7AtEgJhMZc84zehstChLfWow7L53icvmUowFrdoXnRPOhD5yyKH8SEcKB3FAPM87tpqIMqzMicLywDBJticqBp0A/640?wx_fmt=png&from=appmsg "")  
  
  
**前言**  
  
  
在开始编写 PoC 之前，深入了解**漏洞的特性、触发条件以及潜在影响**是至关重要的。只有对漏洞有全面的理解，才能编写出准确率更高的 PoC。  
  
其次，应该充分测试和验证编写的 PoC。确保 PoC 在目标环境中能够可靠地重现漏洞，并产生一致的结果。  
  
此外，及时更新和维护 PoC。随着时间的推移，漏洞的修复和新的检测方式可能会出现，因此，定期检查和更新编写的 PoC，以确保其仍然有效是很有必要的。  
  
在编写 PoC 进行漏洞检测时，难免会遇到误报和漏报的情况，然而，我们可以通过**下面的一些有效的方式来降低误报和漏报的发生**。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc84zehstChLfWow7L53icvmYed3WNG8cic4coY4vUcsZdGOp42wiasEluYSasgoanytDvtuJ3QM5Mmw/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZd7023HfLNKNHPkkdYRDud5wibrK7QsYyyEDicQNNlPopmLofUZeicpWf3PY9DHIItcib9nKvIFZsXa7A/640?wx_fmt=png "")  
#   
  
**准确性**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc84zehstChLfWow7L53icvm4SUpAW4MRYaRPFDr4jGboyOZ48aR3QhV0cHICQ76Uia1QDQbXt0Ut8g/640?wx_fmt=png&from=appmsg "")  
  
  
对一个确定存在漏洞的网站或靶场编写的 PoC 往往十分容易忽略一些误报场景。编写 PoC 时应该不止局限于只对靶场的测试。  
  
确保 PoC 能够通过**唯一确定的标识**  
来判断漏洞是否存在是非常重要的。以下是几种常见的方式来实现这一目标：  
  
1、  
**关键字匹配**：在响应数据包中搜索特定的关键字或字符串，这些关键字通常与漏洞的存在相关。例如，特定错误消息、异常行为或系统返回的特定标识符。如果关键字存在于响应中，可以判断漏洞存在。  
  
  
2、  
**特征码识别**：根据漏洞的特征码或指纹来识别漏洞。漏洞通常会导致特定的响应模式或标识符，如特定的HTTP响应状态码、HTTP头部。通过匹配这些特征码，可以确定漏洞是否存在。  
  
  
3、  
**可预测的变化检测**：某些漏洞可能会导致响应数据包中的可预测变化。例如，通过在请求中使用不同的参数值来检测是否存在注入漏洞。通过观察响应数据包的变化，可以确定漏洞是否存在。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/f7AtEgJhMZc84zehstChLfWow7L53icvm5yWuEfiaBFPp4UOia1haUc3vNbLO4mP0ic8GeZlkATXWJSvibzf5004w1g/640?wx_fmt=gif&from=appmsg "")  
  
  
一个合理的PoC  
不应当只使用上面中的**一种方法**  
进行判断，应当合理地结合多个条件来进行是否存在漏洞的断言，现在我们就以上的一些判断方式进行展开说明。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/zsUXYY6y4cIDakURPCPDZjdlWuibw4AP4eGlFKrE8SLFkxHImicaHBgbOZFG2SVZicibfvUNYDss9vJfyNbFLbgz6UL5b2rtVO8w/640?wx_fmt=svg&from=appmsg "")  
  
**关键字匹配**  
  
  关键字匹配在 PoC 的检测中是十分常见的，但是关键字匹配可能会存在一些问题，我们以 ThinkPHP  
 为例，使用如下 payload  
进行检测，随后通过匹配一些 phpinfo  
页面的关键字来断言漏洞是否存在：  
```
# ThinkPHP5 RCE PoC
s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1
```  
  
  但是如果目标网站的页面本身就是一个打印phpinfo  
的页面，那么此时就会产生误报。  
  
  同样的，很多使用 echo {{randstr(16)}}  
 随后匹配这串随机字符串也同样会有很大的误报问题，最为常见的情况就是，目标网站将你的输入，原样的输出在返回的body  
中，此时就会产生一条误报  
  
  我们使用 httpbin.org  
 来进行演示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc84zehstChLfWow7L53icvm6ZUSKl73zojEfMwIMQHNoxAdymu4x2NeY57ciacmqfj3j6ibKNKhDZkg/640?wx_fmt=png&from=appmsg "")  
  
和 echo  
同理的还有一些各种语言的一些打印函数，如 print  
 等等。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/zsUXYY6y4cIDakURPCPDZjdlWuibw4AP4eGlFKrE8SLFkxHImicaHBgbOZFG2SVZicibfvUNYDss9vJfyNbFLbgz6UL5b2rtVO8w/640?wx_fmt=svg&from=appmsg "")  
  
**特征码识别**  
  
  特征码识别则更为简单，比如通过判断HTTP响应状态码这种方式是极其不建议的行为，**必然会产生误报，十分不建议**  
在 PoC 中**只使用状态码**  
进行漏洞是否存在的依据。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/zsUXYY6y4cIDakURPCPDZjdlWuibw4AP4eGlFKrE8SLFkxHImicaHBgbOZFG2SVZicibfvUNYDss9vJfyNbFLbgz6UL5b2rtVO8w/640?wx_fmt=svg&from=appmsg "")  
  
**可预测的变化检测**  
  
  通过预测结果的方式进行检测，是相对推荐的做法。比如我们已经知道了 123  
 md5 后的值，那么我们可以通过 echo md5({{randstr(16)}})  
 的方式进行漏洞的判断  
  
  在这里给出一些**有回显可预测**  
变化的一些检测方法：  
- **代码执行**  
  
- print({{randint(8)}} * {{randint(8)}})  
，匹配相乘后的结果  
  
- print("{{randstr(8)}}" + "{{randstr(8)}}" )  
，匹配字符串拼接后的结果  
  
- print(md5({{randstr(16)}}))  
，匹配 md5 后的结果  
  
- printf("{{randstr(16)}}%%{{randstr(16)}}")  
 实际输出会少一个百分号，检出时只需要匹配{{randstr(16)}}%{{randstr(16)}}  
即可  
  
  
- **命令执行**  
  
- Linux 下可以使用  
  
- expr {{randint(8)}} - {{randint(7)}}  
,匹配相减后的数字即可  
  
- echo aaaa""bbbb，echo aaaa''bbbb  
，匹配 aaaabbbb  
即可  
  
- echo aaaa\bbbb  
，匹配aaaabbbb  
即可  
  
- Windows 下可以使用  
  
- set /a result={{randint(8)}}-{{randint(7)}} && call echo %result%  
,匹配相减后的数字即可  
  
  
- **SQL 注入类型**  
  
- select md5({{randstr(16)}})  
，匹配 md5 后的结果  
  
- select concat('{{randstr(8)}}','{{randstr(8)}}')  
，匹配字符串拼接后的结果  
  
  
- **文件读取**  
  
  
- root:.*:0:0:  
，使用正则进行匹配  
  
  
  
**通用性**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc84zehstChLfWow7L53icvm4SUpAW4MRYaRPFDr4jGboyOZ48aR3QhV0cHICQ76Uia1QDQbXt0Ut8g/640?wx_fmt=png&from=appmsg "")  
  
  
在编写 PoC 时，确保 Payload  
或包含的检测代码兼顾各个环境或平台的考虑是很重要的。以下是一些关键原则：  
  
1、  
**尝试构建通用的 Payload**：尽量编写通用的 Payload，可以在多个环境或平台上使用。这意味着避免使用仅适用于特定版本、配置或目标的代码。通过使用通用的技术和标准协议，可以提高 PoC 的适用性和可移植性。  
  
  
2、  
**考虑常见的安全防护机制**：在编写 PoC 时，要考虑到目标环境可能存在的常见安全防护机制，如防火墙、入侵检测系统（IDS），语言本身的防护机制等。确保所使用的 Payload 不会被这些机制拦截或干扰，以提高漏洞检测的成功率。  
  
  
3、  
**无法通用检测时**：考虑编写不同平台对应的 Payload分别发送检测。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/f7AtEgJhMZc84zehstChLfWow7L53icvm5yWuEfiaBFPp4UOia1haUc3vNbLO4mP0ic8GeZlkATXWJSvibzf5004w1g/640?wx_fmt=gif&from=appmsg "")  
  
  
现在我们就以上的一些编写原则进行展开说明。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/zsUXYY6y4cIDakURPCPDZjdlWuibw4AP4eGlFKrE8SLFkxHImicaHBgbOZFG2SVZicibfvUNYDss9vJfyNbFLbgz6UL5b2rtVO8w/640?wx_fmt=svg&from=appmsg "")  
  
**构建通用的 Payload**  
##   
  
在编写 PoC 时，我们要进行一点的思考，比如，**能通过代码执行的漏洞，就不要再通过代码调用系统命令来执行**  
。举例说明如图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc84zehstChLfWow7L53icvmDKJuPuRedArnvFczxGGPA3icKo1KF0yA8wViavlwCtvlVGBmRhUaexFA/640?wx_fmt=png&from=appmsg "")  
  
上图是 ThinkPHP 代码执行漏洞，使用 system 去执行命令来进行检测，这种方式存在很多的弊端  
- 不够通用，Windows  
下和 Linux  
下可能没有足够通用的命令用于检测，使用 PHP 自带的输出函数加上算数运算来验证，如前文中提出的print  
、printf  
  
- 没有考虑安全防护机制，比如 PHP 经常存在的   
disable_functions  
 以及一些 WAF 之类的  
  
  推荐的检测方式：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc84zehstChLfWow7L53icvmqKibIveSuoPH73ydoySUOjRJxeuibfXx3LvFZKdxHkW3raYouW5VfY1g/640?wx_fmt=png&from=appmsg "")  
  
这种检测方式更加通用，同时也不容易触发防护机制。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/zsUXYY6y4cIDakURPCPDZjdlWuibw4AP4eGlFKrE8SLFkxHImicaHBgbOZFG2SVZicibfvUNYDss9vJfyNbFLbgz6UL5b2rtVO8w/640?wx_fmt=svg&from=appmsg "")  
  
**考虑常见的安全防护机制**  
##   
  
上一点中也提到过，对于 PoC 的编写，有别于 EXP ，建议  
**点到即止**  
，比如说，一个反序列化漏洞，在 PoC 中，建议选择打印随机字符串来进行检测，或其他的无害化的方式。确保能正常检出漏洞，当 PoC 的检测逻辑足够健壮时，EXP 利用失败，则只需要考虑是不是 Payload 被拦截了，尝试进行对应的一些绕过操作即可。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/zsUXYY6y4cIDakURPCPDZjdlWuibw4AP4eGlFKrE8SLFkxHImicaHBgbOZFG2SVZicibfvUNYDss9vJfyNbFLbgz6UL5b2rtVO8w/640?wx_fmt=svg&from=appmsg "")  
  
**无法通用检测时**  
##   
  
这种情况常见于**命令执行、文件读取漏洞**  
的情况，可以根据对应平台分别发送检测 Payload 进行检测，如发送两个检测包，第一个是针对 Windows 的，第二个是针对 Linux 的即可。  
  
通过兼顾各个环境和平台的考虑，编写通用的 Payload 和检测代码，可以提高 PoC 的适用性、可靠性和实用性，从而更有效地进行漏洞检测和验证。  
  
  
**无害性**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc84zehstChLfWow7L53icvm4SUpAW4MRYaRPFDr4jGboyOZ48aR3QhV0cHICQ76Uia1QDQbXt0Ut8g/640?wx_fmt=png&from=appmsg "")  
  
  
在 PoC 检测阶段，遵循无害性原则是很重要的。即使在执行一些敏感操作，如文件上传，我们希望确保这些操作是无害的并不会对目标系统产生不良影响。以下是一种方式来上传一个自删除的文件，以满足无害性要求：  
- 确保编写的PoC  
不会对目标造成危害。包括但不限于，插入，删除，篡改等等直接或间接产生危害的操作。  
  
- 对于文件上传类漏洞，请尝试清理PoC  
测试中产生的测试  
文件，即在访问该文件后删除自身，例如：  
  
  
- php：  
  
```
<?php echo md5(233);unlink(__FILE__);?>
```  
- asp:   
  
```
<%
Response.Write chr(101)&chr(49)&chr(54)&chr(53)&chr(52)&chr(50)&chr(49)&chr(49)&chr(49)&chr(48)&chr(98)&chr(97)&chr(48)&chr(51)&chr(48)&chr(57)&chr(57)&chr(97)&chr(49)&chr(99)&chr(48)&chr(51)&chr(57)&chr(51)&chr(51)&chr(55)&chr(51)&chr(99)&chr(53)&chr(98)&chr(52)&chr(51)
CreateObject("Scripting.FileSystemObject").DeleteFile(server.mappath(Request.ServerVariables("SCRIPT_NAME")))
%>
```  
- aspx:   
  
```
<%@Page Language="C#"%>
<%
Response.Write(System.Text.Encoding.GetEncoding(65001).GetString(System.Convert.FromBase64String("ZTE2NTQyMTExMGJhMDMwOTlhMWMwMzkzMzczYzViNDM=")));System.IO.File.Delete(Request.PhysicalPath);
%>
```  
- jsp:   
  
```
<% out.println(new String(new sun.misc.BASE64Decoder().decodeBuffer("ZTE2NTQyMTExMGJhMDMwOTlhMWMwMzkzMzczYzViNDM=")));new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>

```  
- jspx:   
  
```
<jsp:root xmlns="http://www.w3.org/1999/xhtml" version="2.0" xmlns:jsp="http://java.sun.com/JSP/Page" xmlns:c="http://java.sun.com/jsp/jstl/core">
<jsp:directive.page contentType="text/html;charset=UTF-8" language="java" />
jsp:scriptlet out.println(new String(new sun.misc.BASE64Decoder().decodeBuffer("ZTE2NTQyMTExMGJhMDMwOTlhMWMwMzkzMzczYzViNDM="))); new java.io.File(application.getRealPath(request.getServletPath())).delete(); </jsp:scriptlet> </jsp:root> ```
```  
```
```  
```
```  
  
通过采用以上方法，在 PoC 检测阶段，可以实现无害的文件上传，并且在访问上传后的文件时触发自删除操作，既可以验证文件是否上传成功，也可以清理测试文件，确保对目标系统的安全性和完整性没有不良影响。  
  
  
**随机性**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc84zehstChLfWow7L53icvm4SUpAW4MRYaRPFDr4jGboyOZ48aR3QhV0cHICQ76Uia1QDQbXt0Ut8g/640?wx_fmt=png&from=appmsg "")  
  
  
Payload  
 中不要出现一些固定的字符或者有关任何个人、公司的信息，尽量使用一些随机字符来进行检测，例如一段随机字符串、一段随机字符串的 Hash  
 值等等，这样做的好处有，提高PoC  
检测的准确性，以及避免被安全设备特征识别。  
  
1、  
**避免固定字符和个人信息**：确保在编写 PoC 时避免使用固定的字符或与个人、公司相关的信息。这样可以防止泄露敏感信息或暴露特定目标的身份，同时也有助于提高 PoC 的通用性和适用性。  
  
  
2、  
**使用随机字符串或哈希值**：尽量使用随机生成的字符串或哈希值来构造 Payload。这样可以增加 Payload 的多样性和复杂性，提高对目标系统的覆盖能力，使 PoC 更具准确性。  
  
  
3、  
**提高漏洞检测的准确性**：通过使用随机字符，可以模拟真实攻击中的变化和随机性。这样可以更全面地测试目标系统的漏洞，提高检测的准确性。避免使用预测性、可被安全设备轻易识别的固定模式。  
  
  
4、  
**规避安全设备的特征识别**：某些安全设备可能会使用特征识别技术来检测和拦截恶意攻击。通过使用随机字符和随机生成的值，可以规避这些特征识别机制，增加 PoC 的检出率。  
  
  
5、  
**增加兼容性和适用性**：使用随机性可以使编写的 PoC 在不同环境、平台和版本之间具有更好的兼容性和适用性。随机生成的值可以适应各种情况和配置，从而提高 PoC 的可靠性和实用性。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/f7AtEgJhMZc84zehstChLfWow7L53icvm5yWuEfiaBFPp4UOia1haUc3vNbLO4mP0ic8GeZlkATXWJSvibzf5004w1g/640?wx_fmt=gif&from=appmsg "")  
  
  
  
**END**  
  
****  
  
  
 **YAK官方资源**  
  
  
Yak 语言官方教程：  
https://yaklang.com/docs/intro/Yakit 视频教程：  
https://space.bilibili.com/437503777Github下载地址：  
https://github.com/yaklang/yakitYakit官网下载地址：  
https://yaklang.com/Yakit安装文档：  
https://yaklang.com/products/download_and_installYakit使用文档：  
https://yaklang.com/products/intro/常见问题速查：  
https://yaklang.com/products/FAQ  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/f7AtEgJhMZc6nLOagqic2nNou7bAeMlkj1CKwGWMGSiaeBCN9r5JBz87nQDSDFyRsPhWia09n3icgcNQicS7bK3qv8Q/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**长按识别添加工作人员**  
  
开启Yakit进阶之旅  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZdyeuVJ3LBqORgX3FWzMcMd3ptaK5mO374IkNu0TibJzBibrRD0HzurpUOicvcibXcxXMK1H9amXRyxUw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
