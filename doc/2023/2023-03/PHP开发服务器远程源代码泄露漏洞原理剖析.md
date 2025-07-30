#  PHP开发服务器远程源代码泄露漏洞原理剖析   
 山石网科安全技术研究院   2023-03-24 11:39  
  
‍PHP Built-in Server是PHP自带的Web服务器，多用于在研发阶段快速启动并运行一个可以执行PHP脚本的Web服务器。由于其性能及安全性并没有得到完好的保障，故PHP官方并不建议在生产环境下使用这个服务器。  
  
**0****1**  
  
  
**历史问题**  
```
```  
#   
  
**0****2‍**  
  
  
**PHP 开发服务器 <= 7.4.21 - 远程源泄露****‍‍‍‍‍‍‍‍‍**  
  
经过测试，我们发现该漏洞不存在于最新的 PHP 版本中。我们对不同版本的 PHP 进行了进一步测试，以确定错误修复的时间和原因。通过调查，我们发现 PHP 7.4.22 的补丁版本，通过比较未打补丁的代码和打补丁的代码，我们可以看到为修复漏洞所做的具体更改。  
  
需要注意的是，虽然此问题已在 PHP 源代码中得到解决，但 Shodan 查询揭示了内置服务器的许多暴露实例。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR5jibvuTtVg7DvbUGnOV0V3fQZv9WibI0IBFjNBVSWiaBLlzJFsXmsZpBzyZ9pmHmzdDsET5golzkoQ/640?wx_fmt=png "")  
  
  
  
**0****3‍‍**  
  
  
**原因‍**  
  
为了充分了解该错误及其修复方式，我们在启用调试符号的情况下编译了已打补丁和未打补丁的 PHP 版本。使用概念验证 (PoC) 请求，我们触发了源代码泄露错误并观察了调试器中的代码流。  
```
```  
  
所有对 CLI 服务器的 HTTP 请求都由php_cli_server_client_read_request  
. 跟踪看起来像这样：  
```
```  
  
php_cli_server_client_read_request  
函数调用函数，php_http_parser_execute  
顾名思义，就是用来解析HTT当下面提到的请求的第一部分几乎完成解析时：  
```
```  
  
并且 HTTP 请求不包含Content-Length  
标头，CALLBACK2(message_complete)  
在下面的代码中调用。在这里，是一个宏，它会在请求消息处理完成后CALLBACK2  
依次调用回调函数。php_cli_server_client_read_request_on_message_complete  
```
```  
  
**CALLBACK2(…) 是如何工作的？**  
```
```  
  
预处理后，CALLBACK2(message_complete)转换为：  
```
```  
  
**settings**是一个类型的结构，php_http_parser_settings  
  
设置变量的每个成员都填充有各自的回调函数。  
  
然后将此对**设置**php_http_parser_execute  
的引用作为参数传递给函数。  
```
```  
  
同样，有CALLBACK  
和CALLBACK_NOCLEAR  
宏的工作方式几乎相同。  
  
因此，CALLBACK2(message_complete)  
结果在调用php_cli_server_client_read_request_on_message_complete(...)  
和CALLBACK(path)  
调用php_cli_server_client_read_request_on_path(...)  
等。  
```
```  
  
很快，我们进入php_cli_server_request_translate_vpath  
功能。此函数将请求的 PHP 文件的路径转换为文件系统上的完整路径。如果请求的文件是目录，它会检查目录中是否存在索引文件，index.php  
如果index.html  
找到，则使用其中一个文件的路径。这允许服务器响应请求提供正确的文件  
  
简而言之，此函数将结构vpath  
和path_translated  
成员设置为request  
结构。所以，对于当前解析的请求，  
```
```  
  
我们最终进入了**request->path_translated**  
设置了的条件分支。这个很重要，后面会用到。  
```
```  
  
函数调用堆栈展开后，我们继续执行内部流程php_http_parser_execute  
。现在，请求的第二部分被解析为状态恢复为start_state  
：  
```
```  
  
和最初的请求一样，我们进入php_cli_server_client_read_request_on_message_complete  
函数，然后调用php_cli_server_request_translate_vpath  
. 这个过程用于像第一次请求一样解析和处理后续请求。  
  
这一次，在 内部php_cli_server_request_translate_vpath  
，由于我们请求的是目录 ( /  
) 而不是文件，因此我们将输入不同的代码块。  
```
```  
  
最后，在请求解析完成后，我们从php_http_parser_execute  
. nbytes_consumed  
比较已解析字节长度 ( ) 和已读取字节长度( )的返回值nbytes_read  
（更多信息请参见此处）。如果它们相等，代码流继续，我们进入php_cli_server_dispatch  
函数。  
```
```  
  
上面提供的代码包括一个检查，以确定请求的文件是否应该被视为静态文件或作为 PHP 文件执行。这是通过检查文件的扩展名来完成的。如果扩展名不是.php  
或.PHP  
，或者扩展名的长度不等于 3，则认为该文件是静态文件。这通过将is_static_file  
变量设置为 1 来指示。  
  
该代码还检查对象的path_translated  
字段client->request  
是否不为空。该字段包含文件系统上所请求文件的完整路径，用于定位和提供文件。如果该path_translated  
字段为空，则表示找不到请求的文件，请求将被视为错误。  
  
代码流继续执行该php_cli_server_begin_send_static  
函数，因为is_static_file  
它被设置为 true。  
```
```  
## ‍‍  
  
**0****4‍**  
  
  
**错误**  
  
这就是错误所在。如上述代码块中所示，在解析第二个请求后，vpath  
设置为/  
并假设未找到索引文件client->request.ext  
将设置为NULL  
. 但是，client->request.path_translated  
仍然设置为/tmp/php/phpinfo.php  
来自第一个请求。检查是在client->request.ext  
第二个请求的时候执行的，我们进入这个分支并将其设置is_static_file  
为1  
。基本上，将请求的文件视为静态文件而不是 PHP 脚本。  
```
```  
  
请注意，此函数打开文件描述符并将其检索到存储在client->request.path_translated  
. 在我们的示例中，client->request.path_translated  
将设置为/tmp/php/phpinfo.php  
. 这种差异，即检查发生在client->request.ext  
第二个请求上，但随后打开client->request.path_translated  
第一个请求设置的文件，导致源代码泄露。  
  
现在文件被标记为is_static_file  
，代码流现在只读取 fd 并将其作为静态文件返回，而不是执行它。  
  
  
**0****5‍**  
  
  
**修复**  
  
PHP 7.4.22 中引入了检查。此修复程序在解析请求路径时检查结构的vpath  
成员是否不为 NULL。request  
如果它不为 NULL，则函数返回 1。  
```
```  
  
解析请求消息第一部分的路径时，client->request.vpath  
最初为 NULL，后来设置为/phpinfo.php  
。但是，当解析请求的第二部分的路径时，client->request.vpath  
已经设置了而不是 NULL，这导致函数返回 1。  
```
```  
  
php_cli_server_client_read_request_on_path  
在解析第二个请求的路径时，我们从CALLBACK(path)  
进入这个修补过的函数。宏检查确保回调函数的CALLBACK(path)  
返回值始终为 0。如果不是这种情况，我们将从解析函数php_http_parser_execute  
返回，返回值将是它在解析请求时已经消耗的字节数。  
  
返回值存储在nbytes_consumed  
变量中并与nbytes_read  
（即请求中的实际字节数）进行比较。  
```
```  
  
如果解析器消耗的字节数不等于读取的字节总数，则意味着请求格式错误。在这种情况下，代码会检查缓冲区的第一个字节以确定请求是否为 SSL 请求。否则，它将错误消息设置为“ **Malformed HTTP request** ”并返回。  
  
  
**0****6‍**  
  
  
**拓展**  
  
在解析 HTTP 请求期间，当某些回调被多次调用时，REQUEST_URI  
服务器变量会被其自身的子字符串覆盖。  
  
在某些情况下，此行为可能导致开放重定向或跨站点脚本 (XSS) 攻击。这是一个例子：  
  
**示例片段：**  
```
```  
  
复制  
  
请求GET /index.php?abcd  
将导致呈现为：  
‍  
```
```  
  
复制  
  
超链接将始终相对于它所在的域。此外，该路径会将元字符转换为其 HTML 实体。因此，XSS 是不可行的。  
  
但是，攻击者仍然可以通过在 URL 中发送带有非常长查询字符串的 GET 请求来利用这一点，例如示例中所示的那个。  
```
```  
  
复制  
  
被REQUEST_URI  
覆盖，仅以 结尾javascript:alert(1)  
。用所需内容成功覆盖它所需的填充量各不相同，可能需要调整。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR5jibvuTtVg7DvbUGnOV0V3O9ictEiaSl4Ojp4jMSs35TVMFktUj4tnmUDapbbWMuqqcvNKeXEp3yDQ/640?wx_fmt=png "")  
  
  
  
**0****7‍**  
  
  
**概念验证**  
  
**基本概念验证**：  
```
```  
  
复制  
  
上述请求提供了一个基本的 HTTP 请求作为概念证明，它将公开源代码phpinfo.php  
而不是执行它。  
  
确保在 Burp Suite 等拦截 HTTP 代理中关闭“**更新内容长度**”，以使概念验证生效。  
  
index.php  
我们观察到，如果该文件存在于服务器启动的当前目录中，则不会泄露源代码。index.php  
然而，我们对漏洞利用 POC 进行了轻微修改，无论文件是否存在，它都会公开源代码。其原因在于上面对bug的解释。  
  
**升级后的 POC：**  
```
```  
  
  
         
  
