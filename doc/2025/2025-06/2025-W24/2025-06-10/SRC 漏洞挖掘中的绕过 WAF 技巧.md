#  SRC 漏洞挖掘中的绕过 WAF 技巧  
原创 GhostShell  乌雲安全   2025-06-10 01:51  
  
   
  
在 SRC 漏洞挖掘中，WAF是挖掘者面临的一大障碍。WAF 能够检测和阻止常见的攻击请求，但挖掘者可通过特定技巧绕过它，下面介绍几种常见的绕过 WAF 技巧。  
## 一、基于正则表达式的绕过  
  
WAF 通常使用正则表达式来匹配和过滤恶意请求。挖掘者可通过修改 payload 的大小写、使用编码、替换函数或字符、使用替代语法以及添加换行符或制表符等方式，来绕过基于正则表达式的过滤。  
- • **大小写变换**  
 ：WAF 的正则表达式可能对大小写敏感，通过改变 payload 中关键字的大小写，可使 WAF 无法匹配从而绕过检测。例如，将 <script>  
 改为 <sCrIpT>  
。  
  
- • **编码利用**  
 ：使用不同的编码方式，如 URL 编码、Unicode 编码、Base64 编码等，可将 payload 转换为 WAF 无法直接识别的格式。如将 javascript:alert(1)  
 转为 unicode 编码为 %u006A%u0061%u0076%u0061%u0073%u0063%u0072%u0069%u0070%u0074%u003A%u0061%u006C%u0065%u0072%u0074%u0028%u0031%u0029  
。  
  
- • **使用替代语法和字符**  
 ：采用不常见的函数、语法结构或字符来替代常见的攻击payload。例如，使用 Function("ale"+"rt(1)")();  
 代替常见的 alert(1)  
，或者用反引号代替括号与引号，如 new Function  
alt`6`;  
。  
  
## 二、HTTP 协议特性利用  
- • **分块传输编码**  
 ：在 HTTP 请求中添加 Transfer-Encoding: chunked  
 头，将请求体分为多个块进行传输。在每个块中，可以将关键字拆分并编码，以绕过 WAF 对关键字的检测。例如：  
  
```

POST /test.php HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

4
a=1
4
unio
4
n se
5
lect
1
1
0

```  
- • **畸形包构造**  
 ：利用 HTTP 协议的特性，构造畸形的 HTTP 请求包。例如，将 GET 请求转换为 POST 请求，修改请求中的空格为 %20  
，并将 Connection  
 字段设置为 keep-alive  
，然后在请求体中添加 payload。由于 WAF 可能对畸形包的解析存在缺陷，从而实现绕过。  
  
## 三、字符集与编码绕过  
- • **修改字符集**  
 ：通过修改 HTTP 请求中的 Content-Type  
 头，指定不同的字符集（如 ibm500），使 WAF 无法正确识别和处理请求中的payload。例如，将 <script>alert("xss")</script>  
 使用 IBM037 编码后，得到 L%A2%83%99%89%97%A3n%81%93%85%99%A3M%7F%A7%A2%A2%7F%5DLa%A2%83%99%89%97%A3n  
。  
  
- • **Unicode 兼容性绕过**  
 ：利用 Unicode 字符的兼容性，构造与常见攻击payload 在 Unicode 标准下等价但形式不同的字符序列。例如，使用 Unicode 兼容字符 <＜img src⁼p onerror⁼＇prompt⁽1⁾＇﹥  
 替代原始的 <img src=p onerror='prompt(1)'>  
，在 Web 服务器进行 Unicode 归一化处理后，仍能执行恶意操作，但可能绕过 WAF 的检测。  
  
## 四、业务逻辑与功能利用  
- • **利用业务逻辑漏洞**  
 ：深入研究目标系统的业务逻辑，寻找可利用的漏洞。例如，在某支付场景中，通过修改数据包中的参数，绕过正常的支付流程，实现未授权访问或操作。如某银行业务逻辑漏洞，通过修改数据包参数绕过指纹支付和脸部识别支付。  
  
- • **借助 Web 资源与功能**  
 ：利用 Web 页面中的合法资源和功能来隐藏或传输恶意 payload。例如，使用 <iframe>  
 标签加载恶意脚本，或将 payload 存储在 Web 存储中（如 localStorage），然后通过 JavaScript 读取并执行。  
  
## 五、工具与脚本辅助  
- • **使用专业工具**  
 ：借助如 Burpsuite、SQLmap 等专业安全工具，这些工具内置了多种绕过 WAF 的功能和技巧。例如，SQLmap 中的 --temper  
 参数可调用特定的脚本来修改 payload，以绕过 WAF 检测。常用的 temper 脚本有 apostrophemask.py  
、equaltolike.py  
、space2dash.py  
 等。  
  
- • **编写定制脚本**  
 ：根据目标系统的特性和 WAF 的规则，编写定制化的脚本来生成和发送绕过 WAF 的请求。例如，通过 Python 的 requests  
 库构造请求，并对 payload 进行特定的编码和变形。  
  
在 SRC 漏洞挖掘中，绕过 WAF 是一项具有挑战性但又至关重要的任务。以上介绍的这些技巧只是众多方法中的一部分，实际应用时需要根据具体的目标系统和 WAF 特性进行灵活组合和创新。同时，挖掘者应始终遵守法律法规和道德准则，在授权范围内进行漏洞挖掘和研究。  
  
   
  
  
