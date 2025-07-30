#  Apache ActiveMQ 漏洞导致隐秘 哥斯拉 Webshel​​l   
 Ots安全   2024-06-01 12:34  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
Trustwave 发现利用 Apache ActiveMQ 主机漏洞的攻击数量激增。在某些情况下，这些主机会托管恶意 Java Server Pages (JSP) Web Shell。  
  
这些 Web Shell 隐藏在未知的二进制格式中，旨在逃避安全和基于签名的扫描程序。值得注意的是，尽管二进制文件格式未知，但 ActiveMQ 的 JSP 引擎仍会继续编译和执行 Web Shell。  
  
ActiveMQ 漏洞  
  
在过去几周中，针对 Apache ActiveMQ 软件中最近出现的严重漏洞的恶意活动显著增加。此漏洞与OpenWire协议中不安全的反序列化做法有关，编号为CVE-2023-46604。利用此漏洞，威胁行为者可以通过执行任意 shell 命令来潜在地获得对目标系统的未经授权的访问。自2023 年 10 月公开漏洞利用的PoC以来，威胁行为者一直在使用它来部署加密矿工、rootkit、勒索软件和远程访问木马。  
  
投掷有效载荷  
  
最近，我们的全球威胁运营团队发现了一个可疑的 JSP 文件在托管有易受攻击的 Apache ActiveMQ 实例的客户端服务器中。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tac3DiclD1Jd1GYez9xJoCzgWhBtaA79PRiaYfibZic9f6TEAQibEG3PT1vfPA4RLCvST8vsWDUjo7YLVXA/640?wx_fmt=png&from=appmsg "")  
  
图 1 Trustwave 全球威胁行动小组发现的可疑文件。检查 .JSP 文件发现恶意代码封装在未识别文件格式的二进制结构中，并以“FLR”魔术标头为标记。  
  
该恶意文件被植入到 ActiveMQ 安装目录中的“admin”文件夹中。此文件夹包含 ActiveMQ 管理和 Web 管理控制台的服务器脚本。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tac3DiclD1Jd1GYez9xJoCzgWnVw1AOQwlZlhMurWQ3zSDa3lHf2zomg8sDwbJoDLWcyfLcISGjKbCw/640?wx_fmt=png&from=appmsg "")  
  
图2 恶意文件被植入在Apache ActiveMQ管理页面的同一目录中。  
  
经过进一步分析，Trustwave SpiderLabs 确定此 JSP 代码来自一个名为Godzilla Webshell的开源 Web Shell 。这些恶意文件特别值得注意的地方在于，JSP 代码似乎隐藏在未知类型的二进制文件中。这种方法有可能规避安全措施，在扫描过程中逃避安全端点的检测。  
  
有趣的是，Apache ActiveMQ 中集成的 Web 服务器 Jetty JSP 引擎实际上解析、编译并执行了封装在未知二进制文件中的嵌入式 Java 代码。进一步检查 Jetty 生成的 Java 代码发现，Web Shell 代码被转换为 Java 代码并因此被执行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tac3DiclD1Jd1GYez9xJoCzgW7t2aHFbIQD6NKNu1sRoqJYHiblibpmewQSdicUtib4vlpTxiah2JzrNnSkw/640?wx_fmt=png&from=appmsg "")  
  
图 3. 说明了 JSP 引擎生成的 Java 代码，该代码是在访问 JSP 文件时生成的。  
  
未识别数据然后使用“out.write()”将二进制文件中的内容发送到客户端的浏览器，导致从浏览器访问Web Shell时显示难以理解的字符。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tac3DiclD1Jd1GYez9xJoCzgWXPLvXiaRFhPY9MibEHU2qOlic3pJ8g941hYQ1FWbf6Bj5sQGL2k3s0uNw/640?wx_fmt=png&from=appmsg "")  
  
图 4. 在浏览器中访问 JSP 文件时，二进制文件中无法识别的数据会显示为无法理解的字符串。但是，Web shell 代码现在已不存在，已被转换为 Java 代码并在服务器端执行。  
  
哥斯拉 Webshell  
  
成功利用和部署 JSP 负载后，威胁行为者可以通过Godzilla管理用户界面连接到 Web shell，从而完全控制目标系统。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tac3DiclD1Jd1GYez9xJoCzgWicond3GktCXNL8NbZpqmVjUY4iaMTro23P7AX66vyU3j5gtxEOTK24vg/640?wx_fmt=png&from=appmsg "")  
  
图 5 威胁行为者可以使用的 Godzilla 管理用户界面  
  
一旦部署到目标网络服务器中，Godzilla Web Shell 将具有广泛的功能，包括但不限于：  
- 查看网络详细信息  
  
- 进行端口扫描  
  
- 执行 Mimikatz 命令  
  
- 运行 Metpreter 命令  
  
- 执行 shell 命令  
  
- 远程管理 SQL 数据库  
  
- 将 shellcode 注入进程  
  
- 处理文件管理任务  
  
受影响的 Apache ActiveMQ 版本  
  
以下 Apache ActiveMQ 版本受到影响。建议用户将代理和客户端都升级到版本 5.15.16、5.16.7、5.17.6 或 5.18.3，以修复此漏洞。   
  
- Apache ActiveMQ 5.18.0 5.18.3 之前版本  
  
- Apache ActiveMQ 5.17.0 5.17.6 之前版本  
  
- Apache ActiveMQ 5.16.0 5.16.7 之前版本  
  
- Apache ActiveMQ 5.15.16 之前版本  
  
- Apache ActiveMQ 旧版 OpenWire 模块 5.18.0 早于 5.18.3  
  
- Apache ActiveMQ Legacy OpenWire 模块 5.17.0 早于 5.17.6  
  
- Apache ActiveMQ Legacy OpenWire 模块 5.16.0 早于 5.16.7  
  
- Apache ActiveMQ 旧版 OpenWire 模块 5.8.0 5.15.16 之前  
  
  
国际奥委会：  
  
MD5：  
```
5e6993bba5e8e72a4899d6ddfb167972
f257b2669b15ca2792625d0bce00d907
5b4871092491a51477a13af5030c76b7
```  
  
SHA256：  
```
233adf5d3c754ead3f304a4891d367884dd615d74d9983119546bebb346b7bf7
5da5796d407a0099aa624b1ea73a877a5197b3b31529d94f2467dce19fe3a74a
f97c6c820694a059c7b0b2f3abe1f614b925dd4ab233d11472b062325ffb67be
```  
  
哥斯拉的默认协议标头：  
```
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
```  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
