#  构建 Spectre：用于 XSS 漏洞利用的红队工具（第 1 部分）   
haidragon  安全狗的自我修养   2024-11-28 23:12  
  
# 介绍  
  
每个红队成员都有他们最喜欢的工具集，但有时当它们都没有完全满足你的需求时，你会碰壁。这就是我在处理基于浏览器的攻击时发现自己遇到的情况，尤其是围绕   
XSS 利用的攻击。有很好的工具可以查找 XSS 漏洞，但我想要一些可以快速、动态和交互式地显示影响的工具。  
  
这促使我创建了   
Specter，这是一个旨在实时利用 XSS 漏洞的红队工具。Spectre 使用   
WebSocket C2 服务器将有效负载直接发送到连接的浏览器，并带有预构建的攻击脚本菜单，这些脚本也可以动态自定义。  
  
这个博客是我旅程的第 1 部分。我将向您介绍该项目背后的灵感、架构以及我在构建项目时面临的一些挑战。如果你是一个喜欢摆弄漏洞利用工具的人，或者只是对红队工具是如何组合在一起感到好奇的，我希望这篇博客能引起你的共鸣。  
# 为什么要构建 Spectre？  
  
这一切都始于我试图在红队参与期间演示 XSS 漏洞的影响。虽然有一些工具可以自动发现 XSS，但不太关注实时利用这些漏洞。我想要一个可以：  
1. 按需执行  
自定义 JavaScript 负载。  
  
1. 提供  
预构建的漏洞利用脚本菜单以进行快速演示。  
  
# 如何运作  
  
Spectre 基本上分为两部分：  
1. 服务器：基于 Python 的 WebSocket 服务器，充当控制中心，允许您选择有效负载并将其发送到连接的客户端。  
  
1. 客户端：注入浏览器的一个小 JavaScript 代码段，用于执行服务器发送的有效负载。  
  
## 主要特点  
- 预定义负载的菜单，例如键盘记录器、地理位置检索和网络摄像头访问。  
  
- 对需要用户输入的脚本（如 URL 或自定义消息）进行动态自定义。  
  
## 设置环境  
## 先决条件：  
- Python 3.7+ 版  
  
- ngrok  
用于公开 WebSocket 服务器  
  
- JavaScript 和 WebSocket 的基本知识  
  
## 第 1 步：克隆项目  
  
您可以先克隆   
Specter 存储库或使用提供的 and 文件创建 Python 项目。[很快就会分享 repo，代码还在开发中，报错少 ： （ ]server.pypayloads.py  
## 第 2 步：安装依赖项  
  
确保您已安装。如果没有，请使用 pip 安装它：websockets  
```
```  
  
以下是   
Spectre 项目结构的简要概述：  
```
```  
# 关键组件：  
1. server.py  
:  
  
托管 WebSocket 服务器。  
  
允许在连接的客户端上动态选择和执行负载。  
  
处理来自客户端的结果，如 Base64 图像或剪贴板数据。  
  
2.   
：payloads.py  
  
将模块化 JavaScript 有效负载存储为字典。  
  
有效载荷包括键盘记录器、地理位置、网络摄像头捕获等。  
  
3. :client.html  
  
包含一个 WebSocket 客户端，用于侦听命令并在浏览器中执行有效负载。  
  
4.   
：requirements.txt  
  
通过列出依赖项来帮助设置 Python 环境。  
  
5.   
：Readme  
  
它;仅用于文档目的。  
## Client.html  
  
该文件用作 Spectre 的  
测试客户端。它模拟恶意脚本嵌入到易受攻击的 Web 应用程序中的场景。以下是其组件的简要说明：client.html  
## 目的  
  
测试环境：此文件用于测试 Spectre 的 WebSocket 服务器功能。  
  
模拟漏洞利用：它运行 WebSocket 服务器动态发送的 JavaScript 有效负载。  
```
```  
## Server.py  
  
这是我们的服务器，将作为 C2 服务器运行，我们可以在其中从终端发送有效负载，并将在客户端浏览器上执行  
  
WebSocket 协议用于  
服务器（由您控制）和  
客户端（在浏览器上运行）之间的实时全双工通信。以下是有关如何建立连接以及如何将有效负载发送到客户端的分步说明：  
## 1. 客户端连接到服务器  
  
WebSocket 连接：  
  
客户端（浏览器）通过建立 WebSocket 连接连接到 WebSocket 服务器 （）。这由客户端 HTML 代码中的函数处理。ws://localhost:8765connectWebSocket()  
  
连接是使用 中的行从客户端启动的。new WebSocket("ws://localhost:8765")client.html  
# 2. 在服务器中处理客户端连接  
  
服务器接受连接：  
  
服务器通过该函数监听 port 上的传入 WebSocket 连接。8765websockets.serve(handle_client, "localhost", 8765)  
  
客户端连接后，将调用该函数。handle_client()  
  
该对象表示与客户端的活动连接，用于存储活动的 WebSocket 连接以供进一步通信。websocketcurrent_websocket  
# 3. 向客户端发送有效负载  
  
在服务器上选择 Payload：  
  
建立连接后，服务器允许用户（通常是红队操作员或攻击者）选择要发送到客户端的有效负载。  
  
系统提示操作员通过输入选择编号来选择有效负载，该编号对应于字典中的选项。payloads  
  
负载：  
  
有效负载是存储在字典中的预定义脚本。每个有效负载都有一个唯一的密钥和一个描述。payloads  
  
例如，键对应于  
键盘记录器，键对应于  
语音转文本功能。310  
```
```  
  
如果 Operator 选择的有效负载具有动态组件（如用于自定义有效负载的用户输入），则服务器会提示 Operator 输入必要的值，并在将其发送到 Client 端之前将其替换为有效负载。  
  
发送有效负载：  
  
选择负载后，服务器使用命令将其发送到客户端。这会将脚本 （JavaScript 代码） 发送到客户端执行。await websocket.send(payload)  
# 4. 在客户端上执行 Payload  
  
客户端上的有效负载执行：  
  
收到有效负载后，客户端 （） 使用 WebSocket 事件处理程序内的函数动态执行它。client.htmleval()onmessage  
  
该脚本在浏览器上下文中执行，这意味着它可以与页面交互、访问浏览器 API 等。  
```
```  
  
有效载荷示例：  
  
键盘记录器有效载荷：发送有效负载时（对应于 selection ），脚本将从浏览器捕获击键并将其发送回服务器。keylogger3  
  
语音转文本有效载荷：选择有效负载后，浏览器将启动语音识别并将转录的文本发送回服务器。speech-to-text  
# 结论  
  
在第一部分中，我们设置了   
Spectre 并演示了它如何通过 WebSocket 连接到客户端以发送动态负载，如键盘记录器和语音转文本。在下一部分中，我们将深入探讨更多有效载荷和高级功能，增强   
Spectre 以进行更深入的红队模拟。敬请期待！  
  
  
其它相关课程  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQEREkjoibjFst4F2YTlvkRG4zW4Nlt9pZBgFYgFxfVZFxu83EQnESej7ydiblH1UfHqKX3hBfcm76JiaSA/640?wx_fmt=png&from=appmsg "")  
#   
#   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQEREkjoibjFst4F2YTlvkRG4zW0h21TYuO94OrIGsD2aHGrUcUYiasibQS5AYJ4a95Ra3zIFIXQ4e8lkFA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQEREkjoibjFst4F2YTlvkRG4zW6iapnXQ3Wviaiaiap37xFRqNok6BymcTiacnk07OowXYFowAKYfa9zS6gSA/640?wx_fmt=png&from=appmsg "")  
#   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQEREkjoibjFst4F2YTlvkRG4zWiaJkE3jZRR7znMJDXAlibBzibYaGLMlVvsa1xhlQFyv3viaARicSIII7a9A/640?wx_fmt=png&from=appmsg "")  
#   
# 详细目录   
# QT开发底层原理与安全逆向视频教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQEREkjoibjFst4F2YTlvkRG4zWQTnLU8kyOziaAickQZiboFzmv3rdCdjbbNnMbalXF815XUjAZlia3pFbXQ/640?wx_fmt=png&from=appmsg "")  
  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHYgfyicoHWcBVxH85UOBNaPMJPjIWnCTP3EjrhOXhJsryIkR34mCwqetPF7aRmbhnxBbiaicS0rwu6w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
-    
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHYgfyicoHWcBVxH85UOBNaPZeRlpCaIfwnM0IM4vnVugkAyDFJlhe1Rkalbz0a282U9iaVU12iaEiahw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
   
  
linux文件系统存储与文件过滤安全开发视频教程(2024最新)  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHSM6Wk8NAEmbHHUS2brkROr9JOj6WZCwGz4gE4MlibULVefmhRw2dvJd8ZeYnDpRIm0AV1TmIsuEQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
linux高级usb安全开发与源码分析视频教程  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHCd9Qic4AAIQfFFD7Rabvry4pqowTdAw6HyVbkibwH5NjRTU4Mibeo4JbMRD3XplqCRzg4Kiaib3jchSw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
****  
**linux程序设计与安全开发**  
  
****  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERGoVibbKav1DpliaTJ9icDrosqXeWyaMRJdCVWEG0VYLDibSMwUP1L5r9XmLibGkEkSZnXjPD6mWgkib9lA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
-   
- **windows恶意软件开发与对抗视频教程**  
  
-   
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERFPap5AiahwlmRC2MGPDXSULNssTzKQk8b4K3pttYKPjVL4xPVu1WHTmddAZialrGo8nQB3dJfJvlZQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
#    
  
  
**二进制漏洞**  
  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHhezg9PuKylWLTBfCjokEH4eXCW471pNuHpGPzUKCkbyticiayoQ5gxMtoR1AX0QS7JJ2v1Miaibv1lA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- #   
  
-   
- w  
i  
n  
d  
o  
w  
s  
网  
络  
安  
全  
防  
火  
墙  
与  
虚  
拟  
网  
卡  
（  
更  
新  
完  
成  
）  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERE5qcRgQueCyt3U01ySnOUp2wOmiaFhcXibibk6kjPoUhTeftn9aOHJjO6mZIIHRCBqIZ1ok5UjibLMRA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- w  
i  
n  
d  
o  
w  
s  
文  
件  
过  
滤  
(  
更  
新  
完  
成  
)  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHhezg9PuKylWLTBfCjokEHmvkF91T2mwk3lSlbG5CELC5qbib3qMOgHvow2cvl6ibicVH4KguzibAQOQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- U  
S  
B  
过  
滤  
(  
更  
新  
完  
成  
)  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHhezg9PuKylWLTBfCjokEHv0vyWxLx9Sb68ssCJQwXngPmKDw2HNnvkrcle2picUraHyrTG2sSK7A/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- 游  
戏  
安  
全  
(  
更  
新  
中  
)  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHhezg9PuKylWLTBfCjokEHzEAlXtdkXShqbkibJUKumsvo65lnP6lXVR7nr5hq4PmDZdTIoky8mCg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- i  
o  
s  
逆  
向  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHhezg9PuKylWLTBfCjokEHmjrTM3epTpceRpaWpibzMicNtpMIacEWvJMLpKKkwmA97XsDia4StFr1Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- w  
i  
n  
d  
b  
g  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERECMA4FBVNaHekaDaROKFEibv9VNhRI73qFehic91I5dsr3Jkh6EkHIRTPGibESZicD7IeA5ocHjexHhw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- 还  
有  
很  
多  
免  
费  
教  
程  
(  
限  
学  
员  
)  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHhezg9PuKylWLTBfCjokEHDvveGEwLYBVsps1sH6rGrSnNZtjD2pzCk4EwhH3yeVNibMMSxsW5jkg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERECMA4FBVNaHekaDaROKFEibR2Viaxgog8I2gicVHoXJODoqtq7tTVGybA8W0rTYaAkLcp8e2ByCd1QQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERECMA4FBVNaHekaDaROKFEibDwwqQLTNPnzDQxtQUF6JjxyxDoNGsr6XoNLicwxOeYfFia0whaxu6VXA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQEREEHMPaJ2RMX7CPES3mic42r1Wub102J6lAmEwKIicDfADiajsEReibfvSCbmiaRlGRCQibqfJJia0iak421Q/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
- 更  
多  
详  
细  
内  
容  
添  
加  
作  
者  
微  
信  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHYgfyicoHWcBVxH85UOBNaPMJPjIWnCTP3EjrhOXhJsryIkR34mCwqetPF7aRmbhnxBbiaicS0rwu6w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
-    
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHYgfyicoHWcBVxH85UOBNaPZeRlpCaIfwnM0IM4vnVugkAyDFJlhe1Rkalbz0a282U9iaVU12iaEiahw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
