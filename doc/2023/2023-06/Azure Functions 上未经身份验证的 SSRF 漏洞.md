#  Azure Functions 上未经身份验证的 SSRF 漏洞   
枇杷五星加强版  黑伞安全   2023-06-05 18:02  
  
## 关于 Azure 函数  
  
Azure Functions  
是一种按需提供的云服务，可提供运行应用程序（无服务器计算）所需的所有不断更新的基础架构和资源。  
您可以使用 Functions 构建 Web API、响应数据库更改、处理 IoT 流、管理消息队列等。  
## 我们如何发现 SSRF 漏洞  
  
我们首先创建一个新的 Function App –  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGpf0zicniarTaOQSlUCKYorTwEic3JXuZlUMmFX02t6RQapuiaFGibWmhcws3gPLFqEBNj795rdJjNib3GA/640?wx_fmt=png "")  
  
  
应用服务准备就绪后，我们创建了功能代码 –  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGpf0zicniarTaOQSlUCKYorTwia9OAT58pWNBeHSKpcA8Ccd82xPn7tpia4WGQvM6IZiaO3HKaIX5zuZwA/640?wx_fmt=png "")  
  
点击功能后，我们到达了以下页面——  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGpf0zicniarTaOQSlUCKYorTwLLc0r0dvrCVGiakZUv60SibZQffJFAJYRoA9rRovmQ9zy2SQ6A97WiaIg/640?wx_fmt=png "")  
  
首先，我们通过提供示例名称和模板来创建函数代码 –  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGpf0zicniarTaOQSlUCKYorTwHCQnAoIu845dWpw3fo7GkxKJia40v3bKjM0SubiadUhluMIzMXtQ8sgQ/640?wx_fmt=png "")  
  
Function App 准备就绪后，我们选择了Code + Test  
。  
我们现在可以查看发送的各种请求，包括引起我们注意的两个主要请求：  
  
https://functions.azure.com/api/passthrough  
和https://functions.azure.com/api/debug  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGpf0zicniarTaOQSlUCKYorTwZpROxZz6tyjH8IicTiciapwmWHXfrunYOxVTWEibZW5cH8lTsNzuYiaAbuw/640?wx_fmt=png "")  
  
通过查看代码本身，这里提到了——  
  
https://github.com/Azure/azure-functions-ux/blob/688323e27bdb343c1b6926ac2ef1e69335368eae/client-react/src/ApiHelpers/FunctionsService.ts#L76  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGpf0zicniarTaOQSlUCKYorTwIj2IhickuRKK1ZrgEpurSlwyG3NhLOmkibqDks5mnkIBW8KLgZ6MsVvw/640?wx_fmt=png "")  
  
在查看  
/api/passthrough  
  
请求时，我们注意到它实际上是在向我们的唯一函数 ( BlobTrigger1.dat  
 )发送 GET 请求  
–  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGpf0zicniarTaOQSlUCKYorTw5B9g5df5vNemTDWFD2tX3uQbFnFzs5Ca5xVID8PcCfPjzQicNKfwjMg/640?wx_fmt=png "")  
  
在我们能够利用此功能之前，我们注意到为了执行请求，需要发送两个参数——  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGpf0zicniarTaOQSlUCKYorTwUw18iaqG2RvCvR8Bm0jtBT9En4hNRBXwg1UcmfbzZxumPqkFDwicDo8Q/640?wx_fmt=png "")  
  
通过阅读文档，我们得出结论，该函数需要其中一个参数才能通过functions.azure.com  
主机的身份验证。  
  
为了发现漏洞，我们决定从请求中删除这两个标头，以便我们可以发送我们想要的任何请求。  
但在我们这样做之前，我们首先需要检查要求哪个实际服务器执行我们的请求 -  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGpf0zicniarTaOQSlUCKYorTwEl6E9nEbhzQd6Amb9p6CcwqCJHJWppCOjrC2PTUI17PnP1ia1wqRQ8w/640?wx_fmt=png "")  
  
还有我们的 Burp 合作者 –  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGpf0zicniarTaOQSlUCKYorTwpxGbEqn0iaCSkzKPVibP0A6JF3GQJIicPBDkDNevFJ051H6Hv8g6kZdEQ/640?wx_fmt=png "")  
  
我们确定被 SSRF 请求滥用的实际功能是——  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGpf0zicniarTaOQSlUCKYorTwriaaG3FPFAZk4RRUNCqxWgGvRaYPdgBmPNIh2ptRNHnW9V0Eaw2xJ5A/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGpf0zicniarTaOQSlUCKYorTwATBUvtEuLkxFMprqHPjQ7kpjFVgRibK8z9f0cGmsBrKhuuxmFyOnlicA/640?wx_fmt=png "")  
  
我们可以通过向https://www.nba.com  
发送请求来验证这一点  
。  
我得到以下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGpf0zicniarTaOQSlUCKYorTwrVzIkCAhibLiaQRr5kFJIS1UAG7SyCE91CzDTF19Y0cxS2KJTZUL31YA/640?wx_fmt=png "")  
  
在上面的屏幕截图中，我们可以看到我们收到了 NBA 主网站的输出，但在法国——因为我们的函数端点位于法国。  
这意味着函数本身就是执行我们请求的函数。  
  
此外，我得出结论，该函数是一个基于 NodeJS 的函数。  
我们设法通过向以下地址发送请求来发现它 - https://www.infobyip.com/  
以获取有关 IP 地址的更多信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGpf0zicniarTaOQSlUCKYorTwAHsLxrvsZhdicWBM36CkxmKEjAicjqb339QFU84y6NeSRsAmp0VZDcPQ/640?wx_fmt=png "")  
  
我们可以看到 User-Agent 是axios/0.21.4  
，这是一个 Node JS 模块。  
  
我们尝试访问 IMDS 服务，但无法访问它。  
然而，我们能够成功枚举本地端口——  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGpf0zicniarTaOQSlUCKYorTw21pXkjE0icQHSpsq8nVd9yWcyNsNqAxM2I4RsrAVcgkiaN1paSR8YA4A/640?wx_fmt=png "")  
  
从上面的截图中可以看出，我们能够找到一个潜在的开放内部端口——41692。  
  
通过进一步枚举，我们可以看到可以到达内部端点，如下所示 -  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGpf0zicniarTaOQSlUCKYorTwISLVcAudMTAA61zIibXRBiaR1vdicCdG2eRpmyaYLGJAM9xicjs7icciaZkQ/640?wx_fmt=png "")  
  
Azure Functions SSRF 用例教会我们在遇到在幕后发送的有趣端点请求时相信我们的直觉。  
一旦我们决定通过搜索它的开源代码来进一步检查它，我们就能够学习和理解它背后的逻辑并发现一个重要的漏洞。  
  
