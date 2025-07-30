#  干货！如何检测发现WPS的未知漏洞   
原创 云沙箱S  微步在线   2023-08-23 11:35  
  
#   
  
  
8月21号下午，微步云沙箱S 检测团队在日常对可疑样本进行分析的过程中，发现了几个“可疑”的WPS文档。其一如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hSibsojzlH9tyF9bME9srXRDSnbOTnSzUmS2T0yDgOpJlQ9WR19IgFlBwJmSgG8uUkMgpPwvd9ZCmQ/640?wx_fmt=png "")  
  
疑点一：  
样本是个WPS文档，但产生了非WPS程序相关的网络行为，大概率存在漏洞利用的行为（在不包含宏等情况的前提下）。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hSibsojzlH9tyF9bME9srXRDV2V92yaCicRU7LSjXEVbDiapvT1bABrHgPj97aHiaa3WnL4pjMOyN9Opw/640?wx_fmt=png "")  
  
进一步分析后，检测团队发现，其在访问两个链接之后会从远程下载两个可执行文件，且下载链接伪装成json结尾，十分异常。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hSibsojzlH9tyF9bME9srXRDOBjMBibh0XxrLxFWz2EicIcmEPnqcftHtceGOwGeCu5iajHTMiac6iaYDsw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hSibsojzlH9tyF9bME9srXRDBZ1YvDB7N4EAGj9mXJmUCqHUVSyh7iaicssV5Qh0AnqSFFdaI95LheXw/640?wx_fmt=png "")  
  
疑点二：  
从文件行为角度看，云沙箱S捕获到该样本在特定目录下创建了两个可执行文件，这个行为对一个文档来说很不寻常。进一步分析发现，创建的文件和从远程下载的伪装成json文件的可执行文件哈希相同，且两个文件利用了白加黑DLL劫持的技术手法，嫌疑十足。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hSibsojzlH9tyF9bME9srXRDnTgRxYIInhGhVZEqvwc4EBtpBfBYJciaZM3jVMnu1waLe5wk3wrhX2A/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hSibsojzlH9tyF9bME9srXRDogm2HqZjP0wicakyibZt7gEFvOhfYHic9bRSL3NAV3A8kkj757kvx1hQg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hSibsojzlH9tyF9bME9srXRDich0ibsbSibmPVILZzdZQ02pqmETJuj7oicSyjYxeHibAt64AMkG8gRzcrA/640?wx_fmt=png "")  
  
再分析恶意DLL，发现其加了UPX壳，包含一个无效的可疑证书。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hSibsojzlH9tyF9bME9srXRDevgCsQqMbW7Fwt0oScs34g7JRKAmD6gtRHwcbgel8j1Y58buSicVKXw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hSibsojzlH9tyF9bME9srXRDpsnqLXM5KeTibIhQGQsdXCcCX8JntjuWTfhjyQsOBKu4ddDDKfRx5nQ/640?wx_fmt=png "")  
  
执行起来后会从阿*云对象存储下载下一阶段的载荷并执行，最终通过C2来控制受害主机。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hSibsojzlH9tyF9bME9srXRDfEfU52ibVCheiaZia1W3zRicdvrBGiaesALtTW9Gxf3ISwMpl0v9IuLQIbA/640?wx_fmt=png "")  
  
经过漏洞团队的验证，我们确认，**这是一次真实的未知漏洞攻击**。验证后，沙箱检测团队快速补充了静态检测规则，检出如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hSibsojzlH9tyF9bME9srXRDNvlGPeF8Yk9jhAbWmVmOEYcxr4z9esIDCUb3uPW63L3omBvulY7r0Q/640?wx_fmt=png "")  
  
目前该漏洞已修复，可在官网获取最新版本。今年，  
**微步云沙箱S特意上线了WPS静态检测和动态分析功能，目前已具备一定的对WPS已知/未知漏洞的检测发现能力**  
。微步沙箱分析平台OneSandbox 也已具备相同的未知漏洞分析能力。  
  
  
**如何使用云沙箱S 分析WPS文档？**  
  
访问  
https://s.threatbook.com  
（或点击文末“  
阅读原文  
”）  
，上传WPS文档，S会自动识别文档格式并选择分析环境，然后等待几分钟即可。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hSibsojzlH9tyF9bME9srXRD9VkblA9dIqMmNqHbEE7wALz7jbuEp0PH2DRECfGKbdoUZdWKuTJHUw/640?wx_fmt=png "")  
  
Tips：  
如果识别有误，也可以手动选择指定格式进行分析。另外，WPS动态分析还属于Beta功能。  
  
  
· END ·  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hRYwmkFFVSsK0fQGJBGqwl6gYoAG5F1cXgRMNjT0PLZibxZyLvJ2PdcOiczbIv7Vl7xQVgzibia4JiafzQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
戳“  
阅读原文  
”，直通微步云沙箱S  
  
↙  
↙  
↙  
  
