#  如何找到更多漏洞赏金的子域？深入了解 Recon   
hai dragon  安全狗的自我修养   2025-01-31 03:39  
  
信函： DALL-E  
  
# 子域枚举/发现🛠️  
  
另一方面，这一步可能是最简单但至关重要的。查找子域只是 Bug Bounties 中的一个常见步骤，但找到比其他子域更多的子域才是使我们在竞争中脱颖而出的原因。  
  
**查找更多子域**  
✅的好处**：**  
1. 广泛的攻击面。  
  
1. 一些工具可以帮助您找到内部子域。  
  
1. 您可能会发现配置错误的子域揭示了一些高权限门户或类似的东西。  
  
**提示：**  
在执行侦查时，永远不要依赖单一工具。  
  
**注意：**  
您必须在linux/WSL/WSL2/VPS中安装Go & Python语言，以便您可以运行所有工具而不会受到任何干扰。  
# 实用方法🛠️  
  
创建一个单独的目录命名子域，并将以下命令的所有输出存储在其中。  
## 1. 子查找器  
  
在正常模式下运行 subfinder：  
```
```  
  
对于在文件上运行：  
```
```  
  
在 Recursive 模式下运行：  
```
```  
  
对于在文件上运行：  
```
```  
  
通常，递归模式是为了稍微多地突破限制以查找更多资源，但有时它实际上会给出较少的 no。的子域。所以，我建议同时使用它们。  
  
运行这两个选项后，运行命令对子域进行排序：  
```
```  
## 2. 子列表3r  
  
要运行的命令：  
```
```  
  
**要在 domains.txt 文件上运行的脚本：**  
  
创建 bash 脚本 ：sublist3r_bulk.sh  
```
```  
  
运行脚本：  
```
```  
## 3. Findomain  
  
要运行的命令：  
```
```  
  
**要在 domains.txt 文件上运行的脚本：**  
  
创建 bash 脚本findomain_bulk.sh  
```
```  
  
运行脚本：  
```
```  
## 4. 资产查找器  
  
要运行的命令：  
```
```  
  
**要在 domains.txt 文件上运行的脚本：**  
  
创建 bash 脚本 ：assetfinder_bulk.sh  
```
```  
  
运行脚本：  
```
```  
## 5. BBOT 公司  
  
就个人而言，这是我最喜欢的收集子域的工具，因为它为您提供了集成 API 密钥的选项列表，从而可以找到更多资产。  
  
要运行的命令：  
  
无 API 配置  
```
```  
  
**如何配置 API**  
  
您可以按照 BBOT GitHub 官方仓库使用 BBOT 配置 API。  
  
我使用自己的小脚本使用 API 密钥运行 bbot，因为即使在 bbot.yaml 文件中配置了密钥后，我也遇到了一些问题。  
  
下面是小脚本的样子：  
  
创建 bbot.sh 文件：  
```
```  
  
在文件中复制以下脚本（添加API密钥后，只需在“=”号后添加API密钥）并按**ctrl+o**  
和**ctrl+x**  
  
对于在单个目标 （bbot-single.sh） 上运行：  
```
```  
  
对于在 domains.txt （bbot-multiple.sh） 上运行时：  
```
```  
  
向文件添加权限：  
```
```  
  
运行脚本  
  
配置 API 是一个耗时的过程，但相信我，它会在整个过程中对您有很大帮助。另外，如果您想添加更多的 API 密钥，可以  
在此处  
查找 Module Config 选项表。  
## 6. 囤积  
  
对于 VPS 用户，与本地计算机相比，此工具的运行速度要快得多。但该工具对于侦察来说非常强大。  
  
为了使其噪音更小、速度更快，我更喜欢在被动模式下运行它。  
```
```  
  
**要在 domains.txt 文件上运行的脚本：**  
  
创建 bash 脚本 ：amass_bulk.sh  
```
```  
  
运行脚本：  
```
```  
## 7. Github 子域  
  
该工具需要 Github API 密钥才能更精确地运行，因此我建议您这样做。  
```
```  
  
**要在 domains.txt 文件上运行的脚本：**  
  
创建 bash 脚本 ：github_subdomains_bulk.sh  
```
```  
  
运行脚本：  
```
```  
  
  
  
  
现在您有 7 个包含子域的文件。将它们全部排序到一个文件中：  
```
```  
  
注意：在运行该命令之前，请确保您的 subdomains 目录仅包含上述命令的输出文件。并且仅在对子域进行排序时在子域目录中运行此命令。  
  
  
  
  
我期待着分享我在探索不断发展的网络安全和漏洞赏金世界时所学到的知识。让我们来猎杀一些虫子吧！  
  
感谢您阅读此博客!!  
  
  
  
  
其它相关课程  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQEREkjoibjFst4F2YTlvkRG4zW4Nlt9pZBgFYgFxfVZFxu83EQnESej7ydiblH1UfHqKX3hBfcm76JiaSA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQEREkjoibjFst4F2YTlvkRG4zW0h21TYuO94OrIGsD2aHGrUcUYiasibQS5AYJ4a95Ra3zIFIXQ4e8lkFA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQEREkjoibjFst4F2YTlvkRG4zW6iapnXQ3Wviaiaiap37xFRqNok6BymcTiacnk07OowXYFowAKYfa9zS6gSA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQEREkjoibjFst4F2YTlvkRG4zWiaJkE3jZRR7znMJDXAlibBzibYaGLMlVvsa1xhlQFyv3viaARicSIII7a9A/640?wx_fmt=png&from=appmsg "")  
#   
# 新课  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERF572V3vh5I1E9EjgxRc5ESuAcvkZaX6BbMo5zT4SibibbYX1gqb3HTVawSct6Oiau2kvT0PROsNTiaKQ/640?wx_fmt=png&from=appmsg "")  
#   
# 详细目录  
# mac/ios安全视频  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERFbBn3mydWukVkxb7u4ibpOneTvEKRymYhW9KMlUWP1RnaXLuZibvPMdGmrdWVV3AMJya9dNxszgOeA/640?wx_fmt=png&from=appmsg "")  
# QT开发底层原理与安全逆向视频教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERGLucgfllJsyUEFRxtnUNkLfUhNeUCnH7x8VtPq0Q2zxZBdhjqiaibsx0rIbaYWMuIibmk5QtNPzsOSw/640?wx_fmt=png&from=appmsg "")  
  
linux文件系统存储与文件过滤安全开发视频教程(2024最新)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHSM6Wk8NAEmbHHUS2brkROr9JOj6WZCwGz4gE4MlibULVefmhRw2dvJd8ZeYnDpRIm0AV1TmIsuEQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
linux高级usb安全开发与源码分析视频教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHCd9Qic4AAIQfFFD7Rabvry4pqowTdAw6HyVbkibwH5NjRTU4Mibeo4JbMRD3XplqCRzg4Kiaib3jchSw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**linux程序设计与安全开发**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERGoVibbKav1DpliaTJ9icDrosqXeWyaMRJdCVWEG0VYLDibSMwUP1L5r9XmLibGkEkSZnXjPD6mWgkib9lA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**二进制漏洞**  
  
rust语言全栈开发视频教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERGLucgfllJsyUEFRxtnUNkLHbLZhPYWITVXTiablic0ZlDrc0uJkAvPnEcQHJI5qbtibk4EWqjZgAX8A/640?wx_fmt=png&from=appmsg "")  
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
  
-   
- **windows恶意软件开发与对抗视频教程**  
  
-   
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERFPap5AiahwlmRC2MGPDXSULNssTzKQk8b4K3pttYKPjVL4xPVu1WHTmddAZialrGo8nQB3dJfJvlZQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHYgfyicoHWcBVxH85UOBNaPMJPjIWnCTP3EjrhOXhJsryIkR34mCwqetPF7aRmbhnxBbiaicS0rwu6w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
-    
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHYgfyicoHWcBVxH85UOBNaPZeRlpCaIfwnM0IM4vnVugkAyDFJlhe1Rkalbz0a282U9iaVU12iaEiahw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
