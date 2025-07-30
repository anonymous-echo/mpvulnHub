#  一个自动化PWN利用框架，专为CTF比赛和二进制漏洞利用设计，集成了栈溢出、格式化字符串等多种漏洞利用技术   
heimao-box  夜组安全   2025-04-13 12:46  
  
免责声明  
  
由于传播、利用本公众号夜组安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号夜组安全及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
**所有工具安全性自测！！！VX：**  
**baobeiaini_ya**  
  
朋友们现在只对常读和星标的公众号才展示大图推送，建议大家把  
**夜组安全**  
“**设为星标**  
”，  
否则可能就看不到了啦！  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2WrOMH4AFgkSfEFMOvvFuVKmDYdQjwJ9ekMm4jiasmWhBicHJngFY1USGOZfd3Xg4k3iamUOT5DcodvA/640?wx_fmt=png&from=appmsg "")  
  
## 工具介绍  
  
本工具是一个自动化PWN利用框架，专为CTF比赛和二进制漏洞利用设计，集成了栈溢出、格式化字符串等多种漏洞利用技术，支持32位和64位程序的自动化分析利用。（About ctf一键栈溢出、格式化字符串pwn工具/一键pwn利用工具）。  
  
pwnpasi 是一款专为CTF PWN方向入门基础题目开发设计的自动化工具，旨在帮助新手小白快速识别和利用32位和64位程序中的栈溢出漏洞与格式化字符串漏洞。该工具能够自动判断溢出字符数，自动识别格式化字符串漏洞，自动识别程序调用的动态链接库，并生成相应的ROP链以利用漏洞。支持多种利用方式，包括调用system后门函数、写入shellcode、puts函数ROP、write函数ROP以及syscall ROP，格式化字符串利用，可自动识别并绕过PIE防护与canary防护。此外，工具还具备本地和远程利用功能，并集成了LibcSearcher库，用于在没有提供libc地址的情况下自动搜索合适的libc版本  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2UibnTuzmAtAleXxvujKxgibhsQdtk46f0tWP7L9TphM4cia4iculbfpzR5ibgwwIU8udmOgEUJMz4G4GA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2UibnTuzmAtAleXxvujKxgibhzXsVx2tnuBicHMM0HFI9WibrcpFBavn7VNQ3L92ib2A1ce6pfHyBLdP2w/640?wx_fmt=png&from=appmsg "")  
## 安装依赖  
  
确保已安装Python 3.x，安装所需依赖库：  
```
python3 setup.py install
```  
## 运行工具  
  
通过命令行运行工具。示例命令：  
```
python pwnsipa.py -l level3_x64
```  
  
使用ldd工具可查看程序调用的动态链接库  
```
ldd [文件名]
```  
  
指定造成溢出的字符数与动态链接库：  
```
python pwnsipa.py -l level3_x64 -libc /lib/i386-linux-gnu/libc.so.6 -f 112
```  
  
远程连接：  
```
python pwnsipa.py -l level3_x64 -libc /lib/i386-linux-gnu/libc.so.6 -ip 192.168.0.1 -p 33333
```  
  
  
## 工具获取  
  
  
  
点击关注下方名片  
进入公众号  
  
回复关键字【  
250413  
】获取  
下载链接  
  
  
## 往期精彩  
  
  
往期推荐  
  
[Burp Suite XSS漏洞检测插件](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247494026&idx=1&sn=f663b11da0137bd899cfaaaed6e89e07&chksm=c36bad72f41c246427e5db486af24cbfe5bde0ad87e7da3c7ace0cf767cfbf4442a98c70bba5&scene=21#wechat_redirect)  
  
  
[针对Navicat的后渗透利用框架](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247494010&idx=1&sn=ed479d0c39e0a2f80327a1b08b7e066f&chksm=c36bad82f41c249405ea6fe42d80e8cc498f40e1ac8285e0ea7baaba777a7a2cc950b95d2990&scene=21#wechat_redirect)  
  
  
[一款Google信息收集插件，包含域名，map，js等文件提取](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247494009&idx=1&sn=b4390e4e240366d555468a99a1ab8823&chksm=c36bad81f41c24978d47058abf7b2d7091982d4f2d193f18c8ccc0cb7513a4708a200b782206&scene=21#wechat_redirect)  
  
  
[SSRF_Detector是一款基于Burpsuite MontoyaAPI的黑盒SSRF漏洞自动化检测工具](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247494002&idx=1&sn=7915d11f7efcf5a1c49366bd82805588&chksm=c36bad8af41c249c7b41022b877945c5014ca5eb53dd16ce640e2dab2241ecec5605b866b732&scene=21#wechat_redirect)  
  
  
[一款集成多种安全功能的工具箱，旨在帮助用户快速进行网络排查、主机信息收集、日志查询、IP类处理等安全相关操作](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247494001&idx=1&sn=f0314943f0e0d1ebf4a6f1d4faaafd22&chksm=c36bad89f41c249fbe2c82b166b466d31d09670e0870501d24d111e47fae380a6768d6a89368&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAmMqjhMehrtxRQaYnbrvafmXHe0AwWLr2mdZxcg9wia7gVTfBbpfT6kR2xkjzsZ6bTTu5YCbytuoshPcddfsNg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&random=0.8399406679299557&tp=webp "")  
  
  
