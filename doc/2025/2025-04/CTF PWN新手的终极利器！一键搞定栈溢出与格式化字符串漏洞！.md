#  CTF PWN新手的终极利器！一键搞定栈溢出与格式化字符串漏洞！   
 黑白之道   2025-04-19 12:42  
  
# 引言  
  
你是否还在为CTF PWN题目中的栈溢出漏洞和格式化字符串漏洞头疼不已？  
  
你是否还在手动计算溢出字符数、苦苦寻找ROP链、反复调试libc版本？  
  
别担心，PwnPasi来了！这款专为CTF PWN新手设计的自动化工具，将彻底改变你的PWN学习之路！  
# pwnpasi  
  
pwnpasi 是一款专为CTF PWN方向入门基础题目开发设计的自动化工具，旨在帮助新手小白快速识别和利用32位和64位程序中的栈溢出漏洞与格式化字符串漏洞。该工具能够自动判断溢出字符数，自动识别格式化字符串漏洞，自动识别程序调用的动态链接库，并生成相应的ROP链以利用漏洞。支持多种利用方式，包括调用system后门函数、写入shellcode、puts函数ROP、write函数ROP以及syscall ROP，格式化字符串利用，可自动识别并绕过PIE防护与canary防护。此外，工具还具备本地和远程利用功能，并集成了LibcSearcher库，用于在没有提供libc地址的情况下自动搜索合适的libc版本  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/pL7Vbzt3soiatbMrHnQAwQicC1PibVE3prrhcdKRRS9ia0gkEMhBmp7dkeiceMNjejTl6Oa6qWs9leuLQWjwVXyJ5qg/640?wx_fmt=png&from=appmsg "")  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/pL7Vbzt3soiatbMrHnQAwQicC1PibVE3prr8g47lOCR6Fcoh3dgf1kibchtSIpdrgwhzr2nFiamAGulck59icfdXZ2MQ/640?wx_fmt=png&from=appmsg "")  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/pL7Vbzt3soiatbMrHnQAwQicC1PibVE3prrrCRwwA6D3nlysCiaZDVzPibTrqOYKzSE9lYhmZ2dibianoRGK2TZ5UmQ9Q/640?wx_fmt=png&from=appmsg "")  
# 项目链接  
```
https://github.com/heimao-box/pwnpasi
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/pL7Vbzt3soiatbMrHnQAwQicC1PibVE3prr82qKb07Ke4u8Ch7RyXib2wkY1hzzNias1LhocNTalrfNUTH05yoaKHeA/640?wx_fmt=png&from=appmsg "")  
  
  
