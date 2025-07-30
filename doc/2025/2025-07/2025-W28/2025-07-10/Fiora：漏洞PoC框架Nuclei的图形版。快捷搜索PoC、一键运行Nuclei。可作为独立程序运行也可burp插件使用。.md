> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAxMjE3ODU3MQ==&mid=2650611380&idx=4&sn=367b40753605207c6f6e06e82fd93034

#  Fiora：漏洞PoC框架Nuclei的图形版。快捷搜索PoC、一键运行Nuclei。可作为独立程序运行也可burp插件使用。  
 黑白之道   2025-07-10 01:59  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
## 工具介绍  
  
Fiora是LoL中的无双剑姬的名字，她善于发现对手防守弱点，实现精准打击。该项目为PoC框架nuclei提供图形界面，实现快速搜索、一键运行等功能，提升nuclei的使用体验。  
## 安装运行  
### 一、作为burp插件运行  
  
1、访问https://github.com/bit4woo/Fiora/releases  
  
2、下载最新jar包  
  
3、如下方法安装插件  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2UoMfH0BInAJyGYB6oXJvzPo5KichxEDZlycTR7wQXY9o3GIo6icFeicLjicG2nmSo07sABEXlAEialfFw/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
### 二、作为独立程序运行  
  
该程序即可作为burp插件运行，也可以作为独立程序运行。命令行下通过java启动程序的命令：  

```
java -jar Fiora-202100220-jar-with-dependencies.jar      

```

  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2UoMfH0BInAJyGYB6oXJvzPam8Y7XqV3034Kl1YyUpianAicJz8GtGrrxyqb0c38SAvV3eRpX5PQRjQ/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
## 使用方法  
  
以grafana的PoC为例。  
### 搜索PoC  
  
程序会自动扫描nuclei-templates目录下的所有PoC文件，并加载进程序中，可以通过关键词搜索来找到想要的PoC。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2UoMfH0BInAJyGYB6oXJvzPdpLmMz53Leaib6CyD6mESicDj1IyFItjBrrEnjgTKeaoxBOykDFYBApg/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
### 生成PoC命令  
  
选中想要的PoC，右键选择“generate Command Of This PoC”即可。命令会写入剪切板，直接粘贴运行即可。优点是可以对命令行进行再次编辑，但是需要自行粘贴后运行。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2UoMfH0BInAJyGYB6oXJvzP42YicyBHhKcIIDNlia54kZAFx2G9rlAPgeKpTibMBHick9oEM6HRGDSjhA/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  

```
#生产的单个PoC 
nuclei -t C:\Users\P52\nuclei-templates\vulnerabilities\grafana\grafana-file-read.yaml -u http://example.com -proxy http://127.0.0.1

#生产workflow PoC
nuclei -w C:\Users\P52\nuclei-templates\workflows\grafana-workflow.yaml -u http://example.com -proxy http://127.0.0.1


nuclei -tags grafana -u http://example.com -proxy http://127.0.0.1

```

### 直接执行PoC  
  
和生成PoC命令类似，但是它会直接执行生成的命令，不需要粘贴。优点是更便捷，但是无法编辑命令行。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2UoMfH0BInAJyGYB6oXJvzP42YicyBHhKcIIDNlia54kZAFx2G9rlAPgeKpTibMBHick9oEM6HRGDSjhA/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
## 工具获取  
  
  
  
https://github.com/bit4woo/Fiora  
  
  
> **文章来源：夜组安全**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
