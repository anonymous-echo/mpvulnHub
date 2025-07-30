#  资产梳理漏洞检测工具 - SiftScan   
GSDK  GSDK安全团队   2024-01-23 20:07  
  
01 项目地址  
```
https://github.com/ExpLangcn/SiftScan
```  
  
  
02 项目介绍  
  
****  
SiftScan是一个集成资产识别、资产梳理、资产收集、弱点检测、漏洞检测等的工具。它致力于提高红蓝对抗/脆弱性赏金的效率。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Xu1xJEZRrFgHjJhoASPXqSEQ1eibEKE6niangwMvvgH9VvGVfSEtclV9dITR1UII1TI9xWZVmqHJlcdFK0aXJMicw/640?wx_fmt=png&from=appmsg "")  
  
使用参数  
```
[SiftScan] 致力于提高红色和蓝色对抗/漏洞赏金的效率. By: Explang｜Twitter: @ExpLang_Cn

Usage:
  SiftScan [flags]

Flags:
      --ai string       智能扫描，输入目标 Url，目标可以是 IP|域名|子域名|URL，程序会自动识别目标类型构建扫描流程并进行扫描
      --debug           Debug 模式
  -h, --help            help for GoScan
  -m, --mode string     爬行模式，simple/smart/strict，默认smart (default "smart")
      --proxy string    请求的代理，针对访问URL在墙外的情况，默认直连为空
  -t, --target string   执行爬行的单个URL
```  
#### 扫描目标文件  
  
自动过滤目标类型，使用--ai参数指定目标文件。  
```
```  
#### 扫描指定的目标  
  
自动过滤目标类型，并使用“-t”参数来指定目标信息。  
```
```  
#### 指定爬行模式  
```
```  
  
  
注：  
工具仅供安全研究与学习之用，若将工具做其他用途，由使用者承担全部法律及连带责任，作者及发布者不承担任何法律及连带责任。  
  
