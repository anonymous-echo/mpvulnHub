#  nuclei-快速漏洞扫描器【安装&使用详解】   
原创 大象只为你  大象只为你   2024-08-06 22:40  
  
> **★★**  
免责声明★★  
> 文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与学习之用，读者将信息做其他用途，由Ta承担全部法律及连带责任，文章作者不承担任何法律及连带责任。  
  
#### 1、nuclei介绍  
  
Nuclei是一款基于YAML语法模板的开发的定制化快速漏洞扫描器。它使用Go语言开发，具有很强的可配置性、可扩展性和易用性。  
  
提供TCP、DNS、HTTP、FILE等各类协议的扫描，通过强大且灵活的模板，可以使用 Nuclei模拟各种安全检查。  
  
项目目前是持续更新中，安装比较简单，一些流程比较单的漏洞会直接提供payload，是我自己比较喜欢的一个工具。  
  
文档  
默认语言是英文，  
支持多国语言，也有中文。  
> 项目地址：  
https://github.com/projectdiscovery/nuclei  
> Nuclei模板：  
https://github.com/projectdiscovery/nuclei-templates  
  
#### 2、环境准备  
  
基础环境是kali linux ，ip: 192.168.242.4  
> 如果没有kali系统虚拟机，可关注公众号：大象只为你，后台回复：【虚拟机】获取。  
  
  
nuclei的安装使用需要go，go版本要求1.21 或更高版本，所以需要先安装go。  
##### 2.1、安装go  
  
在kali linux系统下安装会比较简单，使用apt-get命令，安装完成就可使用，不需要再设置环境变量等，安装命令如下：  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/YlMg2LW4AJuZUnUz1MTbCUiaDExqKm9hXsfnFbVicOLJG9kI93xnuTQQzTJTKx6Kt4ZBSqGW65xvzlOicj2wwOnIQ/640?wx_fmt=jpeg&from=appmsg "")  
#### 3、安装nuclei  
  
安装nuclei官方有提供3个方式：go install，Brew和Docker。我首次安装按官方给的命令go install安装失败了，我结合之前afrog安装的经验，按以下步骤安装成功了。  
  
第一步：克隆源码到kali机上，第二步：源码编译，就可以使用了。  
  
如果想再简单一点，可以到releases下载windows或macOs编译好的版本。  
  
安装编译命令如下：  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/YlMg2LW4AJuqH5ia0Dwoibry3vuDmoEMWoAtLrUSxU9UvAGk2ZAvfgIWzvwoFM9hptLaGoHT62XwnsL43nDyC7AA/640?wx_fmt=jpeg&from=appmsg "")  
#### 4、使用说明  
  
使用命令可用   
./nuclei -h  
 来查看，这里只列出2个命令：单个目标和多个目标的扫描，结合在线靶场使用。  
  
更多用法请参考官方文档-用法：  
https://github.com/projectdiscovery/nuclei/blob/main/README_CN.md  
  
扫描时，如果没有特别指定，就是使用内置所有的模板进行扫描。  
  
在线靶场：  
https://vulfocus.cn/  
，选择场景：Strust2  
> 注意：在线靶场里面的漏洞编号与nuclei-templates定义是不太一样的，  
测试过程发现的，具体以nuclei扫描出来的编号为准。  
  
##### 4.1、使用命令  
  
**扫描单个目标：**  
```
```  
  
**扫描多个目标：**  
```
```  
  
urls.txt内容格式如下：【一行一个url】  
```
```  
##### 4.2、扫描单个目标示例  
  
在线靶场先筛选框架：Strust2， 选择编号：  
CVE-2020-17530  
，启动靶场。  
  
**执行命令结果如下：**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/YlMg2LW4AJuqH5ia0Dwoibry3vuDmoEMWoeVXrNB94LbMPOCpRRQiblUr76xPLEGedpabWSCliaRYQHBdZZOuKgVnQ/640?wx_fmt=jpeg&from=appmsg "")  
  
以该示例扫描出来的xss-fuzz提供的payload，拿到浏览器去验证可用。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/YlMg2LW4AJuqH5ia0Dwoibry3vuDmoEMWo43D81ib7YuNCccQpT8rvuNEA6orGScJiavXYy52aMN9UA00eW4tReF5A/640?wx_fmt=jpeg&from=appmsg "")  
  
另一个漏洞编号：  
CVE-2021-31805  
就跟在线靶场的编号不一样，以扫描结果的为准。我拿漏洞编号到百度去搜索漏洞复现，找到github提供一个python脚本和复现步骤说明。  
> 漏洞复现地址：  
https://github.com/Axx8/Struts2_S2-062_CVE-2021-31805  
  
  
我跟  
着步骤验证，只截图前面3个，反弹shell步骤比较多就没截图，感兴趣可以自己跟着步骤操作。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/YlMg2LW4AJuqH5ia0Dwoibry3vuDmoEMWoDNFNRfdHxP7do23ibBNJ2xqAjAToyF1ubgInJZUI4tBTLrIFC5u37Kw/640?wx_fmt=jpeg&from=appmsg "")  
##### 4.3、扫描多个目标示例  
  
在线靶场先筛选框架：Strust2， 选择2个不同的场景，启动靶场。  
  
在nuclei执行目录下添加一个文本  
urls.txt  
，把url按上面格式添加。  
  
**执行命令结果如下：**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/YlMg2LW4AJuqH5ia0Dwoibry3vuDmoEMWo1tBPCk5BHVlCBVRdiasoog218rdZicbLvIDjxmyZRHBiajTTUtPqZcLbA/640?wx_fmt=jpeg&from=appmsg "")  
#### 5、学习资料推荐&我的公众号  
  
在b站有【小迪安全】自己公开2022年的录播课程，  
感兴趣的可以去看，当然最新的课程只能去报他的直播课了。  
  
地址是：  
https://www.bilibili.com/video/BV1pQ4y1s7kH/  
  
我有一些学习笔记就是看完他的视频，自己实践操作后整理出来的。  
  
敬请关注我的公众号：大象只为你，持续更新网安相关知识中......  
  
  
  
  
