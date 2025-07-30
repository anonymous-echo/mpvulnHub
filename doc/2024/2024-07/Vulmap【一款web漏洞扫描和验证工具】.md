#  Vulmap【一款web漏洞扫描和验证工具】   
原创 大象只为你  大象只为你   2024-07-13 20:57  
  
> **★★**  
免责声明★★  
> 文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与学习之用，读者将信息做其他用途，由Ta承担全部法律及连带责任，文章作者不承担任何法律及连带责任。  
  
#### 1、Vulmap官方介绍  
  
Vulmap 是一款 web 漏洞扫描和验证工具, 可对 webapps 进行漏洞扫描, 并且具备漏洞利用功能, 目前支持的 webapps 包括 activemq, flink, shiro, solr, struts2, tomcat, unomi, drupal, elasticsearch, fastjson, jenkins, nexus, weblogic, jboss, spring, thinkphp。  
  
Vulmap 将漏洞扫描与验证（漏洞利用）结合到了一起, 及大程度便于测试人员在发现漏洞后及时进行下一步操作, 工具追求于高效、便捷。  
  
高效：逐步开发中慢慢引入了批量扫描、Fofa、Shodan 批量扫描, 且支持多线程默认开启协程, 以最快的速度扫描大量资产。  
  
便捷：发现漏洞即可利用, 大量资产扫描可多格式输出结果。  
> 项目地址：  
https://github.com/zhzyker/vulmap  
  
#### 2、环境准备  
  
操作系统中必须有 python3, 推荐 python3.8 或者更高版本。  
**以Kali系统为例**  
> 如果没有kali系统虚拟机，可关注公众号：大象只为你，后台回复：【虚拟机】获取。  
  
```
```  
  
如果没安装python3和pip3，可用以下命令进行安装  
```
```  
#### 3、安装说明  
  
安装比较简单，使用  
git clone  
命令下载源码，安装需要的依赖资源。  
  
下载源码：  
```
```  
  
注意在使用pip3命令安装依赖资源时需要先到源码目录创建虚拟环境，否则会报错。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/YlMg2LW4AJvFtv2osMKMePKQswHKsqyCgkia1zFSPcu3lTBMj3fE4oL6DazjSrhicPsf6cpbcHmG8cmxEbHxazCA/640?wx_fmt=jpeg&from=appmsg "")  
  
按提示创建虚拟环境，相关命令如下：  
```
```  
> **说明：虚拟环境，当前窗口关闭后就失效，下次需要使用时，注意切换目录到myenv所在目录去激活**  
  
  
在安装依赖资源前，需要先修改  
requirements.txt  
里面的版本号，否则会报错。我的python版本是3.11.8，要求gevent版本比较高。github上的源码是2021年，里面的gevent版本是20.9。  
```
```  
  
**激活虚拟环境后**  
，一键安装依赖资源  
```
```  
##### 3.1、配置 Fofa Api && Shodan Api && Ceye  
  
需要先到第三方网站注册并登录获取到相关信息，该步骤需要配置，否则在使用过程会报错。  
  
**修改 vulmap.py 中的配置信息：**  
- Fofa info:   
https://fofa.info/userInfo  
  
```
```  
- Shodan key:   
https://account.shodan.io  
  
```
```  
- Ceye info:   
http://ceye.io  
  
```
```  
#### 4、使用说明  
##### 4.1、参数介绍  
  
使用  
python3 vulmap.py [options]  
命令来运行Packer Fuzzer工具，常用参数如下：  
> -h, --help            显示此帮助消息并退出  
> -u URL, --url URL     目标 URL (e.g. -u "  
http://example.com  
")  
  
  
更多详细参数请查看github的参数介绍。  
##### 4.2、示例扫描说明  
  
使用在线靶场   
https://vulfocus.cn/  
 ，搜索weblogic漏洞编号：  
CVE-2020-14882  
 ，启动靶场。  
  
扫描命令是   
python3 vulmap.py -u http://xxx.com  
   
  
扫描结果列出来，识别目标是什么，漏洞编号(如果有的情况)，发现扫描结果与在线靶场预期的编号不太一样。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/YlMg2LW4AJvFtv2osMKMePKQswHKsqyCPQcIcqGPBNJAcs3lHUUcckSfqSkr6bF4fydRS0g7nSFbcCzS9S5KXQ/640?wx_fmt=jpeg&from=appmsg "")  
  
扫描出来后，再根据漏洞编码进行复现或利用。从侧面说明工具仅做参考，结合多个工具使用做判断。  
#### 5、我的公众号  
  
敬请关注我的公众号：大象只为你，持续更新网安相关知识中......  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YlMg2LW4AJvWLHAn2wppibQax8GNaVTdteIeFygxibU9iaLCIaFOagjpibbLDOnlJKQeaN4ygz6zD1xp420x3R4PNg/640?wx_fmt=png&from=appmsg "")  
  
