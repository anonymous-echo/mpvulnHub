#  漏洞扫描工具 -- GoT（7月5日更新）   
AgentVirus  Web安全工具库   2024-07-04 22:34  
  
===================================  
  
免责声明请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。个人微信：ivu123ivu  
  
0x01 工具介绍  
基于sqlite数据对网站指纹和POC进行管理使用，此工具的开发目的就是存储各个框架的识别指纹，和降低批量漏扫poc脚本编写和管理难度。  
POC数据库支持类似于nuclei poc脚本部分功能（base64解密，正则表达式匹配，提取json字段），以后根据需要会更新更多功能。  
  
0x02 安装与使用  
  
一、资产信息识别(Sniff)  
```
GoT.exe sniff -u http://127.0.0.1
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibtsZ2TxWnGO1dCPAX4iccjrSuHAicuSaOwmKc10KJgu71wR2thQ0la4KW6XoEewyFHHuvNOIkUhqqEQ/640?wx_fmt=png&from=appmsg "")  
  
二、开启代理并检测代理位置  
```
GoT.exe sniff -u http://127.0.0.1 -proxy socks5://127.0.0.1:7890 -pr
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibtsZ2TxWnGO1dCPAX4iccjrSHoibic3PSxSGKboOWXEuMa11ZOsyFJUs2ocCySpMvbKB2gMF8DeUjviaw/640?wx_fmt=png&from=appmsg "")  
  
三、资产识别＋漏洞扫描  
```
GoT.exe sniff -u http://127.0.0.1.com:8888 -at
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibtsZ2TxWnGO1dCPAX4iccjrSAH3jOPG1U7LcAPVeKQDaOd6fkFy4CEMSC7Q168offVjTFCaYH4kHjw/640?wx_fmt=png&from=appmsg "")  
  
四、  
POC+漏扫模块(Attempt)  
  
GoT.exe attempt -u http://127.0.0.1:8090 -condition vuln="用友U9-0702-敏感信息泄露-TransWebService"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibtsZ2TxWnGO1dCPAX4iccjrSUM5mTBiaXlRQbNzqpaKsY18QgkCPgHtSwVVSf4l3lTpwplPXicWDTlqw/640?wx_fmt=png&from=appmsg "")  
  
  
五、与FOFA联动(fofa)  
  
在command.txt中编写fofa命令，在setting.json中填入key和邮箱  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibtsZ2TxWnGO1dCPAX4iccjrS0Iibia76QNzBrQzJLVmiaGpZonhMLEt5OMd2esbnF2FfFicJpOJ8CEicuwA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 项目链接下载**  
  
1、点击阅读原文，从原项目地址下载。  
  
2、网盘下载链接：https://pan.quark.cn/s/3a688c27e6a0  
  
  
  
**·****今 日 推 荐**  
**·**  
  
  
目前正在做  
老旧照片转视频的项目  
  
有兴趣的欢迎私聊微信：ivu123ivu  
  
仅需9.9元  
  
  
  
