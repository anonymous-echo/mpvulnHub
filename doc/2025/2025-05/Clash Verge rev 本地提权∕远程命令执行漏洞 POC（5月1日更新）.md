#  Clash Verge rev 本地提权/远程命令执行漏洞 POC（5月1日更新）   
 Web安全工具库   2025-05-01 16:00  
  
暗月渗透测试04入门学习8课合集下载  
  
链接：https://pan.quark.cn/s/d26dd0ba8b77  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibuKAHIh5Tyibp23wAtibVqz9wsHHol5yXnUN5uh4SAQSibYRfZbeXxTmxlht9UDLcKfWvCkic80qRXp2w/640?wx_fmt=png&from=appmsg "")  
  
===================================  
免责声明请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。个人微信：ivu123ivu  
0x01 工具介绍  
Clash Verge rev存在一个提权漏洞，在Mac、linux和Windows都能进行提权，Mac和Linux下能提权到root，Windows卜可以提权划SYSTEM.  
0x02 安装与使用  
常用命令：  
```
usage: poc.py [-h] -c COMMAND -p PORT --host HOST [--proxy PROXY_IP]
Clash Verge RCE POC
optional arguments:
  -h, --help            show this help message and exit

  -c COMMAND, --command COMMAND  Executed commands

  -p PORT, --port PORT  Set local listening port

  --host HOST           Set local IP address

  --proxy PROXY_IP      Optional SOCKS5 proxy IP, default port 7897
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibuKAHIh5Tyibp23wAtibVqz9w4ygxe49icyRIaX0kaRAG9djhKD9SuLDYiaqBmLOhw3KcDfYcFSAlndqg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibuKAHIh5Tyibp23wAtibVqz9wQFVDd1f3WyicuHz8e0ticYYAFDOyaAEOX86GkYIRoLZEpQibWX8NoIN7Q/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
**·****今 日 推 荐**  
**·**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibuKAHIh5Tyibp23wAtibVqz9wlR2odbuReiaUPyDpRSIKb1qEnZ2aarUEwNAicoVYo0b6oZNkSMTZfx2g/640?wx_fmt=png&from=appmsg "")  
  
  
  
