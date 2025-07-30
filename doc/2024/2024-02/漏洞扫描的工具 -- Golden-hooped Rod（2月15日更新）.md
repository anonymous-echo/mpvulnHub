#  漏洞扫描的工具 -- Golden-hooped Rod（2月15日更新）   
spmonkey  Web安全工具库   2024-02-17 15:28  
  
===================================  
免责声明请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。  
0x01 工具介绍  
Golden-hooped Rod是一款对于web站点进行漏洞扫描的工具。工具使用python语言编写，使用的目录扫描字典均由真实环境而来。使用起来异常便捷。可以对web站点进行漏洞扫描、设置代理、设置线程等。  
0x02 安装与使用  
一、常用命令  
```
usage: GHR.py [-h] [-u URL] [--ip IP] [--nodir] [--proxy PROXY] [-t THREAD]

options:
  -h, --help            show this help message and exit

GHR 常用参数:
  -u URL, --url URL     url，例：--url http://127.0.0.1/
  --ip IP               ip，例：--ip 127.0.0.1
  --nodir               禁用目录扫描
  --proxy PROXY         代理设置，例：--proxy 127.0.0.1:10809（目前仅支持HTTP，暂不支持SOCKET）
  -t THREAD, --thread THREAD
                        线程设置，例：--thread 10 默认线程数为：20

```  
  
二、界面展示  
  
运行界面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibvVMiaTkZNLwlZxAeevby9dJjboDQ2uE80UA2HJ7J2CzApUApe3LeV0x2xOpZbDueEGQ1icjsRPIHBg/640?wx_fmt=png&from=appmsg "")  
  
报告显示  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibvVMiaTkZNLwlZxAeevby9dJxncs9ysy1AZ7pRsklREOtZqgRiaVVX8k9bia6unmJakQVePcTfXflgDg/640?wx_fmt=png&from=appmsg "")  
  
**0x03 项目链接下载**  
  
1、通过阅读原文，到项目地址下载  
  
2、  
  
关注下方公众号  
后台  
  
回复：  
**工具666**，获取网盘下载链接  
  
  
  
**·****今 日 推 荐**  
**·**  
> 一个不断更新的资料库，各类学习资料，音影作品，大家需要需要什么资源欢迎私信或者留言，尽快给大家更新：  
  
https://docs.qq.com/sheet/DUHNQdlRUVUp5Vll2?tab=BB08J2  
  
  
  
