#  被动扫描的fastjson漏洞探测插件 -- FastjsonScan4Burp（2月28日更新）   
Niiiiko  网络安全者   2025-03-01 16:00  
  
===================================  
免责声明请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。个人微信：ivu123ivu  
0x01 工具介绍  
FastjsonScan4Burp 一款基于burp被动扫描的fastjson漏洞探测插件，可针对数据包中的存在json的参数或请求体进行payload测试。旨在帮助安全人员更加便捷的发现、探测、深入利用fastjson漏洞，目前以实现fastjson探测、版本探测、依赖探测以及出网及不出网利用和简易的bypass waf功能。  
0x02 安装与使用  
初次加载会在当前目录下创建resources/config.yml文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccxns2W3WXNcNYAwyKoEJZibc0QVxY1dbUZogp5Ow3D0qQ3Mt87LzfRhKBWG4U7mXgqbEESEXIglpWA/640?wx_fmt=png&from=appmsg "")  
  
基本设置如下，默认情况下不开启bypass waf模块，可根据实际勾选  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccxns2W3WXNcNYAwyKoEJZibcIbmicia8azCZe8pIkt7ZfxwRnNjpPWicOKRjLc6ueSYYPFwzSkF0ueEYw/640?wx_fmt=png&from=appmsg "")  
  
基于被动扫描  
  
插件会被动式地对数据包进行扫描，只需要启动插件后正常浏览数据包即可。插件扫描队列界面会对扫描结果进行展示。  
  
extensionMethod：调用的扫描模块名称  
  
issue：扫描结果  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccxns2W3WXNcNYAwyKoEJZibctxRtljUJic6mt8ibz35BjaILsTfm7nBBnAIxEx4uHDoHZXklYTLAAv4g/640?wx_fmt=png&from=appmsg "")  
  
右键主动扫描  
  
部分情况下想对单一某个数据包进行漏洞验证或其他原因，可以在repeater右键选择对应插件选择扫描或探测  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccxns2W3WXNcNYAwyKoEJZibc9zXYZvlXY3wDriak92nR0ABf6MRLyKFqV4JVT5icwZ3hT6jEtQuKl3VQ/640?wx_fmt=png&from=appmsg "")  
  
或者使用doPassive再次进行被动扫描  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccxns2W3WXNcNYAwyKoEJZibceOz4NdHpUJDuSbcd3wfWxtHZtblwWO3iaOLjNTW5WjeEAI6iarDHe0Ww/640?wx_fmt=png&from=appmsg "")  
  
  
  
**·****今 日 推 荐**  
**·**  
  
  
本套课程在线学习（网盘地址，保存即可免费观看）地址：  
  
  
Web安全课堂 -- XSS攻击与防御  
  
链接：https://pan.quark.cn/s/3d763b0cac7e  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccxns2W3WXNcNYAwyKoEJZibcOFVB8C6BvrH032Dj7Yhe5aKYmYibUjXDUYSoHCb5aXx3ehicUuvZKF0A/640?wx_fmt=png&from=appmsg "")  
  
该内容转载自网络，仅供学习交流，勿作他用，如有侵权请联系删除。  
  
  
  
  
个人微信：ivu123ivu  
  
  
**各 类 学 习 教 程 下 载 合 集**  
  
  
  
  
  
  
  
  
  
https://pan.quark.cn/s/8c91ccb5a474  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibuuhdO7GMx4wqK5PQMWgr8pNaudBlYJUYXP6R6LcL0d3UYmPLoiajIXwaibhvlchGibgiaBGwMSwuq58g/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
  
  
  
  
