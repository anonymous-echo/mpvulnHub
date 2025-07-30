#  xss漏洞挖掘插件 -- Jssx（2月6日更新）   
Yn8rt  网络安全者   2025-02-06 16:00  
  
===================================  
免责声明请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。个人微信：ivu123ivu  
0x01 工具介绍  
根据自己提供的xsspayload进行批量测试，默认使用的是<img src=x onerror=alert(1)>分析页面可以利用的参数：有action属性的form表单，a标签herf属性值。  
对<a herf标签和form表单中的参数进行遍历  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccwBQDbySBm6mbAK7qjic6uWV53j0iaeUxmMkJIRzahKURZriaLrgpS2hzdBhibt1WKicicF2x3kAGzfGhEQ/640?wx_fmt=png&from=appmsg "")  
  
0x02 安装与使用  
1、安装插件：将插件文件夹托到浏览器的扩展程序中就ok了(目前只支持chrome内核的浏览器)。  
  
2、使用插件：点击浏览器工具栏中的插件图标，输入自定义payload。  
  
3、查看结果：扫描完成后，插件会在弹出窗口中显示检测结果，标明发现的敏感参数。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccwBQDbySBm6mbAK7qjic6uWV2rdUwfcFTcPV65hpuoB6nsO9ezW2yvpX1gcefibVSV6zV4IbXpcFOLw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
**·****今 日 推 荐**  
**·**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccwYUcSEibv9UYsy4eVib1k9benmib7GQvePmd7fJeWg5XvyfHnibaz4dibuUtI0RxCD8ibwtxhUCupxTaUA/640?wx_fmt=png&from=appmsg "")  
  
  
