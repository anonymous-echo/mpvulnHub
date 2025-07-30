#  泛微E-Mobile /client.do 命令执行漏洞复现   
Superhero  Nday Poc   2024-10-19 17:43  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkYN4sZibCVo6EFo0N9b7Kib4I4N6j6Y10tynLOdgov9ibUmaNwW5yeoCbQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkhic5lbbPcpxTLtLccZ04WhwDotW7g2b3zBgZeS5uvFH4dxf0tj0Rutw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCk524CiapZejYicic1Hf8LPt8qR893A3IP38J3NMmskDZjyqNkShewpibEfA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
内容仅用于学习交流自查使用，由于传播、利用本公众号所提供的  
POC信息及  
POC对应脚本  
而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号nday poc及作者不为此承担任何责任，一旦造成后果请自行承担！如文章有侵权烦请及时告知，我们会立即删除文章并致歉。谢谢！  
  
  
**00******  
  
**产品简介**  
  
  
泛微e-Mobile移动管理平台是一款由泛微软件开发的企业移动办公解决方案。它提供了一系列功能和工具，使企业员工能够通过移动设备随时随地进行办公和协作。  
  
  
**01******  
  
**漏洞概述**  
  
  
泛微E-Mobile存在命令执行漏洞，攻击者可以通过/client.do执行任意命令执行，从而获得服务器权限。  
  
  
**02******  
  
**搜索引擎**  
  
  
FOFA:   
```
"Weaver E-Mobile"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLbofJRlzN6Hv9qQ2FicciazjdMa4icw9vJq9h24mfp3qAYrQfD1ZULtDpGBWDnxh3TqmGMgNcibd824g/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLbofJRlzN6Hv9qQ2FicciazjoHtsFZViciaOI9P7lVib1ckHmVPicg8JdlhNHf3oUZR6hvBYbdMLia8HIsw/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**检测工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLbofJRlzN6Hv9qQ2FicciazjcmXVzmic399A65uOSg808ThpbI2TPPLTu4vMQzSQKwXj5P8mR3nMRBg/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLbofJRlzN6Hv9qQ2FicciazjvqhqJmuiaIX8ia1fNV17YHrHzibNpGHv7Vy2UICJGuDJQmMXdL7WJ6fOw/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLbofJRlzN6Hv9qQ2FicciazjwLfib4ibCHvv6kgdpgLUrUmEgJLur1EcfepMbSnzTvYj2OlbfSWRIe3Q/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、升级至安全版本  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。   
  
2、三款工具都支持内置poc+自写poc目录一起扫描。   
  
3、保证每周更新10-15个poc。   
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
