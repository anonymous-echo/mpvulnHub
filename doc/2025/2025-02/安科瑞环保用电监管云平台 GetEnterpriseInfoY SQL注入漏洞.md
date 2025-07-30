#  安科瑞环保用电监管云平台 GetEnterpriseInfoY SQL注入漏洞   
Superhero  nday POC   2025-02-07 02:58  
  
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
  
  
AcrelCloud-3000环保用电监管云平台  
依托创新的物联网电力传感技术，实时采集企业总用电、生产设备及环保治理设备用电数据，通过关联分析、超限分析、停电分析、停限产分析，结合及时发现环保治理设备未开启、异常  
关闭及减速、空转、降频等异常情况，同时通过数据分析还可以实时监控限产和停产整治企业运行状态，用户可以利用PC、手机、平板电脑等多种终端实现对平台的访问。  
**01******  
  
**漏洞概述**  
  
  
安科瑞环保用电监管云平台 GetEnterpriseInfoY 接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
body="myCss/phone.css"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLVy5iavYzqKicd9yBDCOpfKUroSUuxhqFu4xP16ibEoa6q6rmLs6ib3ricLB20VS88Cic4feV7HaB0CyZg/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
  
查询当前用户  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLVy5iavYzqKicd9yBDCOpfKUaK9qvMnicvgpUfMxhQ2CXKZVk6mic85hUCsqKkm1KJUyG8tRKAFAGGng/640?wx_fmt=png&from=appmsg "")  
  
sqlmap验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLVy5iavYzqKicd9yBDCOpfKUBAf7p27ibafbQO6UTiaY9ZFop7OnskaYKicRJj6KRxriav5Ffg72J3iaTHg/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**自查工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLVy5iavYzqKicd9yBDCOpfKUpriaEj2nHBYjgmfve8Hibl0dcc2bibLW1MGPmezmW2GVFE93FCicjBibGzQ/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLVy5iavYzqKicd9yBDCOpfKUzcgLXY6rZGqjFHGdhYe4jAdvHpUmQgL2jmdcKm7dC6fM8v4Gw1bxqg/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLVy5iavYzqKicd9yBDCOpfKUP4ZlqqW9lYFlXyqxaa74VbPBsMQ69SKDIEpAPqFPFBBjgIUfGOqpgA/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、升级至安全版本  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。  
  
2、三款工具都支持内置poc+自写poc目录一起扫描。  
  
3、保持每周更新10个左右POC。  
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
