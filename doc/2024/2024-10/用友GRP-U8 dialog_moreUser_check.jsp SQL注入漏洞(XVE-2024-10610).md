#  用友GRP-U8 dialog_moreUser_check.jsp SQL注入漏洞(XVE-2024-10610)   
Superhero  Nday Poc   2024-10-14 20:24  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkYN4sZibCVo6EFo0N9b7Kib4I4N6j6Y10tynLOdgov9ibUmaNwW5yeoCbQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkhic5lbbPcpxTLtLccZ04WhwDotW7g2b3zBgZeS5uvFH4dxf0tj0Rutw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCk524CiapZejYicic1Hf8LPt8qR893A3IP38J3NMmskDZjyqNkShewpibEfA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
内容仅用于学习交流自查使用，由于传播、利用本公众号所提供的  
POC信息及  
POC对应脚本  
而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号nday poc及作者不为此承担任何责任，一旦造成后果请自行承担！如文章有侵权烦请及时告知，我们会立即删除文章并致歉。谢谢！  
  
  
**00******  
  
**产品简介**  
  
  
用友GRP-U8R10行政事业内控管理软件是用友公司专注于国家电子政务事业，基于云计算技术所推出的新一代产品，是我国行政事业财务领域最专业的政府财务管理软件。  
  
  
**01******  
  
**漏洞概述**  
  
  
用友GRP-U8R10行政事业内控管理软件 dialog_moreUser_check.jsp 接口处存在SQL注入漏洞，未授权的攻击者可利用此漏洞获取数据库权限，深入利用可获取服务器权限。  
  
  
**02******  
  
**搜索引擎**  
  
  
FOFA:   
```
app="用友-GRP-U8"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwL9pt6ibfmVHo3OUqMRDQqL2qPQHu54h737LRjANibzYau37Dvv0Q3ficibARgSpQBf4bCyaTzkCwUaOA/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
**03******  
  
**漏洞复现**  
  
延时5秒  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLRhGCpZX73tuBVZGqk5s1VdooheK54Pm7BiabbA7P2PeaG4Adw5kHIOLRPIIEeiclGOSxlaRd0cLQQ/640?wx_fmt=png&from=appmsg "")  
  
sqlmap验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLRhGCpZX73tuBVZGqk5s1Vic4Z07hdjibbWT1Nn7bmTNgD5aMiafwGIicxyY4CBQMONa5tHurcA4S15g/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**检测工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLRhGCpZX73tuBVZGqk5s1Vib1h7M02RYOSVrk6TJUWp4O6FT2OibbSicPzQ2CTweO2TGxyUHc1QQePQ/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLRhGCpZX73tuBVZGqk5s1VZPvgfficZnibN6PAfBtFNgc2On7wzp9oMMp7aTQanm9NbHjH0NJ8fKAA/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLRhGCpZX73tuBVZGqk5s1Via0YicmXWZohFzNxv7xKKtyE8sqEibWno5sDibGhNIH2xXw9W1dXRZeqtg/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、官方已发布漏洞补丁，请及时更新修复补丁。  
  
补丁名称：20230316-关于用友GRP-U8存在sql注入漏洞的解决方案.rar  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。   
  
2、三款工具都支持内置poc+自写poc目录一起扫描。   
  
3、保证每周更新10-15个poc。   
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
