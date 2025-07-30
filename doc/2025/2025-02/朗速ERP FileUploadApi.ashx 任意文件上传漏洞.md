#  朗速ERP FileUploadApi.ashx 任意文件上传漏洞   
Superhero  nday POC   2025-02-09 08:20  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkYN4sZibCVo6EFo0N9b7Kib4I4N6j6Y10tynLOdgov9ibUmaNwW5yeoCbQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkhic5lbbPcpxTLtLccZ04WhwDotW7g2b3zBgZeS5uvFH4dxf0tj0Rutw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCk524CiapZejYicic1Hf8LPt8qR893A3IP38J3NMmskDZjyqNkShewpibEfA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
内容仅用于学习交流自查使用，由于传播、利用本公众号所提供的  
POC  
信息及  
POC对应脚本  
而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号nday poc及作者不为此承担任何责任，一旦造成后果请自行承担！如文章有侵权烦请及时告知，我们会立即删除文章并致歉。谢谢！  
  
  
**00******  
  
**产品简介**  
  
  
郎速ERP是一款功能强大的企业资源计划（ERP）软件，专为中小企业量身打造，旨在帮助企业优化管理流程、提升运营效率。不仅适用于制造业，还广泛适用于零售、物流、服务等多个行业。例如，在制造业中，通过生产计划、物料需求计划等功能，提升生产效率和降低生产成本；在零售业中，通过库存管理  
、销售管理等功能，提高库存周转率和销售效率；在物流业中，通过运输管理、仓储管理等功能，提升物流运作效率和服务质量；在服务业中，通过客户关系管理、项目管理等功能，提升服务质量和客户满意度。  
**01******  
  
**漏洞概述**  
  
  
朗速ERP FileUploadApi.ashx 接口存在文件上传漏洞，未经身份攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
body="/Resource/Scripts/Yw/Yw_Bootstrap.js"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIEYVK9ue12w20kCp914ib3ibzcwTbgKxDiaFibajtdTibSzo6RJ4as01pgFzZMYOKD59NxnfrjHOh6RGA/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIEYVK9ue12w20kCp914ib3ibiaqgHUUJlWAPaPNibMePZbPHOyH3g6FzLDka19F4g2kmNFAGuL76pGTQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIEYVK9ue12w20kCp914ib3ibAkib7TxtPHuICL1cmS3E3c7g4TBNYDDf2Hfg41AejUEoy4h8p3h1eNw/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**自查工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIEYVK9ue12w20kCp914ib3ibT1yCU1VLPtEVlvB7neNEXcStvxRN5hV3lJth1W2LOox2eBUicILyyfg/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIEYVK9ue12w20kCp914ib3ibqtSibbqtoVDfFDcZZNR7A0uXyTIppsNP9ibxlaOk7zZ4Y9Ylk2aOaqBg/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIEYVK9ue12w20kCp914ib3ibcW0dNWNoUPbolb1DX90lwlVYG2E4giccUKArfw3AdFFWiaFMksyRsasg/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、  
升级至安全版本  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。  
  
2、三款工具都支持内置poc+自写poc目录一起扫描。  
  
3、保持每周更新7-10个左右POC。  
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
