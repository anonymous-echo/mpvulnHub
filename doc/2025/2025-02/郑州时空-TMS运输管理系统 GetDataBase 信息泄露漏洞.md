#  郑州时空-TMS运输管理系统 GetDataBase 信息泄露漏洞   
Superhero  nday POC   2025-02-14 01:58  
  
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
  
  
郑州时空-TMS运输管理系统  
是一款专为物流运输企业设计的综合性管理软件，旨在提高运输效率、降低运输成本，并实现供应链的协同运作。系统基于现代计算机技术和物流管理方法，结合了郑州时空公司的专业经验和技术优势，为物流运输企业提供了一套高效、智能的运输管理解决方案。该系统支持多网点、多机构、多功能作业，能够全面满足企业的运输管理需求。适用于各类物流运输企业，包括运输公司、各企业下面的运输队等，特别适用于需要高效管理运输过程、降低运输成本并提升供应链效率的企业。  
**01******  
  
**漏洞概述**  
  
  
郑州时空-TMS运输管理系统 GetDataBase 接口存在信息泄露漏洞，未经身份验证攻击者可通过该漏洞读取系统内部数据库文件，泄露账号密码等重要凭证，导致网站处于极度不安全状态。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
body="/Images/ManLogin/name.png"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLjsDiaru3pXyFDOvb8JX8j90U2RDzQMY4pXR2bUgCZD3njxlictCOCKFWRkXxKHC2L09LfxjgfMwaA/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLjsDiaru3pXyFDOvb8JX8j9T9PXBEHicSb3FBmM7bb7oe6ZicjILIibtny6uLK8bvlFicibaBh9netCArA/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**自查工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLjsDiaru3pXyFDOvb8JX8j9eRx8VlK73UJ6GPEJ1SmLPiaJKCUEhEVmsG6tCqbIxYkwoxXOiajjXH4g/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLjsDiaru3pXyFDOvb8JX8j9hicKNAiahNHUvmr6ibCa4TJrmdM7yA3ribQFicbaVlcTVnexky6aQy9ghLQ/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLjsDiaru3pXyFDOvb8JX8j9PjqvvGkpdz3OupI6YqZIr54UQO4M26zm2Mq8GofdsCPOkksjQVA0jQ/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
  
  
