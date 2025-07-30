#  深科特LEAN MES系统SMTLoadingMaterial SQL注入漏洞   
Superhero  Nday Poc   2025-03-15 15:06  
  
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
  
  
深科特LEAN是深科特公司推出的一套精益生产管理系统，旨在通过优化生产流程、减少浪费、提升效率，帮助企业实现高效、低成本的生产运营。该系统融合了精益生产理念与先进的信息化技术，涵盖生产计划、物料管理、质量控制等多个模块，助力企业实现数字化转型与智能制造。深科特LEAN适用于制造业企业，尤其适合电子、机械、汽车等行业，帮助企业提升竞争力与可持续发展能力。  
**01******  
  
**漏洞概述**  
  
  
深科特LEAN MES SMTLoadingMaterial 接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
(title="LEAN MES - 用户登录" || body="Content/js/skt.utility.checkmobile.js" || body="../MobileApp/VerifyError.aspx" || body="Content/login/login2/multiplant_top.png")
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLGtg2MnoCzcIF93fnqAWFU8Evgk1vDcpQymez2vJhVY2m9Lqmbf4LYGiawBdro5c3xbWBLbeHtZUw/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLGtg2MnoCzcIF93fnqAWFUpOtsohWb3UiaHIMUibeX3YosUwL4ARpicE6yFLl3ocaoib5letYZnERdbw/640?wx_fmt=png&from=appmsg "")  
  
sqlmap验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLGtg2MnoCzcIF93fnqAWFUErWSibpaK7QqUv4qc4HUL68woEtxGTKCRyVLWgHoJb6VBbgxf6NeRsg/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**自查工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLGtg2MnoCzcIF93fnqAWFUQsgnxMv3bjPfAVr6MerWcFeVuhCjnxHzpXWsqkDLt5GWKpkwxM5TTg/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLGtg2MnoCzcIF93fnqAWFUaticiaClQxJHJPd5kOiaFPLatY5pJVRKWZ1r5B85Q3jt46TlN3jepK5YA/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLGtg2MnoCzcIF93fnqAWFUrmZN4siaU8qLSRNWiaZic7mhUH6Xhx1xFdibdygnw8mmCe1z0WJGhTibvibQ/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、升级至最新版本  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。  
  
2、三款工具都支持内置poc+自写poc目录一起扫描。  
  
3、保持每周更新7-10个左右POC。  
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
