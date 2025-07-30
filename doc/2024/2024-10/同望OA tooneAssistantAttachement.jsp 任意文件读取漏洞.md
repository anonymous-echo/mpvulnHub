#  同望OA tooneAssistantAttachement.jsp 任意文件读取漏洞   
Superhero  Nday Poc   2024-10-11 20:04  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkYN4sZibCVo6EFo0N9b7Kib4I4N6j6Y10tynLOdgov9ibUmaNwW5yeoCbQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkhic5lbbPcpxTLtLccZ04WhwDotW7g2b3zBgZeS5uvFH4dxf0tj0Rutw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCk524CiapZejYicic1Hf8LPt8qR893A3IP38J3NMmskDZjyqNkShewpibEfA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
内容仅用于学习交流自查使用，由于传播、利用本公众号所提供的  
POC信息及  
POC对应脚本  
而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号nday poc及作者不为此承担任何责任，一旦造成后果请自行承担！如文章有侵权烦请及时告知，我们会立即删除文章并致歉。谢谢！  
  
  
**00******  
  
**产品简介**  
  
  
同望OA  
，即同望科技打造的智企云协同管理系统，是一款高效的企业协同移动办公系统。秉承“互联网++企业管理”理念，定位于以移动互联办公为基础的企业协同管理软件平台。它旨在通过内置常用标准模块与专项管理模块应用，安全快速地打通管理与业务通道，实现管理柔性和刚性的完美结合，助力企业实现协同价值最大化。  
  
  
**01******  
  
**漏洞概述**  
  
  
同望OA tooneAssistantAttachement.jsp 接口存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。  
  
  
**02******  
  
**搜索引擎**  
  
  
FOFA:   
```
body="loginAction.struts?actionType=blockLogin"
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJ6rjooBS7qcKpLJeFDoP8olepmxU5ZezW5zNuoXd8FAE1RAFiaZ9klFUlGx9t9wqGbt1SG1vM8p6Q/640?wx_fmt=png&from=appmsg "")  
  
  
  
**03******  
  
**漏洞复现**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJ6rjooBS7qcKpLJeFDoP8o0IKyZNKiakZYQrgB4ph3u0DqztlEp9XwJ0uzic3oOwNzMWujgHrwDia5g/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**检测工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJ6rjooBS7qcKpLJeFDoP8o09kONicUltWCkcZjambR6iaZAHCyBnC639PR69PWratRQNDjW1yZD6mg/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJ6rjooBS7qcKpLJeFDoP8oVwhexQmWhrNIFicxReTMGAiafbOKMhGIelZJpzl5SdAO86Gib2WNPKzUA/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJ6rjooBS7qcKpLJeFDoP8oTlCqGh6xw9zCfp7VnXpaCJsWPkpibFKwFDia6rJdicJBEYrIksQttGLDg/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
  
  
