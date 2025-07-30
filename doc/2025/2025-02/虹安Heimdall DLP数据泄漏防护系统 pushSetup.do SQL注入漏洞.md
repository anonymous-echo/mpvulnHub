#  虹安Heimdall DLP数据泄漏防护系统 pushSetup.do SQL注入漏洞   
Superhero  nday POC   2025-02-11 03:31  
  
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
  
  
虹安Heimdall DLP  
数据泄漏防护系统，采用开放式体系结构，与现有IT基础设施结合，是集成化的单一管理平台系统。基于角色的权限确保每个管理员只有适当的控制权和访问权，保证了平台的安全性，集中控制策略设定、实施和审计，统一配置和管理各项功能模块在客户端的应用，实现了全面安全与灵活高效的完美结合。直击企业数据泄密的各个源头，控制数据存储、数据使用、数据传输等各个泄密节点，采用认证、授权、加密、审计、监控等技术手段，充分考虑用户使用习惯，为企业建立科学、牢固的信息体系，让企业管理者轻松掌控核心机密资源。  
**01******  
  
**漏洞概述**  
  
  
虹安Heimdall DLP数据泄漏防护系统 pushSetup.do 接口存在SQL注入漏洞，未经身份验证的恶意攻击者利用 SQL 注入漏洞获取数据库中的信息（例如管理员后台密码、站点用户个人信息）之外，攻击者甚至可以在高权限下向服务器写入命令，进一步获取服务器系统权限。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
body="userReg/initUserReg.do"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIYdoQSRBo1dIDibsA95FXIuOQ1aACnhFweahsiazHkXQic2c2DHSibLEvwWgmEKV7zEIcH9af83QLcJw/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
  
延时4秒，执行2次  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIYdoQSRBo1dIDibsA95FXIuqKQQmkUPk4Jz7NCW63yGaicXia0VWibdEDFgtBicKptxWdviakkJZcqLiaAQ/640?wx_fmt=png&from=appmsg "")  
  
sqlmap验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIYdoQSRBo1dIDibsA95FXIunYef9f4h50iaQILTn2L6Ftr3m6anjLzI6ewLAtxgq2Yq1xMC25iclTibg/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**自查工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIYdoQSRBo1dIDibsA95FXIuchiaYF0YVLZpFV0Zmuy2xh5JFicxUFBLNcmcfre4SuicCLw7nxclQo3lQ/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIYdoQSRBo1dIDibsA95FXIud0DtH4yAKSXMS6sv0nXJPgkycVQL3pJuQIlQPsZ5zNNibcAXOsn0wOA/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIYdoQSRBo1dIDibsA95FXIu7k5QDC1o0EbewibVgjaDp54liczpYdEaLjibvhKxPy04IRFEqRxWzhnVQ/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
  
  
