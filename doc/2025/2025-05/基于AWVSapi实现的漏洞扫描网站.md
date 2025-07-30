#  基于AWVSapi实现的漏洞扫描网站   
 黑白之道   2025-05-07 02:06  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
## 工具介绍  
  
VulnScan，基于AWVSapi实现的漏洞扫描网站。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2WcEJkwkw9uR65Gz6uyRibaTOrbBKMpJyaFoJ5tQWzxvZjdCo8WUAiaSudL7ESGVql7zwJhydH0mtCg/640?wx_fmt=png&from=appmsg&wxfrom=13&tp=wxpic "")  
## 功能介绍  
  
**登录注册功能**  
：通过Kaptcha、spring security实现验证码登录，密码加密，用户验证。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2WcEJkwkw9uR65Gz6uyRibaTCiariaocxXlflgn55gDtIM5WOvc5xWDXnQZwrogDPdSXicfo0kBHia3NRg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
**目标扫描功能**  
：添加扫描目标地址，并设置扫描速度、扫描类型、登录设置（用户名密码登录、Cookie登录）等信息。添加扫描后利用WebSocket实时监测扫描状态，并将漏洞分布和扫描进度信息显示在前端页面。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2WcEJkwkw9uR65Gz6uyRibaTYclnDZg7BsCZJJAQUicDKUpPic0GRQlLdnl32bY42DlwjptSjice07L7Q/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
**查看漏洞功能**  
：列表显示扫描出的全部漏洞。可查看单个扫描目标的漏洞或单个扫描目标的单个漏洞严重程度的漏洞信息。点击漏洞名称可查看漏洞详情。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2WcEJkwkw9uR65Gz6uyRibaTRI55qL1AuCmTTx9swDbt8JTHKkIQfice3uXn1w1FgRt8e7lhkicIdRWw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
**扫描报告和漏洞报告导出功能**  
：将扫描结果或漏洞信息导出为html或pdf文件。可选择导出的模板，如CWE 2011、OWASP Top 10 2017、ISO 27001等。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2WcEJkwkw9uR65Gz6uyRibaT2MNrfbV1VeP9cXSbQdsZYVJmHPAwTBtq7vxMHAGsRsmuK5RKptDVeg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
**信息统计功能**  
：对用户的扫描记录和扫描出的漏洞信息进行统计，使用Echarts插件显示图表信息。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2WcEJkwkw9uR65Gz6uyRibaTEoejPcetL8htsibhuzW1V6T02LSM1RslGspFib3MxMkfS7qUU9ZS9ySQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
**AWVS API相关功能**  
：通过RestTemplate向AWVS发送和获取数据，包括目标、扫描、漏洞、报告等相关API。  
  
**WebSocket功能**  
：1.调用异步线程获取扫描状态信息。2.调用异步线程生成报告链接等信息，结束后返回状态信息。3.回复前端的心跳检测信息。  
  
**数据校验功能**  
：对前端的数据进行JSR303数据校验，自定义枚举校验。  
  
## 工具获取  
  
  
  
https://github.com/Kyon-H/VulnScan/tree/new  
  
  
> **文章来源：夜组安全**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
