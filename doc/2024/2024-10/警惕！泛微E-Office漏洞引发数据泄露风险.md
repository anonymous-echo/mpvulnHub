#  警惕！泛微E-Office漏洞引发数据泄露风险   
 长风实验室   2024-10-23 21:17  
  
在数字化时代，企业信息安全已成为企业运营的重中之重。然而，近期泛微E-Office系统被发现存在信息泄露漏洞，这一事件再次为我们敲响了警钟。今天，我们就来深入探讨这一漏洞的细节、案例分析以及如何采取有效措施来防范此类风险。  
  
**案例分析**  
  
**告警数据来源**  
  
某项目在2024年10月22日的日常监控发现外网39.xx.xx.142针对内网主机172.xx.xx.xx进行泛微E-Office信息泄露漏洞利用等攻击。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqwWIMXYOrskrqNuccKw5C3VxiauUux6NB4ZfqkdcxaDR0D3l8d1EyROdFI6B4vlbcw119Q6RFXwxAg/640?wx_fmt=png&from=appmsg "")  
  
对于此次攻击，我们运维人员第一时间对告警的详情进行分析，下面为告警详情解码分析：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqwWIMXYOrskrqNuccKw5C3Vic8EAEp16zselygLLTdMvS9tibd146ibYZmnejk4BYNQoDXVXy8iaCM9VA/640?wx_fmt=png&from=appmsg "")  
  
  
请求行：GET/building/backmgr/urlpage/mobileurl/configfile/jx2_config.ini HTTP/1.1  
  
请求头：Host:gateway.ylbz.henan.gov.cn:8000  
  
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.137 Safari/4E423F  
  
Accept-Encoding: gzip  
  
Connection: close  
  
请求体：无  
  
详细分析：  
- 请求方法为GET，表示客户端希望从服务器获取资源。  
  
- 请求的资源路径为/building/backmgr/urlpage/mobileurl/configfile/jx2_config.ini，这是服务器上的一个配置文件。  
  
- HTTP版本为1.1，表示客户端和服务器将遵循HTTP 1.1协议进行通信。  
  
- Host头指定了服务器的域名和端口，这里是gateway.ylbz.henan.gov.cn的8000端口。  
  
- User-Agent头包含了客户端的浏览器信息，表明这是一个使用Linux x86_64架构的系统，浏览器为Chrome 34.0.1847.137，基于WebKit内核。  
  
- Accept-Encoding头表示客户端接受gzip编码的响应内容。  
  
- Connection头设置为close，表示客户端希望在响应后关闭连接。  
  
请求体为空，说明这是一个简单的GET请求，没有包含额外的数据发送给服务器，可能是一次试探。  
  
紧接着对攻击地址在微步上进行查看，发现该IP为恶意IP，已对该IP进行上报并封禁。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqwWIMXYOrskrqNuccKw5C3Vsajbia8n3FJogsTQKsL5A30fa7Wdcz18DCGhYwDqHHKYL9ibIwXFonaw/640?wx_fmt=png&from=appmsg "")  
  
针对该服务器的运维人员进行询问，发现该服务存在E-Office 9.1版本，这无疑增加了服务器被进一步攻击的风险。已联系服务器运维人员对E-Office进行升级。以防范潜在的安全隐患。  
  
**漏洞简介**  
  
泛微E-Office是一款广泛应用于企业办公自动化管理的软件，其功能强大，用户众多。泛微E-Office信息泄露漏洞主要存在于系统的数据处理模块中，攻击者可利用泛微E-Office信息泄露漏洞绕过认证机制，获取未经授权的数据访问权限。  
  
**影响版本**  
  
**Office 9.0**  
  
**E-Office 9.1**  
  
**E-Office 10.0**  
  
**解决办法**  
  
1、  
升级到最新版本的泛微E-Office系统，以确保所有已知的安全漏洞都得到修补。  
  
2、对系统进行定期的安全审计和漏洞扫描，及时发现并修复潜在的安全问题。  
  
最后提醒我们，信息安全无小事。泛微E-Office的信息泄露漏洞提醒我们，企业必须时刻保持警惕，加强安全防护措施，以确保企业数据的安全。  
  
  
