#  万户 ezoffice wf_printnum.jsp SQL注入漏洞   
NT-V  NightmareV   2024-02-03 13:26  
  
声明：  
  
请勿使用本文档提供的相关  
操作及工具  
开展任何违法犯罪活动  
。  
本技术类文档与工具仅支持学习安全技术使用，他用造成严重后果，请自行负责！！！  
  
一、  
漏洞名称  
  
万户   
ezoffice wf_printnum.jsp SQL注入漏洞  
  
二、  
产品介绍  
  
ezoffice是万户网络协同办公产品多年来一直将主要精力致力于中高端市场的一款OA协同办公软件产品。  
  
三、  
FOFA搜索语法  
  
"万户 ezoffice"  
  
四、漏洞验证截图  
  
访问漏洞地址，出现如下页面则漏洞存在。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cysMYfusftnuGn9qyhN7YZHzdjlaRuHd4RZXAIAWrklf2TRNjqeNrrvbkgBYArrbCI02mnsRXSjNGiafWz9iclAw/640?wx_fmt=png&from=appmsg "")  
  
Sqlmap验证  
  
跑出数据库验证  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cysMYfusftnuGn9qyhN7YZHzdjlaRuHdnVVpagKbBrb9q4KNvsqcpyZpdcuWgm7JRfF3Ytd4SaDib8BgEBZ6UsA/640?wx_fmt=png&from=appmsg "")  
  
开启  
sql shell验证  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cysMYfusftnuGn9qyhN7YZHzdjlaRuHdcIe7SBA306a4Hr6T3kusVj7MuXicKxk2UM4ibhNFQSWX29U6dprfnsEg/640?wx_fmt=png&from=appmsg "")  
  
漏洞  
POC在下方知识星球内，扫描二维码，即可查看POC内容  
。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cysMYfusftnuGn9qyhN7YZHzdjlaRuHdmIlVpnzTib5KibVyzWZqbSfNrUONkxLNOb7fNZNaKGtcEVyfD9ISvjMA/640?wx_fmt=png&from=appmsg "")  
  
