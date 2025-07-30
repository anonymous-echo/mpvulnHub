#  快排CMS-Socket.php-日志信息泄露漏洞   
原创 骇客安全  骇客安全   2025-02-18 07:43  
  
```
runtime/log/202104/06.log
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IePibcXn991NCztrlE4h6tSfVex97mmxl0LA0hNG6ZollPOotDcdoic2dYB8hl1jrxiaXQHIAT9G9Qo1z3ic1FnDoA/640?wx_fmt=png&from=appmsg "null")  
  
  
其中可以看到泄露了管理员的Cookie信息和其他敏感信息  
  
  
并且文件命名为 **年+月/日期.log**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IePibcXn991NCztrlE4h6tSfVex97mmxluVztpP6wtfMxyYzgMjrJHJkWJZ9ejGgxIhmmNKYiaUU5ashIXzBJZgg/640?wx_fmt=png&from=appmsg "null")  
  
  
这里关注后台的日志文件中的 admin.php页面的cookie就可以获得管理员权限  
  
  
  
