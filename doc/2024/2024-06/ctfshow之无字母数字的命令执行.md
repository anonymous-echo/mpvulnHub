#  ctfshow之无字母数字的命令执行   
原创 vientiane  TimeAxis Sec   2024-06-25 23:06  
  
### 点击蓝字关注我们  
# 无字母数字的命令执行  
## ctfshow web入门 55  
  
题目：  
```
<?php

/*
# -*- coding: utf-8 -*-
# @Author: Lazzaro
# @Date:   2020-09-05 20:49:30
# @Last Modified by:   h1xa
# @Last Modified time: 2020-09-07 20:03:51
# @email: h1xa@ctfer.com
# @link: https://ctfer.com

*/

// 你们在炫技吗？
if(isset($_GET['c'])){
    $c=$_GET['c'];
    if(!preg_match("/\;|[a-z]|\`|\%|\x09|\x26|\>|\</i", $c)){
        system($c);
    }
}else{
    highlight_file(__FILE__);
} 


```  
  
该题是在黑名单中添加了字母以及常见绕过符号。  
  
解题需要了解一下两个知识点。  
1. shell下可以利用.来执行任意脚本  
  
1. Linux文件名支持用glob通配符代替  
  
题目没有过滤.命令。通过.去执行sh命令不需要有执行权限。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CGN2EctBgwQFTBh2mwLsgCibfqnCzSvR6icFpRHtiapP4Wgskmba0FFr7lSYiavXWKmCRsd15LSQcowSmaaEfUmSLw/640?wx_fmt=png&from=appmsg "")  
  
	对于通配符，大家常用的可能都只有*和?。其实还有 glob，只要找到一个可以表示“大写字母”的glob通配符，就能精准找到我们要执行的文件。  
  
翻开ascii码表，可见大写字母位于@与[之间：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CGN2EctBgwQFTBh2mwLsgCibfqnCzSvR6Ae7WTewN0U1N22ibslHX7WicUxsAevw117aG5ibKzjUPWKXtib3wqdIQrg/640?wx_fmt=png&from=appmsg "")  
  
	换个思路去解这道题，可以通过post一个文件(文件里面的sh命令)，在上传的过程中，通过.(点)去执行执行这个文件。一般来说这个文件在linux下面保存在/tmp/php??????一般后面的6个字符是随机生成的有大小写。（可以通过linux的匹配符去匹配）。  
  
	然后开始构造POC,提供一个html来构造上传post请求包。  
```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>POST数据包</title>
</head>
<body>
<form action="http://46230c96-8291-44b8-a58c-c133ec248231.chall.ctf.show/" method="post" enctype="multipart/form-data">
    <label for="file">文件名：</label>
    <input type="file" name="file" id="file"><br>
    <input type="submit" name="submit" value="上传">
</form>
</body>
</html>

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CGN2EctBgwQFTBh2mwLsgCibfqnCzSvR6YTqhaicXAzrWeCxWDYPVwVbRVHzl3tT00GhWEDtwMrVQG1wXrDHB6IQ/640?wx_fmt=png&from=appmsg "")  
  
	这里再提供一种更方便的方法，用yakit来构造。伟大无需多言。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CGN2EctBgwQFTBh2mwLsgCibfqnCzSvR6zP43gYkUickUE6Od0AabrlpHwhO2505XjTOPwb90su6OqJOd90XtpUw/640?wx_fmt=png&from=appmsg "")  
  
	然后在上传文件内容添加sh命令，使用ls成功读取到文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CGN2EctBgwQFTBh2mwLsgCibfqnCzSvR6vkoEN9fhcOcFiaIjP1Kvamryr1t5eLoYmdlOhxoOZOiaaoAdRzNu9e0g/640?wx_fmt=png&from=appmsg "")  
  
直接读flag，打完收工。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CGN2EctBgwQFTBh2mwLsgCibfqnCzSvR6ib23wZlvG7g2MEAyrwPSmCrWmOktB9LoCAekiahibDvibQKaUkVE65gRPA/640?wx_fmt=png&from=appmsg "")  
  
  
点点关注不迷路~  
  
  
