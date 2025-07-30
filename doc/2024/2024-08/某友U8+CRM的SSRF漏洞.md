#  某友U8+CRM的SSRF漏洞   
原创 Yang  红细胞安全实验室   2024-08-24 14:03  
  
> ❝  
> 文章来源于粉丝**@Yang**投稿，如需投稿可联系wx：hgd954589464，欢迎各位师傅踊跃投稿！  
  
## 概述  
  
某友-CRM系统，xxxx.php文件，存在有回显SSRF漏洞，任意文件读取，探测内网服务，结合其它协议、服务进行getShell。  
## 攻击流程图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DibMxurmMHzaCLHwr9RLxRaCaiaCqWkD6RVFCwia4ibUJNtX2zWGONCmtd5FZibAsicp3w590abQc0OiawL6Ap2XWicBvA/640?wx_fmt=png&from=appmsg "")  
## 什么是SSRF?  
### 概述  
  
SSRF (Server-Side Request Forgery 服务器请求伪造)，是一种攻击者构造请求，由服务器发起请求的安全漏洞，一般SSRF目标是内网系统。（服务器处于边界设备，可通过服务器向内网服务发送请求）  
```
如：攻击者构造: http://127.0.0.1，服务器去发起这个 http://127.0.0.1 请求。

```  
### 危险函数介绍  
  
php为例  
```
file_get_contents()
curl_exec()
fsockopen()
fileopen()

```  
  
当这些函数接收到的参数可控，且值可以为协议://可控内容 , 存在ssrf漏洞。剩下就是看看怎么利用了，分为有回显和没回显，若没有回显也能根据网站响应时间来利用SSRF漏洞。  
## 代码审计  
  
这次目标是找SSRF漏洞，搜索file_get_contents等危险函数字样，找到一个xxxx.php文件，里面内容如下图所示。  
### 漏洞点  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DibMxurmMHzaCLHwr9RLxRaCaiaCqWkD6RoeUnQOsciaXhSiaQxoVmAyibQ3Dc1Kf2wdM96EW1r7FMNZu0EpH1FCKQQ/640?wx_fmt=png&from=appmsg "")  
  
若$filePath可控，则file_get_contents($filePath) 可以造成任意文件读取、SSRF漏洞。  
  
**备注：路由我就先不做过多的介绍**  
  
接下来分析$filePath参数是怎么获取到的  
  
先确定这个xxxx.php是怎么传参，由源码可以看到，这里边没有常见的$_POST或$_GET接收外界的参数。  
### 传参分析  
  
xxxx.php包含的文件：tglobal.lib，lib/temail.lib  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DibMxurmMHzaCLHwr9RLxRaCaiaCqWkD6RQVDPmeKnSx6yexEOJNRooVvoXG9Va7B6raEsJEbCusbMtP6rK6eo2A/640?wx_fmt=png&from=appmsg "")  
  
接下来从上往下，对包含的文件进行审计。  
#### tglobal.lib  
##### 概述  
  
tglobal.lib实现了该系统中一些常用的方法。  
##### 分析  
  
该文件整体源码分析下来，并没有找到类似处理POST或者GET请求的代码。我们继续跟踪tglobal.lib包含的lib库，看看有什么内容。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DibMxurmMHzaCLHwr9RLxRaCaiaCqWkD6R9xuePAzkIzNibkx3QogNrk8FF4Hw7IJBicdicqDEY18BSQHc57wPJDzHQ/640?wx_fmt=png&from=appmsg "")  
  
tglobal.lib中的文件包含：首先含了tpagecache.lib，笔者进一步审计tpagecache.lib的代码。  
#### tpagecache.lib  
##### 概述  
  
经过分析，tpagecache.lib注册了全局变量，通过extract，将$_POST,$_GET,$_SESSION等全局变量导入到当前符号表中。  
##### 分析  
  
往下翻阅，有段代码用于注册全局变量。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DibMxurmMHzaCLHwr9RLxRaCaiaCqWkD6Rx3vLQNBiaSuOUf9ahVIH7g4yficOTTWmEdEHlQCSfsemTpv27rXHAeoQ/640?wx_fmt=png&from=appmsg "")  
  
分析这行代码  
```
ini_get('register_globals'); //用于获取 全局注册标识，通过register_globals值判断 是否打开全局变量注册功能

```  
  
ini_get('register_globals') 的结果为false，打开注册全局变量功能，进入代码体。  
```
//模拟注册全局变量
if (!ini_get('register_globals')) {
    $superglobals = array($_SERVER, $_ENV,
        $_FILES, $_COOKIE, $_POST, $_GET);
    if (isset($_SESSION)) {
        array_unshift($superglobals, $_SESSION);
    }
    foreach ($superglobals as $superglobal) {
        extract($superglobal, EXTR_SKIP);
    }
}

```  
```
$superglobals = array($_SERVER, $_ENV,$_FILES, $_COOKIE, $_POST, $_GET);

```  
  
将这些全局变量封装成数组，存放到$superglobals  
  
继续往下走，foreach语句，取出superglobals内容传入到extract变量里面来。  
```
    foreach ($superglobals as $superglobal) {
        extract($superglobal, EXTR_SKIP);//EXTR_SKIP解释：当符号表存在相同变量不覆盖
    }

```  
  
**作用**  
  
extract可以将数组元素导入当前符号表。也就是可以将$_POST[]或$_GET[] 数组元素导入到当前符号表中，将元素注册全局变量。  
##### 例子  
  
这几行代码的作用，拿GET请求作为例子  
```
http://127.0.0.1/test.php?a=1&b=2&c=3&d=4

```  
  
若test.php包含了tpagecache.lib文件，可以将GET请求的参数导入到当前的符号表里面来。不需要额外调用$_GET['a']来获取参数。  
```
<? 
 include_once("tpagecache.lib");
 echo a;
 echo b;
 echo c;
 echo d;
?>

```  
  
可以看到输出结果是  
```
1234

```  
### 总结  
  
**该CRM系统,只要源码中tglobal.lib文件,即开启全局函数注册,通过extract($_POST)或extract($_GET) 导入所有post/get请求键值到当前符号表中。传参方式：可以任意参数传递,参数名跟代码中变量名一样即可。**  
## 漏洞测试  
  
这里就不把poc放出来，只看看漏洞验证结果。  
  
**DNSLog**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DibMxurmMHzaCLHwr9RLxRaCaiaCqWkD6RhTvKENCOVhCcgWiacpPTlLr1F5WiagLbwVaia8laiaPsLWRJ7URZABuBHw/640?wx_fmt=png&from=appmsg "")  
  
**任意文件读取**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DibMxurmMHzaCLHwr9RLxRaCaiaCqWkD6RAm3rGKjTSvNDnH9YT5gV65Ggg5jMiaziaSHRME7aqadKibOnP5lh8bMNQ/640?wx_fmt=png&from=appmsg "")  
### 总结  
  
**做代码审计的时候，边打点边审计,效率会高一些。复现打点的时候得谨慎,做好保护措施:代理,预设测试方案,消除痕迹。**  
## 声明  
  
本文所提供的信息仅供学习和研究网络安全技术之用途。读者在使用这些信息时应自行判断其适用性，并对其行为负全责。作者不对任何读者因使用本文中信息而导致的任何直接或间接损失负责。  
  
转载须知：  
  
如需转载本文，请务必保留本文末尾的免责声明，并标明文章出处为红细胞安全实验室，同时提供原文链接。未经许可，请勿对本文进行修改，以保持信息的完整性。  
  
感谢各位师傅们的理解与支持。  
  
本公众号不定期更新一些技术文章，还望各位师傅们点点关注和在看。  
  
  
