#  某通用系统0day审计过程   
Zjacky  白帽子左一   2024-07-20 12:19  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFbaUgVwdsriauB77CgQS8lyBNAxtx9IMqJQdhuuoITunu8A5Gp7kFjF7BvEXSaLMuDTYhnu7Nicghg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
```
文章来源: https://forum.butian.net/share/2873
```  
# 某通用系统0day审计过程  
# 前言  
  
本篇文章首发在先知社区 作者Zjacky(本人) 先知社区名称: Zjacky 转载原文链接为https://xz.aliyun.com/t/13866  
  
代码审计篇章都是自己跟几个师傅们一起审计的1day或者0day(当然都是小公司较为简单)，禁止未经允许进行转载，发布到博客的用意主要是想跟师傅们能够交流下审计的思路，毕竟审计的思路也是有说法的，或者是相互源码共享也OK，本次审计的目标是一套也是各大高校使用的通用系统，已经提交相关SRC平台进行修复  
# 路由分析  
  
直接看登录接口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGcGu2RBNMCBMlBotrpfKtpia31icnEGmJJSqv5Ea5wiaXleeDEcvn7As0JSlgDwoCsUv8MCCkHCQ50g/640?wx_fmt=png&from=appmsg "")  
  
路由为 /setting.php/index/login  
  
‍  
  
找对应源码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGcGu2RBNMCBMlBotrpfKtpr0tUiaYGCc1d6LK5aDuUcHzmIsSmCJiavN7ogFltGgIAmNxW0R4gnlPQ/640?wx_fmt=png&from=appmsg "")  
  
第一个接口setting对应Application下的文件  
  
第二个接口Index对应Setting下的Controller文件名字  
  
第三个接口为Controller的方法名字  
  
‍  
# 代码审计  
## 上传  
  
Application\Admin\Controller\UploadController.class.php  
  
在这个路径下继承了一个upload控制器父类  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGcGu2RBNMCBMlBotrpfKtp5NvKP1KFP5p00icoAFUMDicQCOatSHUquJBlD1viayicapLibJu7UoP92Og/640?wx_fmt=png&from=appmsg "")  
  
所以调用的接口如下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGcGu2RBNMCBMlBotrpfKtpTeBnIuYwFLBDHibqcB9HMhmyicLdicjyhAUuXMvEFNnoVNBbB3HIROuicw/640?wx_fmt=png&from=appmsg "")  
  
实例化了一个UploadFile()对象然后给他的属性赋值  
  
重点关注以下代码  
```
$upload-&gt;exts = array('jpg', 'gif', 'png', 'jpeg'); // 设置附件上传类型

```  
  
发现这里会调用UploadFile()的魔术方法 跟进  
```
    public function __set($name,$value){
        if(isset($this-&gt;config[$name])) {
            $this-&gt;config[$name]    =   $value;
        }
    }

```  
  
这里其实就是问题的本身，要是传进来的在config里头不存在则返回空，那么我们去看一下config的设置  
```
    private $config =   array(
        'maxSize'           =&gt;  -1,    // 上传文件的最大值
        'supportMulti'      =&gt;  true,    // 是否支持多文件上传
        'allowExts'         =&gt;  array(),    // 允许上传的文件后缀 留空不作后缀检查
        'allowTypes'        =&gt;  array(),    // 允许上传的文件类型 留空不做检查
        'thumb'             =&gt;  false,    // 使用对上传图片进行缩略图处理
        'imageClassPath'    =&gt;  'ORG.Util.Image',    // 图库类包路径
        'thumbMaxWidth'     =&gt;  '',// 缩略图最大宽度
        'thumbMaxHeight'    =&gt;  '',// 缩略图最大高度
        'thumbPrefix'       =&gt;  'thumb_',// 缩略图前缀
        'thumbSuffix'       =&gt;  '',
        'thumbPath'         =&gt;  '',// 缩略图保存路径
        'thumbFile'         =&gt;  '',// 缩略图文件名
        'thumbExt'          =&gt;  '',// 缩略图扩展名    
        'thumbRemoveOrigin' =&gt;  false,// 是否移除原图
        'thumbType'         =&gt;  0, // 缩略图生成方式 1 按设置大小截取 0 按原图等比例缩略
        'zipImages'         =&gt;  false,// 压缩图片文件上传
        'autoSub'           =&gt;  false,// 启用子目录保存文件
        'subType'           =&gt;  'hash',// 子目录创建方式 可以使用hash date custom
        'subDir'            =&gt;  '', // 子目录名称 subType为custom方式后有效
        'dateFormat'        =&gt;  'Ymd',
        'hashLevel'         =&gt;  1, // hash的目录层次
        'savePath'          =&gt;  '',// 上传文件保存路径
        'autoCheck'         =&gt;  true, // 是否自动检查附件
        'uploadReplace'     =&gt;  false,// 存在同名是否覆盖
        'saveRule'          =&gt;  'uniqid',// 上传文件命名规则
        'hashType'          =&gt;  'md5_file',// 上传文件Hash规则函数名
        );

```  
  
emmm根本没有 exts 所以说后缀根本没有检测，可以从从调用的upload中查看  
  
断到一个叫自动检查附件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGcGu2RBNMCBMlBotrpfKtpkjHgVpWnOPYL9XlDcZovPTAJUU5jr509bz0iaqIQ4ImZeFFg8pWCrzg/640?wx_fmt=png&from=appmsg "")  
  
步进一下进入check函数存在检查文件类型  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGcGu2RBNMCBMlBotrpfKtpQFjia2u03fkQiakZ846ZRIoXE2spOqEnS0iaicUuUvicOKJ8OGSbia81NPFg/640?wx_fmt=png&from=appmsg "")  
  
再次跟进一下checkExt发现是一个很强的校验白名单  
```
    private function checkExt($ext) {
        if(!empty($this-&gt;allowExts))
            return in_array(strtolower($ext),$this-&gt;allowExts,true);
        return true;
    }

```  
  
但是重点是他并没有赋值进去  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGcGu2RBNMCBMlBotrpfKtpQaF8E5Zo9WeibldiapczXFiaQegeMfic0nD4ybib8rMgxBXMZQxtTOeeSdg/640?wx_fmt=png&from=appmsg "")  
  
在这进行反向验证，讲前面的属性修改为在config里头的内容  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGcGu2RBNMCBMlBotrpfKtpyG7xSYZZM8FA8e6KwVxmptciad3ibAwj9MEib9pmC3rHgvFSkSqPht9BQ/640?wx_fmt=png&from=appmsg "")  
  
再次进行断点跟到最后面的config的地方发现成功修改  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGcGu2RBNMCBMlBotrpfKtpsCUPlXvYsYQNMthIMzbT8KP2vWuKaT6vTUzHwfWTqiaOzw0cqwiaeS1w/640?wx_fmt=png&from=appmsg "")  
  
所以这套系统只要存在 $upload-&gt;exts = 这个的上传接口 就存在任意文件上传  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGcGu2RBNMCBMlBotrpfKtpcsYj84M0T6e73oORB9UjEhQJ0ZtIRTwIDX66D0hLahQfcKCdeEzGqg/640?wx_fmt=png&from=appmsg "")  
  
‍  
## SQL(绕redis缓存)  
  
直接看前台控制器了  
  
找到这个路由存在sql的问题  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGcGu2RBNMCBMlBotrpfKtpdDtFTm4ibPKxLABENmiaEs7uZF7FeU4nrZMQupJSWB3ITxoOcxoZ7t9A/640?wx_fmt=png&from=appmsg "")  
  
在这个代码里头，可以发现 $count 跟 $listJson 是关键  
  
$count的设置是为了不频繁查询，所以这里只要设置随机伪造的PHPSESSID就可以了  
  
$listJson 的设置就尤为关键了 if (!$listJson) 这里的语句是 我的redis去查phone就是要查不到 为null才能执行下面的sql语句，所以phone就是要不存在的手机号才行，所以就直接随机phone就可以了，但是他在后续的代码中把这跟手机号给设置进了redis中  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGcGu2RBNMCBMlBotrpfKtp4TjRDEEZ2sibu7CqdaTebfOiaTDqxY00EPUiaCNU9RKWqdicUnk60rdRjw/640?wx_fmt=png&from=appmsg "")  
  
所以必须要把这跟phone随机化来绕redis的缓存才能进行正常注入  
  
‍  
## SSRF  
  
这里全局搜索curl_exec( emm感觉是这里 确实是可控的  
  
\Application\Course\Controller\DocumentController.class.php  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGcGu2RBNMCBMlBotrpfKtpBrDEgQFvzWaiaKSeo03Lb08l51QQicCx3SHmRqyN4OsgiaXLe6YbvcEpA/640?wx_fmt=png&from=appmsg "")  
  
‍  
  
从逻辑上来看  
  
$_SERVER['HTTP_AUTHORIZATION'] 跟 $_SERVER['HTTP_X_OSS_PUB_KEY_URL'] 这两个值都得存在 他就不会进行403的跳转 那么这两个都是我们可控的只要在header头加入即可，之后就会将我们传入的base64编码的值进行解码后给到curl进行直接curl执行  
```
Authorization: Basic QWxhZGRpbjpPcGVuU2VzYW1l
X-Oss-Pub-Key-Url: aHR0cDovL2RxM2JlMC5kbnNsb2cuY24=

```  
  
远程测了一下也是完全没问题的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGcGu2RBNMCBMlBotrpfKtpIzzEQOxYBlcvLMXJVEOshGOiaR14zBP3icfroXvEM6h7y74y4ib7XL7Mw/640?wx_fmt=png&from=appmsg "")  
  
加入后返回两百  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGcGu2RBNMCBMlBotrpfKtpia31icnEGmJJSqv5Ea5wiaXleeDEcvn7As0JSlgDwoCsUv8MCCkHCQ50g/640?wx_fmt=png&from=appmsg "")  
  
最终也是测出了SSRF  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGcGu2RBNMCBMlBotrpfKtp5ExLRYeOausgL46exxaZBSKvFaJfQlwq7cZXY4NTQicibOojWYx32xtQ/640?wx_fmt=png&from=appmsg "")  
  
声明：⽂中所涉及的技术、思路和⼯具仅供以安全为⽬的的学习交流使⽤，任何⼈不得将其⽤于⾮法⽤途以及盈利等⽬的，否则后果⾃⾏承担。**所有渗透都需获取授权**  
！  
  
**如果你是一个网络安全爱好者，欢迎加入我的知识星球：zk安全知识星球,我们一起进步一起学习。星球不定期会分享一些前言漏洞，每周安全面试经验、SRC实战纪实等文章分享，微信识别二维码，只需25，即可加入，如不满意，72 小时内可在 App 内无条件自助退款。**  
1. ![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGpTtick8dYImTUOcmaQWHRzkPIp7SwgncysYUIo0cKZAcHvXcMEBL5ZZEJCIpUP08SGOR8bnejDxQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSE3xxjQrLXjiaAWoqibdM1AFZ0uePzzUOG049bSjeEkbft1NfIm833fQ0ibIbW5IoE2ftnWoS3YxRPLg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
****  
