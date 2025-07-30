#  dedecms之汗流浃背的审计1day   
江南韵  WIN哥学安全   2024-03-02 15:20  
  
****## 免责声明：  
  
由于传播、利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
  
  
**前言：**  
  
又是我，深情哥大弟子江南韵(  
压星河),最近跟着学了一手更新包审计1day,感觉又更新了技能书。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYv9BolQvdGSFEdl4ib84bMZNecy20sjn2rjbU39HpfHJMTRUtwOAxEr6QqR9AccE24VyaVgov4j04Q/640?wx_fmt=png&from=appmsg "")  
  
**1.官网查找更新包：**  
```
https://www.dedecms.com/download#changelog
```  
  
看了一圈就是这个更新日志了，里面都是更新包，我们直接下载一个最新的更新包  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYv9BolQvdGSFEdl4ib84bMZNoS699PjKtRlswbibzDVSOXQf4e4PmyTlbncZxWk8kbNyb9BVIGhiaviaQ/640?wx_fmt=png&from=appmsg "")  
  
然后直接打开看看，研究了一下应该是类似文件覆盖的更新的  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYv9BolQvdGSFEdl4ib84bMZN9kPfLpTnciaX9vNzkAgd0Q1SDQT7fEMvHe69dUvgT7ucQiaQesrhDIiag/640?wx_fmt=png&from=appmsg "")  
  
那就好办了，他们教我直接看文件大小就行  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYv9BolQvdGSFEdl4ib84bMZNd4JwsdKe5Vqb8v85YMzPnGhYNmB9oBlRvCaRiawUibuLpNHdgliaWMxIg/640?wx_fmt=png&from=appmsg "")  
  
  
  
**2.直接定位更新的代码**  
  
发现多出了这个，这一看不就限制了任意读取或者删除  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYv9BolQvdGSFEdl4ib84bMZN5yUibeTr9VuKCkC3ILgBQlZWibhJ6ibNdOy3wnwasuP3I4FeQic5dZlBlg/640?wx_fmt=png&from=appmsg "")  
  
再往下面看，发现了危险函数unlink,接下来就看delete参数是不是我们可控的就行了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYv9BolQvdGSFEdl4ib84bMZNia254ibkic4VePVemFpLicSz4KZpvVgGKtUt2uJKtsmXIfpdVDENtyLhFg/640?wx_fmt=png&from=appmsg "")  
  
  
**3.审计的基本思路**  
  
听学长说拿到代码最好看一下目录结构，一般网上都会有的，可以更方便的定位到存在漏洞的功能点,然后再网上就找到了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYv9BolQvdGSFEdl4ib84bMZNJEBGngy37bgWle5QC4jgzpZmZmgC2JdfSjvoUxxAicUhomXouYgUAxQ/640?wx_fmt=png&from=appmsg "")  
  
文件再后台/dede/upload.php里面，其实更新日志都写了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYv9BolQvdGSFEdl4ib84bMZNLG4GYsJm1LMGqXoxRDZKSria8ARrjWliauud8PxFia9RM89ofcfuel8Ew/640?wx_fmt=png&from=appmsg "")  
  
接下来就是路由了，听说好像直接get传入参数就可以给$delete赋值了![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/v1.3.10/assets/newemoji/Shocked.png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYv9BolQvdGSFEdl4ib84bMZNr6ZXWmhRBk91jicPjatiaQKic2BgA1bD5iaACKmss2nUyEB83muuIUIGMg/640?wx_fmt=png&from=appmsg "")  
  
可控  
加路由+  
危险函数，漏洞点就产生了，真离谱，下次有时间  
再看看路由情况  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYv9BolQvdGSFEdl4ib84bMZNWrNKRZ0oZA1PyNptKfCTniaROEL8icQKm2KeKyMqUxdSIfunUcEYeD3A/640?wx_fmt=png&from=appmsg "")  
  
1day的poc如下  
```
/dede/upload.php?delete=../../要删除的文件
```  
  
  
**4.还有一个存在漏洞上传的php**  
  
/puls/mytag_js.php前台的，当时以为是前台的上传，后面发现不是  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYv9BolQvdGSFEdl4ib84bMZN5iaSPSjx5jAOMKvgG7EhEtz4HU5ZaibX3tE5AP2uC2Rn3NJiaCs6qMmMg/640?wx_fmt=png&from=appmsg "")  
  
  
危险函数为file_put_contents和include，那就是文件包含了应该  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/S2ssjS1jNYv9BolQvdGSFEdl4ib84bMZNCrzjvzR4xSnr76RF7x0n8sGBRibfRfMej19HicQO7PT88jpmOdDibGgCA/640?wx_fmt=jpeg "")  
  
看一下参数可不可控跟踪  
$cacheFile发现是可控的   
aid是我们可以赋值的  
```
$cacheFile = DEDEDATA.'/cache/mytag-'.$aid.'.htm';
```  
  
接下来就是  
$m  
yvalues，经过调式可得，首先得满足aid=1&nocache=1，才能走下去，  
$m  
yvalues是通过  
$tagbody控制的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYv9BolQvdGSFEdl4ib84bMZNJ8dxtg9BKTu88uqibsLHVCbDiazEADpjticVyqTPUFaP3l2lfS9hX5zXg/640?wx_fmt=png&from=appmsg "")  
  
再往上走  
$  
tagbody是由$row控制  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYv9BolQvdGSFEdl4ib84bMZN2eHOO9rIck0nfCtVCd1aQOPzzgtGJu9BhJTTH5sTerCTaImt0TqmuQ/640?wx_fmt=png&from=appmsg "")  
  
再看看$row,是由我们传入的aid控制的，所以这里两个参数都可以控制，但是具体  
$  
row的值还是不知道从来里来的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYv9BolQvdGSFEdl4ib84bMZNIz6v5tMxrgW1MmP1O0YZJQDPHk0xQt1Ln9Q3n0cmHb4EHImCxZVkXg/640?wx_fmt=png&from=appmsg "")  
  
所以我们直接看数据库对应的表_  
_mytag,还有注释  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYv9BolQvdGSFEdl4ib84bMZNmNMFTrRhllfcekVejVrgKgjI2Rt3K0oZiaGL4oHsjJichhV3qQrdd4Vw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYv9BolQvdGSFEdl4ib84bMZNAhcoCTicibgndu5mblEwwP99EEbOeUXkMicgmDUQfy42Q7nib0iar6MeZLQ/640?wx_fmt=png&from=appmsg "")  
  
可以分析出这个功能点应该再自定义标签js哪里，如图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYv9BolQvdGSFEdl4ib84bMZNS5DugT8pABTGQoeTrHCLyibqouLJWPib6iblAvngWQ9upMExrVne34MvA/640?wx_fmt=png&from=appmsg "")  
  
  
然后警告调试myvalues的值是通过查询自定义id值1，再将图中正常内容的值赋值给myvalues，也就是上面的123456  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYv9BolQvdGSFEdl4ib84bMZN2XoBmUhypt7j834XwVxvED4zMjmibDwUXkXdVGsra3qv9oicb7kNicIpA/640?wx_fmt=png&from=appmsg "")  
  
所以一目了然了，通过再后台自定义标签js正常内容添加内容，通过file_put_contents将内容写入到data/cache/mytag-1.htm，include包含这个文件就行了。  
```
include $cacheFile;
```  
  
但是还是有一堆内容检测，挺好绕的，大家可以测试一下，我就不放poc了  
```
global $cfg_disable_funs;
        $cfg_disable_funs = isset($cfg_disable_funs) ? $cfg_disable_funs : 'phpinfo,eval,assert,exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,file_put_contents,fsockopen,fopen,fwrite,preg_replace';
        $cfg_disable_funs = $cfg_disable_funs.',[$]GLOBALS,[$]_GET,[$]_POST,[$]_REQUEST,[$]_FILES,[$]_COOKIE,[$]_SERVER,include,require,create_function,array_map,call_user_func,call_user_func_array,array_filert';
        foreach (explode(",", $cfg_disable_funs) as $value) {
            $value = str_replace(" ", "", $value);
            if(!empty($value) && preg_match("#[^a-z]+['\"]*{$value}['\"]*[\s]*[([{']#i", " {$myvalues}") == TRUE) {
                $myvalues = dede_htmlspecialchars($myvalues);
                die("DedeCMS提示：当前页面中存在恶意代码！<pre>{$myvalues}</pre>");
            }
            if(!empty($value) && preg_match("#<\?(php|=)#i", " {$myvalues}") == TRUE) {
                //
                $myvalues = dede_htmlspecialchars($myvalues);
                die("DedeCMS提示：当前页面中存在恶意代码！<pre>{$myvalues}</pre>");
            }
            if(!empty($value) && preg_match("#(<)[\s]*(script)[\s\S]*(src)[\s]*(=)[\s]*[\"|']#i", " {$content}") == TRUE) {
                preg_match_all("#(src)[\s]*(=)[\s]*[\"|'][\s]*((http|https)(:\/\/)[\S]*)[\"|']#i", " {$content}", $subject);
                foreach ($subject[3] as $url) {
                    if (preg_match("#^(http|https):\/\/#i", $url) && !preg_match("#^(http|https):\/\/{$_SERVER['HTTP_HOST']}#i", $url)) {
                        die("DedeCMS提示：非本站资源无法访问！<pre>{$url}</pre>");
                    }
                }
            }
```  
  
绕过上面的内容检测，就可以拿最新版的shell了，但是很难受这个是后台的洞，myvalues值是后台修改的，害就分析到这里吧。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYv9BolQvdGSFEdl4ib84bMZNrqlPGxiaKvKibJJTDdW2wttsRKVsnVwDBicu4HGJbMzDk0CIPibD6IajAA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYv9BolQvdGSFEdl4ib84bMZNu1Tf3ibk5Lia9G2xfgH1DWKzibX3AKiau4H6BYyWESk58A4Po8U2brTMTA/640?wx_fmt=png&from=appmsg "")  
  
**5 总结**  
  
想了想交了一下cnvd,发现重复了，真的是汗流浃背了，真nm卷，最新版也重复,下次看看其他的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYv9BolQvdGSFEdl4ib84bMZNhlsSuL64f4MD5pAYicAQ9ckPMRz4yTj9kyTqTu2TUN7v6tdM1IqIWVQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
Tips:  
  
  
文章来源：  
 湘安无事  
  
往期推荐  
  
[一款全面且强大可平替xray的扫描器,支持被动主动扫描-漏洞探测](https://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247498341&idx=1&sn=6d9d306d298c56fa7793df9a777a53d1&chksm=c0c85b91f7bfd287c9009c10fbf4d2c4a8c85dac66bfb61360032705c1c7f490eea23e99e807&scene=21#wechat_redirect)  
  
  
[【2024HW】国H招聘早班车启动](https://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247498213&idx=1&sn=7812c982a6e05f29ed94c19e7b3cbefe&chksm=c0c85811f7bfd107217033770676284a6c5a89adccfe5f61f9c925c2b57b94a86fc01d7514e5&scene=21#wechat_redirect)  
  
  
[全自动化信息收集工具，解放双手](https://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247498149&idx=1&sn=62cf6ba271c83c7718cc6a907e33e2a5&chksm=c0c85851f7bfd1479a5c7ff176dc1336e182da1852b3b66e6489101f46444b40b530cf20e8ff&scene=21#wechat_redirect)  
  
  
[【红队必备】黑客应该用什么样的浏览器？自带多层代理、匿名浏览、防止追踪](https://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247498135&idx=1&sn=c9709b02a4282fbb874a49d8d8a578b6&chksm=c0c85863f7bfd1757bc9cd4ffbc15b2cc577fe9ecc6bb374133b8b87f099a9024ff1da81ef3a&scene=21#wechat_redirect)  
  
  
[学习干货|等保测评2.0技术自查阶段(上)](https://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247498135&idx=2&sn=e4b775e63f58eda523a0f7cd4b692737&chksm=c0c85863f7bfd175afcff9c10267d85c25273219fd4350c0af841583c8aea311885c8e887f1d&scene=21#wechat_redirect)  
  
  
[【漏洞速递】宝塔最新未授权访问漏洞及sql注入](https://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247497949&idx=1&sn=dd9856b9e5125f92ec9a3281b0f5fcc5&chksm=c0c85929f7bfd03fda87e1a4c288c5cf4270f81af9300e8cd06304d9e60c54133466723c89f7&scene=21#wechat_redirect)  
  
  
[实战 | 记一次有趣的文件上传绕过getshell](https://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247497923&idx=1&sn=a759d4420a96b595dbd2a047e6268f71&chksm=c0c85937f7bfd021c8dd76550839f0070a2d39dfbb09c830f0645caf3a3fc41bb2174e9bd5bb&scene=21#wechat_redirect)  
  
  
[一款国外大牛 40X bypass工具(1.5K+star！)](https://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247497868&idx=1&sn=66bdd60b53f4423d7e3d151097a40ba2&chksm=c0c85978f7bfd06e1da57eef8d6e93ad9f0d2ec92ca714866a46226767d25dbd3d4413a4f603&scene=21#wechat_redirect)  
  
  
[最新免杀34个查杀引擎的Webshell](https://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247497854&idx=1&sn=d3bc98a2a58eda6727648b3f63dc2de2&chksm=c0c8598af7bfd09c444c988f309237f8470364b6138f2e1abc5256236ca62397d98ecbbcdd6b&scene=21#wechat_redirect)  
  
  
[【工具推荐】渗透测试工具箱 -- AutoRedTools](https://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247497838&idx=1&sn=bb215e03914f60ca73e8058e280165d5&chksm=c0c8599af7bfd08c80eb7d5c8280e92662c3290c21eda7109988467e753b2290c47633993061&scene=21#wechat_redirect)  
  
  
[【长篇巨制】6W多字的Windows 应急响应手册发布](https://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247497751&idx=1&sn=e9ec8352fdda412869b365490044b7c2&chksm=c0c859e3f7bfd0f5af33ea70554e3f97684978b80bf2f06b1cc430ca2f1d36327811a392161a&scene=21#wechat_redirect)  
  
  
[常规安全检查阶段 | Windows 应急响应](https://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247497751&idx=2&sn=4dc34499aca0c5237f9c384d5386f45b&chksm=c0c859e3f7bfd0f53e2893372869d3792e16b305ca32cf25140306fb1355861bcc608462bf96&scene=21#wechat_redirect)  
  
  
[灯塔资产管理系统魔改版搭建(ARL-Puls)](https://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247496861&idx=1&sn=72ef999374fd2754a46e1526899e86b6&chksm=c0c85569f7bfdc7fcf2a815c46ee73c9f031b0a32d7179da28a11d20e3a7b9aff4743be15251&scene=21#wechat_redirect)  
  
  
[记某系统有趣的文件上传](https://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247496821&idx=1&sn=c4d0abef07a6d70c8901d9f405360543&chksm=c0c85581f7bfdc971ab3865c18d6d36dc1e5ba68a1a4662afffd45f67a9f23f1b162c2fce0a9&scene=21#wechat_redirect)  
  
  
[【渗透实战】微信小程序渗透测试](https://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247496721&idx=1&sn=1acb2223b03f5ed44b7d44eaa40ad068&chksm=c0c855e5f7bfdcf37e05059835786b05c44f8357463ae4c941021affcb2b7122b583e4a1ada9&scene=21#wechat_redirect)  
  
  
  
  
