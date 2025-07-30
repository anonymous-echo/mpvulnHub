#  dedecms之汗流浃背的审计1day   
江南韵  湘安无事   2024-02-24 23:09  
  
**声明：**  
该公众号大部分文章来自作者日常学习笔记，也有少部分文章是经过原作者授权和其他公众号白名单转载，未经授权，严禁转载，如需转载，联系开白。  
  
请勿利用文章内的相关技术从事非法测试，如因此产生的一切不良后果与文章作者和本公众号无关。  
  
  
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
  
**推荐阅读：**[干货 |](http://mp.weixin.qq.com/s?__biz=MzU3Mjk2NDU2Nw==&mid=2247484042&idx=1&sn=4e790a24f47cac1c632c0d7bab91a7e8&chksm=fcc9a932cbbe2024429fa59c0ef858f9173a12470543d40be164343660f9842b9ed5d957e597&scene=21#wechat_redirect)  
   
**记又一次教育园js逆向挖掘**  
  
**推荐阅读：**[干货‍ |](http://mp.weixin.qq.com/s?__biz=MzU3Mjk2NDU2Nw==&mid=2247484200&idx=1&sn=0b3b9ebd2d3b7a5e391f2910b54ad75a&chksm=fcc9a890cbbe218675c798595d8aee6a9a500446d2c38a4c72cb737cc9c08f39903920cef957&scene=21#wechat_redirect)  
  
******一波三折的教育园证书挖掘******  
  
**推荐阅读：干货‍ | 记又一次教育园证书挖掘**  
  
**推荐阅读：干货‍ | 教育园src上分小技巧**  
  
**点赞，转发，在看**  
  
