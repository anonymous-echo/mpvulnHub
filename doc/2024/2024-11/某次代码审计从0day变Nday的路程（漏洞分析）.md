#  某次代码审计从0day变Nday的路程（漏洞分析）   
原创 Ambition  进击安全   2024-11-21 02:21  
  
**免责申明**  
  
本文章仅用于信息安全防御技术分享，因用于其他用途而产生不良后果,作者不承担任何法律责任，请严格遵循中华人民共和国相关法律法规，禁止做一切违法犯罪行为。  
  
# 一、前言  
  
   在昨天一位师傅联系到我，说有一套代码找到了一个后台的任意文件上传漏洞，但是想变成前台漏洞，于是找到我进行分析分析。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhW2HRmLhxONQf4WR7dic8qH5R1Q7XicppLic2gD7RbbX2icNP0BcI66POvUP1TK5YDE9GXicMSTuFrX1ibA/640?wx_fmt=png&from=appmsg "")  
# 二、分析过程  
  
   其实大家也可以看到就是下面这套源码：https://gitee.com/lylme/lylme_spage    我们搭建起来看一看，载入编辑器开始看代码。   ![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhW2HRmLhxONQf4WR7dic8qH5K20GpNBPG7Ms0INibfqOjCm3uBxsvORxXdzXXpYIqS4JnZeRRBSHGIw/640?wx_fmt=png&from=appmsg "")  
    光看代码的目录结构，大致可以猜到，admin目录下的文件肯定是需要后台登录之后才可以进行触发，这里我们先看看在后台登录的逻辑在哪里。**这里说一个小技巧：可以搭建起来网站之后通过数据包定位代码**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhW2HRmLhxONQf4WR7dic8qH5E4FBYodWulWbk2mNRkUibVXMbW6ngy82XtQtZTGh9FibuKHcpvGcvibHQ/640?wx_fmt=png&from=appmsg "")  
admin下的login.php文件，跟进去看一看。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhW2HRmLhxONQf4WR7dic8qH5oSGnicEqFsB83qP33ZibiaT7ANNlacx2TVgauYV8GrXelY66qllN8ZoOQ/640?wx_fmt=png&from=appmsg "")  
这里大致看一下我们知道了，对用户名以及密码进行相关加密并且在经过authcode方法处理进行认证的，虽然说看到其中有一个sys_key，但是对于这种鉴权方式拿到了相关的key还是需要username以及password的，这种认证方式还是比较少见的。  
# 三、鉴权分析  
  
  知道了如何进行登录认证的，下来我们看看如何进行鉴权，也就是如何进行的区分你登录了没登录，这里可以说一下，一般都是通过cookie或者session等方式进行鉴权的。 查看一个admin文件，肯定是有鉴权的。![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhW2HRmLhxONQf4WR7dic8qH5nFBIBzkFI1QicxKou8iaNsPvkoQGAJFayny36pgjLX2RfUzBNDqY4p4g/640?wx_fmt=png&from=appmsg "")  
可以看到判断了isLogin值是否等于1如果等于的话允许你访问，否则不允许访问，可以验证一下，我们给他加一个！取反，尝试这块是不是真正的鉴权。  
### 取反验证，加入！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhW2HRmLhxONQf4WR7dic8qH5YedFE87K6RtOMLpQ2H0Lo8Rg5Ho3bxwALYoWhvLtQlibggbw84qJJ4A/640?wx_fmt=png&from=appmsg "")  
尝试访问。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhW2HRmLhxONQf4WR7dic8qH5bXMQ8HboWewpibP2OSo6vIjTb4HjADT6w8vBMztat2GQjlICicsfNic8A/640?wx_fmt=png&from=appmsg "")  
### 不加入！验证是否跳转登录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhW2HRmLhxONQf4WR7dic8qH5ibgOkqYGpKuZcdaYqByRIO3X7jT3ibg0HkiaHNibJwcsibxM84BD7QCPxJw/640?wx_fmt=png&from=appmsg "")  
看看是否会跳转登录。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhW2HRmLhxONQf4WR7dic8qH5Aq5x71KK7uRuOibYzewlrVtibH5LXvibicdkKSIowIibDzkpiaXKhAgRCicCQ/640?wx_fmt=png&from=appmsg "")  
  
确定了这个是鉴权之后，我们看看如何绕过。  
# 鉴权绕过（没成功）  
  
在这里我们知道了肯定是上面包含了一个文件为common文件获取到的isLogin值，我们跟入文件查看。![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhW2HRmLhxONQf4WR7dic8qH5HsFYnuMNXzOouaqD3w0Hh4XaZ13Ju7wxIPb9bGuzGUABLrcBwA6rHQ/640?wx_fmt=png&from=appmsg "")  
继续跟入。![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhW2HRmLhxONQf4WR7dic8qH5v348ibXrLtVruKhrh591jzOoQiag5lTbP84zSeMMJOyLWseFld7ibMZRg/640?wx_fmt=png&from=appmsg "")  
这里发现了判断COOKIE当中的admin_token值进行判断，并且这里进行调用authcode方法给到了token，并且分离出来了user以及sid值，然后进行对于admin_user以及admin_pwd进行md5加密，与sid进行对等，那么这里有两个风险点：1、COOKIE可控，但是调用了authcode方法，这个方法也好说因为COOKIE可控我们可以构造恶意payload让他调用authcode方法结构为我们想要的信息。2、使用了==弱类型比较，我们可以尝试绕过，如果构造出来经过authcode解密之后的值与admin_user以及admin_pwd进行md5加密值相等的话可以绕过鉴权。这里先进行看看authcode调用结束之后是上面信息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhW2HRmLhxONQf4WR7dic8qH5ibCrTwx265VYGD10kTDfwCwHXdbrqiclvAdAlcnSMxyg6A0aFTf21VEg/640?wx_fmt=png&from=appmsg "")  
稍微改动一下代码，这里就不动调了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhW2HRmLhxONQf4WR7dic8qH5cBic7zMoUcnc5czztfymXficDj7dxcbnbExI8pjlL5Nfo11icTmWIx8Tg/640?wx_fmt=png&from=appmsg "")  
这里发现我们需要的就是499dc4f0fdbc3f1e2ded411795c41138与admin_user以及admin_pwd进行md5加密值相等，但是查阅资料之后发现md5弱比较的类型需要md5开头为0e开头才可以，而且好像0e后面不可以有字幕，所以这条路径就卡在这里了。  
# 前台RCE审计过程  
  
   但是我们也获取到了一些信息，那就是PHP当中如果不包含文件common.php那么就是可以进行前台访问的，把目光放在了前台上面。  使用脚本进行跑一下，筛选出来全部不存在common.php的文件。![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhW2HRmLhxONQf4WR7dic8qH5ytwlUyj6lpV0HgQLa2iaibf882693REGRMFg1Vdokd8POg8qlRTEcFjw/640?wx_fmt=png&from=appmsg "")  
   获取到之后，把前台可以访问的文件写一个脚本全部复制到一个路径下，用工具跑一次看看。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhW2HRmLhxONQf4WR7dic8qH5Gvy5nBrBmF88mmh8qx0ukvoAfaq5VIia72xRbkcvuET9QFzqWfbGDjw/640?wx_fmt=png&from=appmsg "")  
扫描之后看file文件找到了漏洞，分析如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhW2HRmLhxONQf4WR7dic8qH5yrZRR8GVF5U5XPeTg8Y5aY1lXiaMqhfVME7zdWaqWLbiavQP4g1nsgSA/640?wx_fmt=png&from=appmsg "")  
这里接受参数file或者url然后将file参数给到了方法upload_img方法，跟入方法看看。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhW2HRmLhxONQf4WR7dic8qH5P7Oy5DtkiaaIUF77vjR3W6BoHKK2icE9goEOWlwLeeibhb7M1v3E4ldWQ/640?wx_fmt=png&from=appmsg "")  
其中存在一个过滤就是获取文件后缀名调用了方法validate_file_type，跟入这个方法看看如何过滤的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhW2HRmLhxONQf4WR7dic8qH5YvRKsRAgDVONQUo4qpMkCpCUSse4u0Rg1oYVGu6qic3rAHdzBGCiaraQ/640?wx_fmt=png&from=appmsg "")  
这里发现获取到后缀之后最终会判断MIME，并不会直接退出，所以我们只要MIME为数组当中的值即可，尝试验证一下。  
# 漏洞验证  
  
尝试进行漏洞验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhW2HRmLhxONQf4WR7dic8qH5Hjj1Xjj0oaLDHneXXUibSuaaZWS7pypRLw1WFkFm8hJTJMhN3eUqWJg/640?wx_fmt=png&from=appmsg "")  
尝试访问。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhW2HRmLhxONQf4WR7dic8qH5woqXibJI5zCu7GhvibCHLglfDPjkF6y4yAJ0qfSibWOn48HAFBdjuAEGw/640?wx_fmt=png&from=appmsg "")  
# 天塌了  
  
正当我兴致勃勃的找这个师傅装* 的时候，把这个漏洞详细发给了这个师傅，这个师傅没回复我别的，只回复了我几个字符。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhW2HRmLhxONQf4WR7dic8qH5v95xNb1yH82Rib6ic7rhOE6AiaZxmQHVQQkuukDQRyq4s5Vf9vMlTc9tw/640?wx_fmt=png&from=appmsg "")  
.................  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhW2HRmLhxONQf4WR7dic8qH5WITZ5jLOh01vjgGUdvhoOI96rgs32iaawHib3qIibialauqBalrMVq4Zaw/640?wx_fmt=png&from=appmsg "")  
# 完结  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZRKuxIKRyhXhuxbCGecu4ibia3kSXD8ePQHrSvPSNtC7PmjzQwR88Hu0LpuXdQzamKBCPAXX82anLS8f0FF3LzzQ/640?wx_fmt=jpeg "")  
  
  
