#  某云盘系统 API 端点无限制上传漏洞解析   
Massa  安全洞察知识图谱   2025-05-16 00:29  
  
**免责声明**  
 由于传播、利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号安全洞察知识图谱及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
## 1工具介绍  
### background  
  
在某次赚钱的时候,发现出现了这个系统的低版本 搜索了很久相关只找到了一个  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgF6wQwLQssSvFeznUQ7cE0ib4IoiczUiaq8IF5qtX7EjV1Kkca1RqoChkIrafJZry2ZS7SJYF06CJgFw/640?wx_fmt=png&from=appmsg "")  
  
  
简短的一句话 但没有其他漏洞细节 于是本地搭建挖一下  
### 0x01 漏洞限制条件  
  
![image-20250306174220208.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rhic2eSUB7oxwhHPcGA4rxBibkdMq1RatwKMPhnFGiadfrm23SzTrWOibqINNoVib03bLpvuf3FnfaXVJyQ/640?wx_fmt=jpeg "")  
  
首先是需要一个账号来调用后台的插件  
  
但是本套系统默认两个账号  
  
guest:guest demo:demo  
  
还有一个就是要知道web的路径 当然这个后面说  
### 0x02 漏洞分析  
  
定位到函数 发现有一个in['file']的参数  
  
![image-20250306174557708.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rhic2eSUB7oxwhHPcGA4rxBibkbBdG1WJhWLibq396d6CAhibbfCQXjEHHCSQiaGpz6BM4g13kmhottwaHQ/640?wx_fmt=jpeg "")  
  
跟进in 在controller里面可以看到这个参数  
  
![image-20250306175026755.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rhic2eSUB7oxwhHPcGA4rxBibkUxpE6T2mC7KnO88rLb2PyiadCQgA4MKQia976oJHvwdsLfMptrLSozKg/640?wx_fmt=jpeg "")  
  
![image-20250306182032074.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rhic2eSUB7oxwhHPcGA4rxBibkUj3ibBOWm7BUquSAGPia4wXLpkkaEhsacFVC0fDATOg4dAAU1fFicBRQQ/640?wx_fmt=jpeg "")  
  
  
还是全局变量 很容易判断他可以直接传参数  
  
跟进这个可以发现有一个get_path_ext  
后缀  
  
![image-20250306182255890.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rhic2eSUB7oxwhHPcGA4rxBibk0foTnOXeibacCIiah8FiaCc0bNBEmZvXvPQaba46PRJT0DBEUofMSHCicg/640?wx_fmt=jpeg "")  
  
可以发现只限制了数量和一些不可见字符 并没过滤php  
  
继续跟进unzip_filter_ext 可以发现他过滤了 .user.ini .htaccess  
  
![image-20250306182624887.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rhic2eSUB7oxwhHPcGA4rxBibkrWHDHjFebiasYf602AmztvuvtZFrD7mEJibso1Fj4dicwqib0e5d3eu1PA/640?wx_fmt=jpeg "")  
  
但是有一个checkExt检查后缀 但是逻辑有点问题  
  
在这里有一个不允许的名单  
  
还会不断的merge  
  
![image-20250306185117546.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rhic2eSUB7oxwhHPcGA4rxBibkM29ia6iaGxlvRP7MwibA2kiaibrnNMaj86kDBRtlthQJrwpM5hZDaaelnJA/640?wx_fmt=jpeg "")  
  
在这里进行判断  
  
![image-20250306185314860.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rhic2eSUB7oxwhHPcGA4rxBibk9ia0FibvabguJ8RMPTibpauyfOuBklr08CcEic1cEibqbnic9BbnEjnQr3hA/640?wx_fmt=jpeg "")  
  
  
逻辑错误点在这里 我们这里的$file是php 而后面的则是.php  
  
因为stristr的意思是在前面的字符串查找后面的 而在php字符串里并不包含.php  
  
所以在这里我们可直接传入php  
  
![image-20250306190635350.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rhic2eSUB7oxwhHPcGA4rxBibkfxWRwx1GIzvUa5QSF8d2DWaJpJOTvlIXalaGAmzUhGWrJhia53O866A/640?wx_fmt=jpeg "")  
  
打印了下 $infoData发现为NULL 那后面$linkfile就是单纯的网页地址  
  
而且他会对一个url发起请求并保存文件  
  
我们可知$cachefile 的后缀是php 其实就可以直接写文件了  
  
在目录下放一个/1.php的马  
  
![image-20250306194818702.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rhic2eSUB7oxwhHPcGA4rxBibkSjNibJoWQ4oRVCOuoRBRcWkUbNhXxhhWmLF4qlhb2KckpbyM1Av8Jcg/640?wx_fmt=jpeg "")  
  
直接进行访问  
  
![image-20250306191647101.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rhic2eSUB7oxwhHPcGA4rxBibkwPFyZI63bVmk7HuzAlMRUv6RmNGlRQCb2zGAYDib4IS1sDcpqyoMVnQ/640?wx_fmt=jpeg "")  
  
发现在响应头里会有php文件名 但实际上  
  
![image-20250306191716494.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rhic2eSUB7oxwhHPcGA4rxBibkxN1ZBnnXPUkMiaTGK67lzmiaiaibvnMMH9Mb3fpGibW0yVvqhHDj4snS2FA/640?wx_fmt=jpeg "")  
  
在这里也写了完整的生成语句  
  
![image-20250306191943227.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rhic2eSUB7oxwhHPcGA4rxBibkaY4N2uf5jOoSbKlVo2fpicBynpRJUxgdqP8X8wrE0OicH1noxjSIiaIOg/640?wx_fmt=jpeg "")  
  
但是我们发现在生成文件的时候还是有一个目录的  
  
![image-20250306192008663.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rhic2eSUB7oxwhHPcGA4rxBibkuXyPoUbAheJWyLh3kVIicMIJpIpUbqc5a2WWuavjVTL5ia3wsiclbc6Cw/640?wx_fmt=jpeg "")  
  
回到刚才代码  
  
我们查看cacheFile类  
  
![image-20250306192121007.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rhic2eSUB7oxwhHPcGA4rxBibkM96sdWtW8bQRCZKUj0oriaMlu7oqtGGicDGiaribYNNcicS7LzRc9Sqjvgw/640?wx_fmt=jpeg "")  
  
在这里有一个hash_path  
的生成  
  
可以选择下断点 或者直接var_dump  
下变量  
  
发现大致目录如下  
  
![image-20250306192340806.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rhic2eSUB7oxwhHPcGA4rxBibkxoJ1mmOtImuJGjCibia2xuPeKoId7BMaB77YTZrrVXHJR7KuXRN45hNg/640?wx_fmt=jpeg "")  
  
其实可以推断出来 /var/www/html/data/User/guest/home/ 为一般漏洞利用的hash_path  
  
而且你会发现虽然说他在前面设置了一个随机生成的系统密码  
  
但实在底下只是进行了md5的编码就把$path写进来了 所以  
  
![image-20250306194548339.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rhic2eSUB7oxwhHPcGA4rxBibk5ClLLEtvSNYn4zULWG5hk8eeKaGA6dx0C8V7kg7VhYPYZLv8H88a3A/640?wx_fmt=jpeg "")  
  
  
![image-20250306194412913.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rhic2eSUB7oxwhHPcGA4rxBibkcH6pPeKBoMwc8OOG3ActcfZpRxH79utaDSOjo1ZllH0jGQ42YrgiatA/640?wx_fmt=jpeg "")  
  
只要文件不变 md5值是不变的  
  
![image-20250306194654634.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rhic2eSUB7oxwhHPcGA4rxBibkxapL358e8BoW0PnqaLzUqFXAM0CmqpAibFW4g5GQ5ibehy2yueibsKWOw/640?wx_fmt=jpeg "")  
  
构造poc即可写木马  
### 0x03修复方案  
  
官方的修复中  
  
![image-20250306194957952.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rhic2eSUB7oxwhHPcGA4rxBibkxx8TwocOFGJClJdmgpribBkhVzuwXiakXQE9NP6JicAxShuXmrDricRzsA/640?wx_fmt=jpeg "")  
  
在这里把文件返回头给注释掉了 但是我们上文提了自己生成也可以  
  
可以看到在path生成上完善了 拼接了$pre 没办法再进行路径的查找  
  
![image-20250306195030619.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rhic2eSUB7oxwhHPcGA4rxBibkzJgud3VM2CAiaJOQB0ZpqNgpLzIwKrtpnsRwkPNVus3UVfTnFJ9bGeA/640?wx_fmt=jpeg "")  
  
**文章来源：奇安信攻防社区**  
  
**链接：https://forum.butian.net/article/673**  
## 2免费社区  
  
安全洞察知识图谱星球是一个聚焦于信息安全对抗技术和企业安全建设的话题社区，也是一个  
**[免费]**  
的星球，欢迎大伙加入积极分享红蓝对抗、渗透测试、安全建设等热点主题  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rh8aia4mibs0I8I42MrYYOSE2DVEpVpPHvxufMGR0yufpgouwIXEl7H5eLm0MgolGFQMDFIrKLTxaYIQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rhic2eSUB7oxwhHPcGA4rxBibkzK2yZDWbEbIFUicsiaIvKBicJpoAGWD0TsCuglicbPcQsyKrmIibvHiaGWDA/640?wx_fmt=jpeg&from=appmsg "")  
  
