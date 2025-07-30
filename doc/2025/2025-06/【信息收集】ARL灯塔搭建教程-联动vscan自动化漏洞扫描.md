#  【信息收集】ARL灯塔搭建教程-联动vscan自动化漏洞扫描   
原创 网络攻防情报小组  C4安全团队   2025-06-05 15:37  
  
安装环境：Ubuntu  
  
灯塔安装docker容器下载链接：  
  
https://pan.xunlei.com/s/VONOpsG-EUyAvbg9jWdGZ_6OA1?pwd=gdmz#  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSxK3xelQ7hHiaiaoV57uQd3EqWscEVuqzPzuYboezePTo7jDzqHyXZkxeuIEiaiaEpVrcf0nhHs7icyUA/640?wx_fmt=png&from=appmsg "")  
  
  
将上面的容器文件tar包和ARL的压缩包zip包下载下来，先解压zip文件  
  
再使用docker命令加载下载下来的tar包：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSxK3xelQ7hHiaiaoV57uQd3EsWIArGMyb3goH1ibyQam9iaZibZCrzCGeKy8Qo1ibibicsBfIXWLm4XwGS1w/640?wx_fmt=png&from=appmsg "")  
  
进入zip解压后的ARL下面的docker目录，使用命令创建  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSxK3xelQ7hHiaiaoV57uQd3EsBrvbodPLMw5VJicvVLMjkmlyxao64FPtHoZscibPICA26o1ynVhCnAA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSxK3xelQ7hHiaiaoV57uQd3EiatsT0maeFdBAJbWnSBsnIzY0pcmyxUuPeYhDWkUcxjrsKd9ssgmNLQ/640?wx_fmt=png&from=appmsg "")  
  
之后使用docker-compose up -d启动ARL  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSxK3xelQ7hHiaiaoV57uQd3E5K7zVbiaMh1xVLlBlKL7KnQsh5rrkhUxwnUgfJs0ELot6fibMSFDF8tA/640?wx_fmt=png&from=appmsg "")  
  
启动成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSxK3xelQ7hHiaiaoV57uQd3EJFvK8ibY5PvJIzdXkZEFl2zGYpCicSgpNIwJO53na4zPJ0tgnV4wYjpw/640?wx_fmt=png&from=appmsg "")  
  
  
漏洞扫描工具vscan下载地址：  
  
https://github.com/youki992/VscanPlus/releases  
  
建议下载v1.0.4.2版本，选择Linux可执行文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSxK3xelQ7hHiaiaoV57uQd3EhRXREQFMbzuGLicG9Xpn1rwCmNibibYiab3crRf70no97JNMUj1meia23xQ/640?wx_fmt=png&from=appmsg "")  
  
因为ARL自带的Centos容器版本较老，  
v1.0.4.2以上的  
版本编译的vscan运行会提示更新GLIBC，非常麻烦不建议尝试  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSxK3xelQ7hHiaiaoV57uQd3EEicjR0366zjoszGn2CrSQScEghYOicbn3IYjkibPiagxR8icegOicYPXicecg/640?wx_fmt=png&from=appmsg "")  
  
重命名下载的vscanPlus为vscan，复制到ARL对应的三个容器中：  
  
arl_web、arl_worker、arl_scheduler，目录都是一样的  
```
docker cp vscan arl_web:/usr/bin/vscan
docker cp vscan arl_worker:/usr/bin/vscan
docker cp vscan arl_scheduler:/usr/bin/vscan
```  
  
然后把漏洞扫描的逻辑文件nuclei_scan.py，也按同理复制到三个容器中  
  
下载地址如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSxK3xelQ7hHiaiaoV57uQd3EsFibC4ZCHM2LThYHtekyhGpdyNb7Hick0UQ3U6ib3twViaiaIo0ukEmHYtw/640?wx_fmt=png&from=appmsg "")  
  
https://cowtransfer.com/s/739a8b4c12a44d，或访问奶牛快传 cowtransfer.com 输入传输口令 rl0omb  
  
复制命令如下  
```
docker cp nuclei_scan.py arl_web:/code/app/services/nuclei_scan.py
docker cp nuclei_scan.py arl_worker:/code/app/services/nuclei_scan.py
docker cp nuclei_scan.py arl_scheduler:/code/app/services/nuclei_scan.py
```  
  
然后给这三个容器配置libpcap环境，这里以其中一个环境为例  
  
因为Centos版本较老，首先需要更换yum源  
  
在/etc/yum.repos.d文件夹下新建CentOS-Base.repo文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSxK3xelQ7hHiaiaoV57uQd3Et8XvN44lnnibyykYu7A6LKrtgIuhRhT5DFRIFeXjQ8ibhqdE7py64FuQ/640?wx_fmt=png&from=appmsg "")  
  
写入内容如下  
```
# CentOS-Base.repo
#
# The mirror system uses the connecting IP address of the client and the
# update status of each mirror to pick mirrors that are updated to and
# geographically close to the client.  You should use this for CentOS updates
# unless you are manually picking other mirrors.
#
# If the mirrorlist= does not work for you, as a fall back you can try the 
# remarked out baseurl= line instead.
#
#

[base]
name=CentOS-$releasever - Base
mirrorlist=http://vault.centos.org/?release=$releasever&arch=$basearch&repo=os&infra=$infra
baseurl=http://vault.centos.org/centos/$releasever/os/$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7

#released updates 
[updates]
name=CentOS-$releasever - Updates
mirrorlist=http://vault.centos.org/?release=$releasever&arch=$basearch&repo=updates&infra=$infra
baseurl=http://vault.centos.org/centos/$releasever/updates/$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7

#additional packages that may be useful
[extras]
name=CentOS-$releasever - Extras
mirrorlist=http://vault.centos.org/?release=$releasever&arch=$basearch&repo=extras&infra=$infra
baseurl=http://vault.centos.org/centos/$releasever/extras/$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7

#additional packages that extend functionality of existing packages
[centosplus]
name=CentOS-$releasever - Plus
mirrorlist=http://vault.centos.org/?release=$releasever&arch=$basearch&repo=centosplus&infra=$infra
baseurl=http://vault.centos.org/centos/$releasever/centosplus/$basearch/
gpgcheck=1
enabled=0
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7

```  
  
之后更新yum源  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSxK3xelQ7hHiaiaoV57uQd3EXG5cRknxUyjp3ic0kgwf6JAFTYSK3RQGFzwngDFeB5oLmGX5brn9JOg/640?wx_fmt=png&from=appmsg "")  
  
之后安装libpcap环境  
  
yum install libpcap-devel  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSxK3xelQ7hHiaiaoV57uQd3EM0FTl53dz6zMW1ao2lMLNjicCRKqAuicJQeuh7t2bk8Dy2bu2Skob7BQ/640?wx_fmt=png&from=appmsg "")  
  
建立libpcap的软连接  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSxK3xelQ7hHiaiaoV57uQd3E0JzhC6kwg21xLFia5SS8UiaopNMKDaclO1l9f2NNzH7IH6Lad0TfscMw/640?wx_fmt=png&from=appmsg "")  
  
再运行vscan，漏扫程序就正常提示输入参数了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSxK3xelQ7hHiaiaoV57uQd3E04hkgQCX0vsWwAjujcO4QlxicvCexwypxj2txcQLadmACtrBrQ7pWOg/640?wx_fmt=png&from=appmsg "")  
  
回到ARL系统页面，在策略配置中，配置一条勾选"nuclei调用"的策略  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSxK3xelQ7hHiaiaoV57uQd3E4ES05Qr0N5LEJlp1wcqpjkE5NFveJHv67wellh2ztvFMSLdyCFoSIA/640?wx_fmt=png&from=appmsg "")  
  
使用该策略下发一条任务，在信息收集完成后，可以看到原先nuclei的扫描结果被替换成了vscan的扫描结果，其中包含目录扫描、指纹检测、漏洞扫描三部分，众所周知vscan是基于指纹检测漏洞的，所以指纹检测错误会影响最终漏洞结果，其中：  
  
漏洞URL中会显示扫描的敏感目录  
  
漏洞名称中会显示vscan自带的指纹检测结果  
  
验证命令中会写明简略的漏洞名称（需要对照nuclei或xray的漏洞poc找到漏洞细节）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSxK3xelQ7hHiaiaoV57uQd3EUzXNHkREbl6509LBmxGsqbaP4lojlOypWcErOYwCpkLTvZKbmICyXQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
2025年团队HW情报交流群如下，目前招聘中高级别研判，师傅可进群交流  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSxK3xelQ7hHiaiaoV57uQd3EWPtcWZcAp2dfjLqtQ1Oa26SFfLeoGMOXDmEbZeMoSPcCJK4M8soQdQ/640?wx_fmt=png&from=appmsg "")  
  
****  
**专栏介绍**  
  
Freebuf知识大陆内部共享资料截屏详情如下  
  
（每周保持更新，已更新 170+文档，扫码可免费预览）  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJSiao22HdM7F7OBu4zNJicKjkzvdgfFtJotO7T8dD5ATKyyeuQibDwZoltOB3Uy5nRicGDxCEpwrlRYNg/640?wx_fmt=jpeg&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
  
**知识大陆——安全渗透感知大家族**  
****  
  
圈子券后现价   
￥39.9元/年       
￥59.9元/永久  
  
（新人优惠券折扣  
20  
￥，扫码即可领取优惠）  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJR7GIiatmMxDnlYcGJjOmibZcd7ribwq1zichkjwIczCqhZ1zpXib3VcJpMWlSLfa6qpXwfVy6hguOXdibA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
内部圈子——  
群  
友反馈，价格优惠，内容优质  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJSiao22HdM7F7OBu4zNJicKjkZXuRl4vOBsaQwJK1AbsPcGMiczaPickCuIzicPiblfFjyjic3aeuzqVLLhg/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJSiao22HdM7F7OBu4zNJicKjkpxDWia5shmzQH4UialWGUCsoWYMHVpcEtUxF7RsfJaHKl9gsVWEjqAuw/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
**课程专栏介绍--内部教程**  
  
团队内部课程如下，感兴趣的师傅扫码咨询  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJQdSgKLoGRNHxosfWAF6q2LORrxiaqE2Kr7X3DtRbbrCsJrRgxwe5yNiaEnHIsn8HJrsia8UEutLphxA/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  
  
  
  
  
  
  
END  
  
  
  
关注Cod  
e4th安全团队  
  
了解更多安全相关内容~  
  
  
  
