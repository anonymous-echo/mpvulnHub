#  firebase：一款功能强大的Firebase数据库安全漏洞与错误配置检测工具   
 FreeBuf   2024-04-28 19:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
**关于firebase**  
  
  
  
firebase是一款针对Firebase数据库的安全工具，该工具基于Python 3开发，可以帮助广大研究人员针对目标Firebase数据库执行安全漏洞扫描、漏洞测试和错误配置检测等任务。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR380OZicrcfvbgsicJwGV3nj80MI0ooljW2zrne6Jy47BEa3YSXV3Fv7medgxSEv8Ovca7cKhBKbNokw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
该工具专为红队研究人员设计，请在获得授权许可后再进行安全测试。  
  
  
**工具要求**  
  
  
##   
  
当前版本的firebase需要使用到下列非标准Python模块：  
  
  
dnsdumpster  
  
bs4  
  
requests  
  
  
**工具安装**  
  
  
##   
  
由于该工具基于Python 3开发，因此我们首先需要在本地设备上安装并配置好最新版本的Python 3环境。  
  
  
接下来，广大研究人员可以直接使用下列命令将该项目源码克隆至本地：  
```
git clone https://github.com/Turr0n/firebase.git
```  
  
然后切换到项目目录中，使用pip工具和项目提供的requirements.txt文件安装该工具所需的其他依赖组件：  
```
cd firebase

pip install -r requirements.txt
```  
```
python3 firebase.py [-h] [--dnsdumpster] [-d /path/to/file.htm] [-o results.json] [-l /path/to/file] [-c 100] [-p 4]
```  
### 命令行参数  
  
****  
-h：显示工具帮助信息和退出；  
  
-d：已下载HTML文件的绝对路径；  
  
-o：输出文件名称，默认为results.json；  
  
-c：爬取Alexa排名前100万的域名，可以设置具体数量，例如100（即最大100万个）；  
  
-p：要执行的进程数量，默认为1；  
  
-l：包含待爬取数据库的文件路径，每行一个数据库名称，该选项不能跟-d或-c一起使用；  
  
--dnsdumpster：使用DNSDumpster API收集数据库信息；  
  
--just-v：忽略没有安全漏洞的数据库；  
  
--amass：amass扫描的输出文件路径 ([-o]选项)；  
  
****  
**工具使用样例**  
  
  
##   
  
下列命令将查询Alexa排名前150的域名以及DNSDumpster提供的数据库，结果将存储至results_1.json文件中，整个工具脚本将使用4个并行进程执行任务：  
```
python3 firebase.py -p 4 -f results_1.json -c 150 --dnsdumpster
```  
  
生成的JSON结果文件将包含收集到的数据库安全信息以及转储的内容，每个数据库包含一个状态数据，可能的值如下：  
  
```
```  
##   
  
**许可证协议**  
  
  
##   
  
本项目的开发与发布遵循MIT开源许可证协议。  
  
  
**项目地址**  
  
  
##   
  
**firebase：**  
  
https://github.com/francesc-h/firebase  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复“加群”，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
> https://github.com/PaulSec/API-dnsdumpster.com  
> http://beautiful-soup-4.readthedocs.io/en/latest/  
> https://github.com/requests/requests  
> https://pentest-tools.com/information-gathering/find-subdomains-of-domain  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247493362&idx=1&sn=39c9b1c4d709e5ad0babb44995b0e412&chksm=ce1f1c6df968957be704d2843b3f448b252d2a2e1b5271efa486c3e57819849e0e287b04568b&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247493318&idx=1&sn=02dc5120e00a3d6759be8fcf1b49ec0a&chksm=ce1f1c59f968954fd868b2f8cefa0e8bc5dd703c36dd6db4fc03923be36783a7d4cc791c18b6&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
