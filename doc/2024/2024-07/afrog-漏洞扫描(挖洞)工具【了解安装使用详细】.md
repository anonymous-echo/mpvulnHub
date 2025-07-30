#  afrog-漏洞扫描(挖洞)工具【了解安装使用详细】   
原创 大象只为你  大象只为你   2024-07-04 18:20  
  
> **★★**  
免责声明★★  
> 文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与学习之用，读者将信息做其他用途，由Ta承担全部法律及连带责任，文章作者不承担任何法律及连带责任。  
  
#### 1、afrog介绍  
  
afrog 是一款性能卓越、快速稳定、PoC可定制的漏洞扫描(挖洞)工具，PoC涉及CVE、CNVD、默认口令、信息泄露、指纹识别、未授权访问、任意文件读取、命令执行等多种漏洞类型，帮助网络安全从业者快速验证并及时修复漏洞。  
  
**afrog有以下优点：**  
- 开源  
  
- 快速、稳定、误报率低  
  
- 详细的 HTML 漏洞报告  
  
- 可定制且可稳定更新的 PoC  
  
- 活跃的社区交流小组  
  
> 项目地址：  
https://github.com/zan8in/afrog  
  
#### 2、环境准备  
  
基础环境是kali linux ，ip: 192.168.242.4  
> 如果没有kali系统虚拟机，可关注公众号：大象只为你，后台回复：【虚拟机】获取。  
  
  
afrog的安装使用需要go，go版本要求1.19 或更高版本，所以需要先安装go。  
##### 2.1、安装go  
  
在kali linux系统下安装会比较简单，使用apt-get命令，安装完成就可使用，不需要再设置环境变量等，安装命令如下：  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/YlMg2LW4AJuZUnUz1MTbCUiaDExqKm9hXsfnFbVicOLJG9kI93xnuTQQzTJTKx6Kt4ZBSqGW65xvzlOicj2wwOnIQ/640?wx_fmt=jpeg&from=appmsg "")  
#### 3、安装afrog  
  
安装afrog官方有提供3个方式，编译好的Binary直接使用、Github下载源码编译和Go方式安装。本文给前面两种方式，Github源码安装是会比较麻烦，过程中也可能会出现异常情况。  
##### 3.1、编译好的Binary直接使用  
  
github项目地址看到右侧看到Releases点进去下载最新的  
afrog_xxx_linux_amd64.zip  
 或直接访问   
https://github.com/zan8in/afrog/releases  
 选择版本下载，然后复制到kali系统、解压即可用。  
```
```  
##### 3.2、Github下载源码编译  
  
方便工具使用管理，一般会单独放在一个目录下，比如tools，安装命令如下：  
> 如果git clone方式，因网络问题无法正常下载，可直接到github上下载后再复制到kali 虚拟机。  
  
```
```  
  
在编译这个步骤预计10~20分钟，具体看网速而定，如果网速不好的话，这个步骤会卡很久，卡很久可能是异常了【详见3.3、Github下载源码编译异常处理】。  
  
编译完后就可以使用命令确认是否正常使用。  
```
```  
##### 3.3、Github下载源码编译异常处理  
  
卡在   
go: downloading github.com/zan8in/rawhttp  
 这个地方很久  
没反应  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/YlMg2LW4AJuZUnUz1MTbCUiaDExqKm9hXN2ObC8KicBQmiaWFGGnOFde3WL4kXaXzm4Y3PVDicJIjIdtMuUBSiaNR1g/640?wx_fmt=jpeg&from=appmsg "")  
  
如果没有使用  
Ctrl+C  
命令强制停止，最后会有异常信息如下：  
```
```  
  
把以上报错信息复制去ChatGPT给出的说明是安装和编译 afrog 时遇到了连接问题，无法从 Go 代理服务器下载所需的包。这可能是由于网络问题或代理服务器的问题。  
  
尝试在浏览器中打开   
https://proxy.golang.org  
 是能正常访问。采用更改 Go 代理服务器的方式解决  
```
```  
#### 4、使用说明  
  
使用命令可用   
./afrog -h  
 来查看，这里只列出1个命令和对应2个场景靶场使用示例。afrog和其他一些工具的联动后面我自己测试使用再分享出来。更多用法请参考wiki：  
https://github.com/zan8in/afrog/wiki  
  
在扫描之前，需要先配置  
afrog-config.yaml  
##### 4.0、配置afrog-config.yaml  
  
配置文件目录在  
$HOME/.config/afrog/afrog-config.yaml  
 。详细可参考：  
https://github.com/zan8in/afrog/wiki/Configuration  
  
至少需要配置ceye，api-key和domain 从  
http://ceye.io/  
 获取，自己注册账号。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/YlMg2LW4AJuZUnUz1MTbCUiaDExqKm9hX07XkNl34vPwuGmicMIEGJBnCia6Gaqn1ibh9T61IJgMsZU3qDXCjTeJ2A/640?wx_fmt=jpeg&from=appmsg "")  
  
使用命令vim 打开配置文件，按  
i  
键进入编辑，退出编辑按  
esc  
，保存退出输入  
:wq!  
，仅退出不保存输入  
:q!  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/YlMg2LW4AJuZUnUz1MTbCUiaDExqKm9hXRtsNRJDsaxEWzExU5sSVGhGiaU3DGCZBk04eVahIjeowuImyX7V7dyg/640?wx_fmt=jpeg&from=appmsg "")  
##### 4.1、使用命令  
  
**扫描单个目标：**  
  
默认情况下，afrog 会扫描所有内置 PoC，如果发现任何漏洞，它会自动创建 HTML 报告，  
以扫描日期作为文件名，并且在web端【需启用web服务才可看】展示出来；如果没有发现漏洞不会生成报告。  
```
```  
  
扫描的结果在  
/reports  
目录下，或使用命令  
./afrog --web  
 启动web服务查看漏洞报告。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/YlMg2LW4AJuZUnUz1MTbCUiaDExqKm9hXOkNZmT5iaFxYZLUF1yyuDeEkJqQ356qQ7fgaEaT5Lf0YJaerOUHJjyQ/640?wx_fmt=jpeg&from=appmsg "")  
> 注意：扫描结果不一定完全准确，可结合其他信息收集或检测一起。  
  
  
以下演示基于  
在线靶场：  
https://vulfocus.cn/  
，靶场启动后20分钟内有效。  
##### 4.2、无漏洞示例  
  
在线靶场搜索SQL注入编号：  
CVE-2022-28346  
，启动靶场。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/YlMg2LW4AJuZUnUz1MTbCUiaDExqKm9hXKia5EMehOibaianqdV4Fd0IUYevrLcjQlrAicDGj3IOPTrhpBM9Yia9lLAA/640?wx_fmt=jpeg&from=appmsg "")  
  
**执行命令结果如下：**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/YlMg2LW4AJuZUnUz1MTbCUiaDExqKm9hXTCeKTxpeHt6jicSbJAntBrRHXKuogeTb9vhygT5m9WcAK4XDt3oBfKg/640?wx_fmt=jpeg&from=appmsg "")  
  
到reports目录下查看没有生成  
xxx.html  
文件。  
  
**分析原因：**  
 漏洞编号  
CVE_2022_28346  
在afrog收录的pocs里面有没有记录，所以就扫描不出来。  
##### 4.3、有漏洞示例  
  
先在github上的pocs记录上取一个  
CVE-2020-14750  
，再到在线靶场搜索，启动靶场，得到测试地址。  
  
**执行命令结果如下：**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/YlMg2LW4AJuZUnUz1MTbCUiaDExqKm9hXkbbmn45ntfTLL6Khiag6x31gGoPVek8WDRbdHhnIicFl1mYcmhGp87RQ/640?wx_fmt=jpeg&from=appmsg "")  
  
访问web端，可以看到列出结果和控制台一样的记录，只不过web端会有更详细的记录可以查看。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/YlMg2LW4AJuZUnUz1MTbCUiaDExqKm9hXIUGOlQGPFSsZNvicS3NR6pE2uOIUUTCq97Mt8xzeTxAkiamrJWcBmqcw/640?wx_fmt=jpeg&from=appmsg "")  
  
以弱口令登录为示例，查看详细，会发现测试弱口令登录成功的账号密码都提供出来了。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/YlMg2LW4AJuZUnUz1MTbCUiaDExqKm9hXXgCFRsKTGnwuKHtmodC8MJWhbn26Xr4fxG7I5icURIX33b94nverFFQ/640?wx_fmt=jpeg&from=appmsg "")  
#### 5、我的公众号  
  
敬请关注我的公众号：大象只为你，持续更新网安相关知识中......  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YlMg2LW4AJvWLHAn2wppibQax8GNaVTdteIeFygxibU9iaLCIaFOagjpibbLDOnlJKQeaN4ygz6zD1xp420x3R4PNg/640?wx_fmt=png&from=appmsg "")  
  
  
