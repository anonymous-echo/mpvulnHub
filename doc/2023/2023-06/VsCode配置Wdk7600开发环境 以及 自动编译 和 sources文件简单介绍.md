#  VsCode配置Wdk7600开发环境 以及 "自动编译" 和 sources文件简单介绍   
TkBinary  看雪学苑   2023-06-21 17:59  
  
```
```  
  
虽然Wdk7600已经过时，但还是有很多项目是使用Wdk7600编写的，而很多老项目配置环境有很多种方式。如配置在visual studio 中编写，配置在notepad++中编写。搜索全网也没看到有VsCode配置的方式，索性这里就写一下。  
  
   
  
**注意：不讨论文章技术，对你有用你就看，对你无用就无需看，且不要站在现在很多人都用Vs2019 vs2022的IDE去写项目的角度去看，个人写代码用什么IDE都可以，Vs2019也不错，也很推荐。**  
  
   
  
**但本文章也主要讲解WDK7600的配置，很多企业人员有很多项目为了稳定不会贸然升级驱动，所以WDK7600用的还是蛮多。**  
  
****### 1.2 软件安装  
  
如果配置此环境请下好以下软件：  
  
◆1.WDK7600(在官网中表示为wdk 7.1.0)Wdk7600导航连接  
（https://learn.microsoft.com/en-us/windows-hardware/drivers/other-wdk-downloads）  
  
◆2.VsCodeVsCode 官网  
（https://code.visualstudio.com/）  
  
◆3.VsCode中的C++插件  
  
  
请将 Wdk7600 安装到默认目录等熟悉后可以将其修改为你自定义的目录，或者先通读此片文章之后再进行配置。  
  
### 1.3 开发环境配置步骤  
  
◆1.添加路径包含项  
  
  
```
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GVfxmI0UEPyCJxP3sNfOmwco4tN59FGkSydxCkjgEhecf13QDIAP7cOzHibhqLJwJ29NuM4u7fs5Q/640?wx_fmt=png "")  
  
  
◆2.新建一个驱动文件，和对应sources文件，查看是否可以使用驱动文件。  
  
  
sources文件内容如下：  
  
```
```  
  
  
  
driver.c文件内容如下：  
  
```
```  
  
  
  
在命令行中启动编译环境，然后cd到驱动文件所在目录，直接输入 build -cez 或者 bld即可。  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GVfxmI0UEPyCJxP3sNfOmwuD3DIPHF8ueQSEV8Ewte6icVc8VWwwibSzmsocibqaw7t3PtPwtsCpWicQ/640?wx_fmt=png "")  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GVfxmI0UEPyCJxP3sNfOmw5iaMFh9vopUKBjy2DMS0AwC2ukekhxBiatPzUMvnUTAnPIgJgqEvG0jA/640?wx_fmt=png "")  
  
   
  
可以看到可以正常输出。到这一步说明VsCode的开发环境已经配置好了，可以放心写代码了。  
  
   
  
但有一点不足，每次编译都要另外一个CMD窗口启动吗？这样显得会很麻烦，如果能集成到VsCode中那么是不是就很好了。  
  
### 1.4 集成终端编译  
#### 1.4.1 集成任务  
  
这一点经过我的研究已经实现. 我们需要使用VsCode中的任务在VsCode中有一个 终端，终端选项中有一个配置任务(task) 我们只需要生成一个task，然后将task替换为我给的即可。  
  
   
  
注意，这里使用的路径是默认路径，如果你修改过wdk的安装目录，请手动更改此json。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GVfxmI0UEPyCJxP3sNfOmwvVJNehkUiaZS1wR4f8oYuBXhBrFL1VHCgX6G4hhJ8DeSQSicUhJG3agg/640?wx_fmt=png "")  
  
生成的tasks.json使用我给定的即可。  
  
  
```
```  
  
####   
#### 1.4.2 设置为全局任务  
  
上面生成好的task.json 请放到  
  
C:\Users\YourComputerName\AppData\Roaming\Code\User  
  
  
如下图所示：![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GVfxmI0UEPyCJxP3sNfOmwcoVc6nqBrWRgkI0O0aeMr3IvIpVIUk9TKM3GeCsAj0WUe7IUo7O6jA/640?wx_fmt=png "")  
  
  
   
  
最后 在终端中运行任务. 任务则选择你配置好的编译环境即可。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GVfxmI0UEPyCJxP3sNfOmwLs1G6SVNGBXleuwjyUUzWricdMltGhQDXXyo6mIXSPY5FiaicKjwRu6BA/640?wx_fmt=png "")  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GVfxmI0UEPyCJxP3sNfOmwrzxHSxuyeWI3QM5zjffbqkwZJd8l3Pfs75SXnB9fibDAq3iaDOQrLBMQ/640?wx_fmt=png "")  
  
   
  
在终端的右侧则有你运行的任务，现在你可以在你想要的任务中运行 bld 命令进行编译。  
  
   
  
再也不需要单独打开一个cmd窗口进行编译了。  
  
   
  
如你想要编译 win7release64版本则切换到此任务编译即可，想编译32位版本则切换到32即可，任务可以开多个，需要哪个在那个里面执行 bld命令即可。  
  
  
  
```
```  
  
下面的内容可看可不看，我是写到一起做个记录。  
### 2.1 INCLUDES 字段  
  
**主要作用: 处理Include与CPP文件分离得情况**  
  
   
  
场景：  
  
   
  
目录A存放着 xxx.h文件.  
  
   
  
目录B(主目录)存放着 xxx.cpp得实现文件；  
  
   
  
目录B中有目录A；  
  
   
  
那么对应sources应该改为如下：  
  
```
```  
  
  
  
目录A则是 test1  这里主要使用了INCLUDES命令指明了 .h所在得目录。  
  
   
  
当然也可以指向系统得目录：  
  
```
```  
  
  
  
◆目录A(test1)中 .h文件内容如下：  
  
  
```
```  
  
  
  
◆主目录实现.cpp内容如下  
  
  
如果sources中不使用INCLUDES知名.则会报错,无法找到xxx.h 亦或者 .h和.cpp都放在同一目录下.(主目录下) 则不需要使用INCLUDES  
### 2.2 i386_SOURCES 32位驱动使用内联汇编  
  
  
◆**用法一，cpp中使用内联汇编**  
  
  
在32位驱动中可以让我们使用内联汇编。  
  
   
  
设:  test.cpp test.h driver.cpp都在同一目录，所以不需要使用 INCLUDES字段了。  
  
   
  
例子如下：  
  
   
  
Driver.cpp  
  
```
```  
  
  
  
test.h  
  
```
```  
  
  
  
test.cpp (内部使用了内联汇编)  
  
```
```  
  
  
  
◆用法二 直接指定 .asm文件  
  
  
上面是使用得内联汇编,如果我们想将自己写好得 纯 asm文件也参与编译。  
  
   
  
那么需要写为如下：  
  
```
```  
  
  
  
注意：xxx.asm一定要在 i386目录下，如果没有此目录我们需要新建一个目录，存放我们得.asm文件。  
  
   
  
如果想要使用 xx.asm中的函数，那么只需要声明即可。  
  
  
```
```  
  
  
  
test.asm 如下：  
  
```
```  
  
###   
### 2.3 AMD64_SOURCES  使用64位汇编  
  
上面讲了32位汇编的使用，在64位下已经无法使用内联汇编了，需要我们单独提供汇编然后参与编译。  
  
   
  
这里就使用到了AMD64_SOURCES  
  
   
  
**注意：xxx.asm 必须放在相对于主目录下的 asm64目录下。**  
  
   
  
文件内容如下：  
  
```
```  
  
  
  
start.cpp 是驱动的代码,(DriverEntry) 如果想要在DriverEntry中使用那么我们就要声明 xxx.asm中的函数才可以，且需要声明为 fastcall  
  
   
  
asm测试代码：  
  
```
```  
  
  
  
start.cpp实现：  
  
```
```  
  
  
  
目录结构为：  
  
```
```  
  
###   
### 2.4 多驱动编译  
  
如果驱动项目较多，想一下全部进行编译，那么就需要使用 DIRS字段。  
  
   
  
编译方法如下：首先建立一个DIRS文件. 文件的内容指明你想编译的驱动的文件目录即可。  
  
但是你的目录里面要指明sources文件.亦或者是新的DIRS.  
  
DIRS  
  
```
```  
  
  
  
上述意思代表编译 A B C 三个文件目录下的驱动如果A目录下有SOURCES则会读取SOURCES文件进行编译.A目录，如果B目录又有内嵌的文件夹且有DIRS 那么会优先读取DIRS继续寻找B目录中的内嵌文件夹，直到找到有SOURCES存在的目录进行编译。  
  
### 2.5 编译等级设置  
  
如果你想让你的驱动编译的时候检测严格一点，则可以在SOURCES中定义如下字段。  
  
```
```  
  
  
  
/W3 是警告级别 /W1 /W2 /W3 /W4 /W4等级最为严格. 如果参数不使用则需要使用UNREFERENCED_PARAMETER(pDriverObj)；来进行包含，否则在/w4登记下无法编译通过。  
  
/WX 是警告视为错误。  
  
### 2.6 将驱动编译为库  
  
驱动代码也可以变成库代码，可以给别的驱动使用，在高版本中的VS则直接生成即可，wdk7600则必须我们使用 sources指定了。  
  
   
  
分为以下几点讲解：  
  
我们可以将我们的驱动编译为库，这里涉及到库开发。  
  
   
  
分别是：  
  
1.驱动中如何生成库  
  
2.驱动中如何使用自定义的库  
  
#### 2.6.1 驱动中如何生成库  
  
首先如果你是以C/C++ 开发的话 那么就要给一个.h和一个.cpp文件。  
  
假设以 test.h test.cpp为例，那么驱动的sources文件内容应该如下：  
  
```
```  
  
  
  
其中我的目录结构为：  
  
```
```  
  
  
  
test.h如下：  
  
```
```  
  
  
  
test.cpp  
  
```
```  
  
  
  
生成后则会生成test.lib库。  
  
#### 2.6.2 驱动中使用库  
  
使用库就很简单了，将头文件拷贝过来，然后在SOURCE里面指明即可。  
  
   
  
sources如下：  
  
```
```  
  
  
  
test.h同上一样，Driver.cpp如下：  
  
```
```  
  
  
  
如果是C语言则直接编译即可。  
  
  
关于TARGETLIBS 还可以包含路径，例如如下:  
  
```
```  
  
###   
### 2.7 C常量定义  
  
在SOURCES文件中可以使用 C_DEFINES，  
  
它的意思则是等价于你在.c文件中使用了#define来声明宏。  
  
```
```  
  
  
  
例子2：  
  
```
```  
  
###   
### 2.8 SOURCES指明编译的文件 以及条件宏  
  
WDK中找的，可以为驱动编译资源可以定义两个SOURCE分别指向要编译的文件然后最终引用。  
  
  
例子：  
  
```
!
if
$(IA64) 
    
xxxxx 条件使用 IA64
!endif
DIR_SOURCES
=
wacompen.c  \
            
wacompen.rc \
            
oempen.c    \
            
errcodes.mc
STB_SOURCES
=
hid.c    \
            
pnp.c       \
            
serial.c    \
            
errlog.c
SOURCES
=
$(DIR_SOURCES) $(STB_SOURCES)
```  
  
###   
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GVfxmI0UEPyCJxP3sNfOmwH6Tg6oo9u108xJyZUTmeepIzsO9GRMYYIOSxmSxsYw3omicugCS35tg/640?wx_fmt=png "")  
  
  
**看雪ID：TkBinary**  
  
https://bbs.kanxue.com/user-home-302697.htm  
  
*本文为看雪论坛优秀文章，由 TkBinary 原创，转载请注明来自看雪社区  
  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458499288&idx=1&sn=b2b9cd6ff7388a8658d254e13c72f9ad&chksm=b18e885286f9014436a590f2531fda167be67e1e227ea395812968e828932bd44eade34b0dbf&scene=21#wechat_redirect)  
  
  
**#****往期推荐**  
  
1、[在 Windows下搭建LLVM 使用环境](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458500602&idx=1&sn=4bcc2af3c62e79403737ce6eb197effc&chksm=b18e8d7086f9046631a74245c89d5029c542976f21a98982b34dd59c0bda4624d49d1d0d246b&scene=21#wechat_redirect)  
  
  
2、[深入学习smali语法](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458500599&idx=1&sn=8afbdf12634cbf147b7ca67986002161&chksm=b18e8d7d86f9046b55ff3f6868bd6e1133092b7b4ec7a0d5e115e1ad0a4bd0cb5004a6bb06d1&scene=21#wechat_redirect)  
  
  
3、[安卓加固脱壳分享](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458500598&idx=1&sn=d783cb03dc6a3c1a9f9465c5053bbbee&chksm=b18e8d7c86f9046a67659f598242acb74c822aaf04529433c5ec2ccff14adeafa4f45abc2b33&scene=21#wechat_redirect)  
  
  
4、[Flutter 逆向初探](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458500574&idx=1&sn=06344a7d18a72530077fbc8f93a40d8f&chksm=b18e8d5486f904424874d7308e840523ebfb2db20811d99e4b0249d42fa8e38c4e80c3f622c6&scene=21#wechat_redirect)  
  
  
5、[一个简单实践理解栈空间转移](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458500315&idx=1&sn=19b12ab150dd49325f93ae9d73aef0c4&chksm=b18e8c5186f90547f3b615b160d803a320c103d9d892c7253253db41124ac6993d83d13c5789&scene=21#wechat_redirect)  
  
  
6、[记一次某盾手游加固的脱壳与修复](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458500165&idx=1&sn=b16710232d3c2799c4177710f0ea6d41&chksm=b18e8ccf86f905d9a0b6c2c40997e9b859241a4d7f798c4aeab21352b0a72b6135afce349262&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8GVfxmI0UEPyCJxP3sNfOmwWqNz1tqib05anuhr6YqCVFQXnNVVh13LibDgSMG3vqibbibDeuszyicqeRQ/640?wx_fmt=gif "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8GVfxmI0UEPyCJxP3sNfOmwWqNz1tqib05anuhr6YqCVFQXnNVVh13LibDgSMG3vqibbibDeuszyicqeRQ/640?wx_fmt=gif "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8GVfxmI0UEPyCJxP3sNfOmwWqNz1tqib05anuhr6YqCVFQXnNVVh13LibDgSMG3vqibbibDeuszyicqeRQ/640?wx_fmt=gif "")  
  
**球在看**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8GVfxmI0UEPyCJxP3sNfOmwXiaHegvQ7Uvt6I6fA2FT09vwaQXS9Gpb0zYF7aic0dIsIhx0kGMBKSCQ/640?wx_fmt=gif "")  
  
点击阅读原文查看更多  
  
