> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMzMwODg2Mw==&mid=2247512801&idx=1&sn=bc1390b991ab475c42a3dcf2072bf910

#  记一次AMD漏洞挖掘：从文件权限配置错误到驱动权限提升  
Ba1_Ma0  李白你好   2025-06-16 00:01  
  
**免责声明：**  
由于传播、利用本公众号李白你好所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号李白你好及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
  
文章作者：先知社区（Ba1_Ma0）  
  
文章来源：https://xz.aliyun.com/news/17962  
  
  
**1**  
►  
  
**AMD**  
  
  
超微半导体公司（Advanced Micro Devices, Inc.），通常缩写为 AMD，是一家总部位于加利福尼亚州圣克拉拉的美国跨国半导体公司，为商业和消费市场开发计算机处理器和相关技术。  
  
  
**2**  
►  
  
**漏洞挖掘过程**  
  
  
在使用PrivescCheck工具收集信息时，发现AMD目录可以被用户修改  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUBEokcBtic8V9SHP89CYeDLiaiaUzI8OCHJgibnwwk6XbLRnFMkoE1BOMTht8WjuiakcjshVO5eUDotJeg/640?wx_fmt=png&from=appmsg "")  
  
  
虽然用户权限只能读取和执行，但Authenticated Users是可以对此文件夹进行修改的  
  
## 什么是Authenticated Users  
  
  
Authenticated Users（已认证用户） 是Windows操作系统中的一个安全主体（Security Principal），代表所有通过系统身份验证的用户或计算机账户  
  
  
意思就是，普通用户可以对AMD文件夹进行读取、执行、修改  
  
## 文件权限配置错误  
  
  
在AMD文件内有两个子文件夹  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUBEokcBtic8V9SHP89CYeDLianmb0QGFHibMkjO0Z4ppesagocyd3L6TDEQQuL9FcSpaV3U7kDP3w5kA/640?wx_fmt=png&from=appmsg "")  
  
  
经研究，AMD-Software-Installer文件夹只是Software程序的安装包目录，不重要，重要的是Chipset_Software文件夹  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUBEokcBtic8V9SHP89CYeDLiao2WEPZVAf1WBozAhYWMv75cbwb76XvFkcahQrtRk1pgP7kibZ9AkDUw/640?wx_fmt=png&from=appmsg "")  
  
  
其内部为AMD驱动安装配置文件，包括驱动inf安装配置文件，驱动sys程序，驱动msi安装  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUBEokcBtic8V9SHP89CYeDLiaPd70FQq3IQpWVTWCcgic9zTyloeQ2b66hXGW1gcIInFKfdhE6R8bMIw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUBEokcBtic8V9SHP89CYeDLiaCXSc0sq2lrsR8wjicsde9Q7ZOwib5BoOqWFnuibsSXaRz4ezODYG1RRzg/640?wx_fmt=png&from=appmsg "")  
  
  
普通用户对此文件夹内所有文件均可访问、执行与修改，最重要的是'修改'这个权限，代表用户可以无条件修改驱动的安装配置文件（.inf），也可以利用msi文件安装恶意程序  
  
## 利用漏洞  
  
  
这里展示普通用户可以随意修改驱动的安装配置文件会造成什么危害，这里用AMD PSP驱动做演示，首先，要读懂它的安装配置文件，文件夹目录：  

```
C:\AMD\Chipset_Software\Binaries\PSP Driver\W11x64
```

  
使用文本编辑器打开amdpsp.inf  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUBEokcBtic8V9SHP89CYeDLiaiciaV6libQwJGvrsRicvPc7KdfXpplL32icAD6uq5245DHB3Ific0kGJRqkg/640?wx_fmt=png&from=appmsg "")  
  
  
INF DestinationDirs Section 是 Windows 驱动程序安装文件（.inf）中的一个重要部分，用于定义文件在目标系统上的安装路径，它指定了驱动程序和相关文件应该被复制到哪个系统目录中，文件默认是从system32drivers目录下导入dll，可以修改配置文件，让它导入用户指定目录下的dll  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUBEokcBtic8V9SHP89CYeDLiajDfKzYpZraNBBqKQJIK4mBR8tUK1W1BFB15mpw1WGDfF8jRs6HA0yA/640?wx_fmt=png&from=appmsg "")  
  
  
修改至从AMDChipset_SoftwareBinariesPSP DriverW11x64目录下导入dll，这个目录可控，能写入恶意dll  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUBEokcBtic8V9SHP89CYeDLiaAohRzicI3KicuOs1UiaGd0KLW8sjJDD47yIvB9iaS4TAqjiaGuZ5ticpfZuA/640?wx_fmt=png&from=appmsg "")  
  
  
这里是安装的sys程序，和移动system32目录下的dll，作用是将指定目录下的amdtee_api64.dll，amdtee_api32.dll移动到system32目录下  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUBEokcBtic8V9SHP89CYeDLiazOBibSXqcLuJTD7VdRbEOkRshNdXhQsMJkHogtPpWpseDX5AsqIMlkQ/640?wx_fmt=png&from=appmsg "")  
  
  
这里通过前面修改的文件夹，可以将AMDChipset_SoftwareBinariesPSP DriverW11x64目录下名为amdtee_api64.dll移动至system32目录下  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUBEokcBtic8V9SHP89CYeDLiaElxmwmGCqFt3XhzXlhxibBH6TC2kPicNy4KsrH7YzxwwvvQtzEicUPmxw/640?wx_fmt=png&from=appmsg "")  
  
  
为了区分，移动后的文件名改为了777.dll  
  
### 更新驱动文件  
  
  
打开计算机管理，依次选择系统工具-设备管理器-安全设备-AMD PSP 11.0 Device，右击选择更新驱动程序  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUBEokcBtic8V9SHP89CYeDLiaSNPZtKYiarqUVKibGIegqaaSwbJiaPpCgWr8DMtP66YI0j7swtYOSRHmA/640?wx_fmt=png&from=appmsg "")  
  
  
选择手动查找并安装驱动  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUBEokcBtic8V9SHP89CYeDLiaFKUKric1KXDbzJLUREChcM6niamJza6yOJ16DiaPkQticFbTVXxibXibzLJg/640?wx_fmt=png&from=appmsg "")  
  
  
选择从本地获取  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUBEokcBtic8V9SHP89CYeDLiadANTQfclmdKN9TIHEOmDoIDYYvx6jvDT470YuYKy2giaIQvla36UEWw/640?wx_fmt=png&from=appmsg "")  
  
  
找到AMDChipset_SoftwareBinariesPSP DriverW11x64目录下的amdpsp.inf并点击确定  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUBEokcBtic8V9SHP89CYeDLiaroyKXibEyD5YLagpIKP1HrBRhs76SCjVjEXjA0WIfHWXEgRqlUyeo2Q/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUBEokcBtic8V9SHP89CYeDLiaGGPXDwE4Y6BicsZnTm2QJCd4Y95SFu1q64ExSCXdkYyk65qujicrVX4Q/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUBEokcBtic8V9SHP89CYeDLiabQGuDZz6r6iaCUl84S0wSbvl7CCbjkU2Uia6CkY5yUJe6DyeKLYDiaHvg/640?wx_fmt=png&from=appmsg "")  
  
  
打开system32文件夹，成功将恶意文件移动至此目录  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUBEokcBtic8V9SHP89CYeDLiaPGqrmHuvia63pMQ2UxgkB6g0ARmMPMmxfzudvP7zL395KZMaDSiaUIIw/640?wx_fmt=png&from=appmsg "")  
  
  
这里只是验证其中的一个文件移动操作。  
  
  
**3**  
►  
  
**提权漏洞挖掘**  
  
  
通过前面的文件权限配置错误，检查AMD当前运行的驱动文件目录是否可以被修改  
  
  
遗憾的是，正在运行的驱动文件夹也可以被修改  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUBEokcBtic8V9SHP89CYeDLiaLmgNumA28RvoiaE0s9lay9JYtAcGHy2c9NJfbIQkA4PreJL7eohhshg/640?wx_fmt=png&from=appmsg "")  
  
  
下图是其他正常驱动目录的配置权限，只有system权限才能完全控制  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUBEokcBtic8V9SHP89CYeDLiawd8iacpjunScI0AOaVQHAYCp0HhficamGcmmBHpQoHpXibFOFfdrwfRsw/640?wx_fmt=png&from=appmsg "")  
  
  
AMD External Events Service Module 存在一个权限提升漏洞，其中 atiesrxx.exe 会从当前目录加载一个不存在的 DLL（MSASN1.dll）到程序栈中执行。需要注意的是，由于用户可以修改驱动程序文件夹，而该文件夹中的内容会以系统权限执行，攻击者可利用此漏洞在本地机器上获取系统权限。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUBEokcBtic8V9SHP89CYeDLiaDhf5m7giaosE9x67GrHx6aZIagNXTyib6Yyh0nJ13CG8hMPcAycibghFg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUBEokcBtic8V9SHP89CYeDLiaKicsSiaK19vt3QZ2OL6AImu8rIkA8CY98ia9VxdmHNmkibMA89z9heOMbQ/640?wx_fmt=png&from=appmsg "")  
  
  
当 AMD External Events Service Module（atiesrxx.exe）运行时，它会从当前目录加载一个不存在的 DLL（MSASN1.dll）并在栈中执行。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUBEokcBtic8V9SHP89CYeDLia0rsAomkj2SJWeoLtouWUyOJWx0wLnSAfySwzhURMMBTmHQGW1cj5xA/640?wx_fmt=png&from=appmsg "")  
  
  
编写一个用于验证漏洞的 DLL，并将其重命名为 MSASN1.dll。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUBEokcBtic8V9SHP89CYeDLiavlicHwibtKKrtxx2rxiaJMzf6fMnb872IVEXHlMG8S8f2KrGibhtLB2sfA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUBEokcBtic8V9SHP89CYeDLiaZDXaMK5b5P8Psp0MdGHLrHtlns9ajARaDmHibx7bnI2suibxGXhhqCdw/640?wx_fmt=png&from=appmsg "")  
  
  
将 MSASN1.dll 移动到 AMD External Events Service Module 的驱动程序文件夹中。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUBEokcBtic8V9SHP89CYeDLiaMycGx0brAmXib5v5ibnxG5z0zuzibcmAY4XL9ASO0D39LKppgyUdBZ78Q/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUBEokcBtic8V9SHP89CYeDLial5cPlL61xnCZ2Qzr5AEHVMZOUB1N5v04qJia6ciaA3zGWibfUhtowj8qQ/640?wx_fmt=png&from=appmsg "")  
  
  
重启服务后，  
恶意 DLL 成功以系统权限加载并执行。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUBEokcBtic8V9SHP89CYeDLiaLjVsiaicAsv7Xiaicf6wEBoyqbJYnOfsxCXyLZIZnwH8D5UA6g0Tb4G6sg/640?wx_fmt=png&from=appmsg "")  
  
  
因为服务是开机自启动的，所以还可用作权限维持  
  
  
提交赏金漏洞，官方回应  
问题出在 AMD 芯片组驱动程序软件的安装程序中，不在赏金范围内  
，但后续  
更新会发布安全公告或简报  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUBEokcBtic8V9SHP89CYeDLiac3Ac8a47nCtUicZEyDMhQxicoXkK6ez5z7ptceRyBzM6YQz6t47r5Plg/640?wx_fmt=png&from=appmsg "")  
  
  
  
**4**  
►  
  
**网安资源社区**  
  
  
李白你好VIP社区-  
网络安全资源社区  
  
https://www.libaisec.com/  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUBEokcBtic8V9SHP89CYeDLiaUNPLXJ2hWqGFsGdc7KrRIj2S5PAw97VgGZ8KvVe2prvvQsV5xOiaUEQ/640?wx_fmt=png&from=appmsg "")  
  
[情报 | 攻防 | 渗透 | 线索 | 资源社区](http://mp.weixin.qq.com/s?__biz=MzkwMzMwODg2Mw==&mid=2247511326&idx=1&sn=78f9ccdbc0ea7a06e0f4ab368d5a89f3&chksm=c09ade4ef7ed5758fde517714213faadcd67e5e7c55eda452d581da294a8c396bb1db889042f&scene=21#wechat_redirect)  
  
  
  
