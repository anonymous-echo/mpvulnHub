#  字节跳动IoT产品漏洞奖励计划V1.0   
 字节跳动安全中心   2023-08-22 11:34  
  
字节跳动IoT产品漏洞奖励计划  
  
正式上线啦！  
  
🎉  
  
欢迎IoT大佬们多多关注！  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/gAcolpf06WrMH74TltYPHxdRzEKZ1s27a89w9ujeEbDCicupiahYc6ibavnDDFGLicHWJsGicMuPPZHK0GpbeOianIwg/640?wx_fmt=gif "")  
  
**奖励计划范围**  
  
  
  
  
产品类型：VR设备  
  
型号：PICO 4、PICO 4 Pro  
  
     
  
PICO非IoT类漏洞  
  
按照《字节跳动安全响应中心安全报告处置规则V5.0》收取  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/gAcolpf06WrMH74TltYPHxdRzEKZ1s27a89w9ujeEbDCicupiahYc6ibavnDDFGLicHWJsGicMuPPZHK0GpbeOianIwg/640?wx_fmt=gif "")  
  
**漏洞评分标准**  
  
  
  
  
根据漏洞的危害程度将其等级分为【严重】、【高危】、【中危】、【低危】四个等级。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/gAcolpf06WrMH74TltYPHxdRzEKZ1s27uQwIxe0V6WUrDx5ic55k2h3WtcHa8hUrUHMlW2901xUmIgwxqBUnnNg/640?wx_fmt=gif "")  
  
严重漏洞  
  
1、绕过安全启动机制     
  
2、解锁bootloader     
  
3、在未经授权的情况下访问受TEE保护的数据  
在特权进程或TEE中远程执行任意代码（绕过系统安全缓解措施）     
  
4、无需交互，远程静默安装APK     
  
5、在未鉴权的情况下远程访问任意受保护的数据（利用漏洞能够达到作为特权进程访问任意数据的效果）     
  
6、升级/刷入非官方签名的可启动镜像      
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/gAcolpf06WrMH74TltYPHxdRzEKZ1s27uQwIxe0V6WUrDx5ic55k2h3WtcHa8hUrUHMlW2901xUmIgwxqBUnnNg/640?wx_fmt=gif "")  
  
高危漏洞  
  
1、在普通应用进程中远程执行任意代码    
  
2、通过本地可在特权进程中执行任意代码     
  
3、绕过将应用数据与其他应用隔离开的安全机制     
  
4、绕过将用户或个人资料彼此隔离开的安全机制     
  
5、在未鉴权的情况下远程访问受保护的数据（指应用在请求并获得权限后才可以访问的数据）      
  
6、本地绕过用户交互实现静默安装     
  
7、绕过系统屏幕锁     
  
8、越权或绕过系统保护机制，直接访问设备传感器数据和相机图像（包括但不限于眼部/面部相机、SLAM相机、透视相机以及IMU数据，相机图像含原始图像或合成图像。）      
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/gAcolpf06WrMH74TltYPHxdRzEKZ1s27uQwIxe0V6WUrDx5ic55k2h3WtcHa8hUrUHMlW2901xUmIgwxqBUnnNg/640?wx_fmt=gif "")  
  
中危漏洞  
  
1、在受限进程中远程执行任意代码     
  
2、通过本地可在普通应用进程中执行任意代码  
  
3、在未鉴权的情况下远程访问不受保护的数据，可在一定条件下对用户造成危害（指本地安装的所有应用不申请权限即可访问的数据）     
  
4、在未鉴权的情况下本地访问受保护的数据（指本地安装的应用需要请求并获得权限后才可以访问的数据，或仅限特权进程访问的数据）      
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/gAcolpf06WrMH74TltYPHxdRzEKZ1s27uQwIxe0V6WUrDx5ic55k2h3WtcHa8hUrUHMlW2901xUmIgwxqBUnnNg/640?wx_fmt=gif "")  
  
低危漏洞  
  
1、通过本地可在受限进程中执行任意代码     
  
2、通过本地发起的永久性拒绝服务攻击导致设备无法再使用     
  
3、不安全的加密算法及密钥存储，可导致敏感信息泄露等危害（根据影响程度，调整风险等级）  
  
4、无需用户交互即可开启或关闭通常由用户才能发起的功能，或需要获得用户许可后方可使用的功能  
（根据影响程度，调整风险等级  
）  
      
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/gAcolpf06WrMH74TltYPHxdRzEKZ1s27a89w9ujeEbDCicupiahYc6ibavnDDFGLicHWJsGicMuPPZHK0GpbeOianIwg/640?wx_fmt=gif "")  
  
**漏洞奖励**  
  
  
  
  
严重3级：45000元严重2级：37500元严重1级：30000元  
  
  
高危3级：25000元高危2级：22000元高危1级：20000元  
  
  
中危3级：2000元中危2级：1600元中危1级：1200元  
  
   
  
低危3级：180元低危2级：120元低危1级：60元  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/gAcolpf06WrMH74TltYPHxdRzEKZ1s27a89w9ujeEbDCicupiahYc6ibavnDDFGLicHWJsGicMuPPZHK0GpbeOianIwg/640?wx_fmt=gif "")  
  
不在奖励计划范围内的漏洞  
  
  
  
  
1、低影响DOS：没有安全影响的软件功能性错误、应用程序级别的崩溃、简单的提示性弹窗、重启可以解决的本地拒绝服务、临时性的Framework重启；  
  
2、缺少证书绑定；受TLS保护下的URL/request body中敏感数据传输；  
  
3、普通权限app无法访问到的敏感信息存储；对用户无实际影响的日志数据、系统测试数据等 ；  
  
4、用户数据未经加密存储于外部存储设备中(带有敏感信息的APP日志以及已经承诺了加密存储的用户数据除外)；  
  
5、APP缺少代码混淆保护，APK可以被重打包，APP中含有硬编码或可恢复的秘钥，安卓APP中缺乏二进制保护控制；  
  
6、所涉及漏洞在利用过程中依靠在内容上欺骗用户（例如钓鱼、诱导点击等）配合交互，并且交互次数2次及以上，我们不会对需要此类利用场景的漏洞进行奖励；  
  
7、通过物理接触，破坏设备硬件完整性才可以发起的攻击；只能在老版本固件/硬件成功利用的漏洞，只存在于非奖励计划机型上的漏洞；  
  
8、在开发者模式下发起的攻击（影响较大的可例外评估，如提权漏洞）；  
  
9、同时影响其他业界设备的开源及第三方漏洞（对设备影响较大的漏洞可例外评估）；  
  
10、在上报漏洞之前，该漏洞的技术细节（如：POC等信息）已经公开，包括但不限于网站、自媒体、邮件组、公开演讲、即时聊天群等，此类漏洞无法参与漏洞奖励计划；  
  
11、多人或同一人提交重复的漏洞场景/同样的漏洞成因，第一个提交的漏洞报告被视为有效，其他被视为不符合资格；由于硬件、系统及架构相关漏洞修复发版周期较长，相关漏洞（含nday漏洞）重新收取的时间以内部安全工单修复完成时间为准。  
  
12、当涉及的漏洞需要依赖某些权限才可被成功利用并造成影响，而该权限本身就可以造成同样效果，这样的情况我们不会进行奖励；  
  
13、只是提到存在漏洞的可能性但未提及利用方式，或者是无实际危害证明的扫描器结果，以及基于非法获得的机密信息所做的漏洞报告；  
  
14、上报漏洞需要在最新公开版本的，并且使用标准默认配置的设备操作系统上可复现，且使用的是最新可用的硬件环境，否则无法获得奖励。  
  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/gAcolpf06WrMH74TltYPHxdRzEKZ1s27a89w9ujeEbDCicupiahYc6ibavnDDFGLicHWJsGicMuPPZHK0GpbeOianIwg/640?wx_fmt=gif "")  
  
降级场景  
  
  
  
  
1、无法稳定复现的漏洞；  
  
2、需要交互的利用，例如钓鱼风险需要受害者进行点击链接、查看消息等；  
  
3、部分环节与其他漏洞重复的漏洞 ；  
  
4、影响范围非常小，比如某些系统只有几十个注册用户或者活跃用户、旧系统只有少量数据；  
  
5、利用条件苛刻（如：特殊账号权限才能发现利用的漏洞等）或人力、时间成本与实际危害明显不匹配的漏洞；  
  
6、利用场景复杂：所涉及漏洞依赖一个小概率出现的场景才能被利用实施攻击造成危害（如：爆破），该类漏洞会酌情降低风险等级，或者无法被认定为漏洞；  
  
7、漏洞已被消减：所涉及漏洞已有消减措施，并且无法提供绕过消减措施的方法，该类漏洞会酌情降低风险等级，或者无法被认定为漏洞；  
  
8、需要解锁引导加载程序才能进行本地攻击；  
  
9、  
默认配置或选项造成安全隐患的，依据影响酌情调整风险等级；  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/gAcolpf06WrMH74TltYPHxdRzEKZ1s27a89w9ujeEbDCicupiahYc6ibavnDDFGLicHWJsGicMuPPZHK0GpbeOianIwg/640?wx_fmt=gif "")  
  
名词说明  
  
  
  
  
**远程：**指通过Internet在不安装应用或不实际接触设备的情况下利用漏洞实施攻击。  
  
**局域网：**指通过路由器WiFi/WLAN网络在不安装应用或不实际接触设备的情况下利用漏洞实施攻击。  
  
**本地：**指利用漏洞实施攻击需要在受害系统中安装应用，或者需要物理接触设备。  
  
**受限进程：**比普通应用进程受到更严格的权限约束，或运行在高度受限的SElinux(或SEAndroid)域中执行的进程。  
  
**普通应用进程：**指在SELinux(或SEAndroid)的untrusted_app或platform_app域中运行的应用或进程，例如第三方应用进程或内置的无system级别权限的应用进程。  
  
**特权进程：**指在SELinux(或SEAndroid)的system_app域中运行的应用或进程，也包括以system级别的权限运行的进程和root权限进程。  
  
**TEE:**Trusted Execution Environment的简称，与设备上的安卓系统并存，主要用来给安卓提供可信计算、可信存储等安全服务的运行环境。  
  
  
  
