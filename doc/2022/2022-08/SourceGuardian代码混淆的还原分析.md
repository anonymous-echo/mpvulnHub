#  SourceGuardian代码混淆的还原分析   
原创 数据安全实验室  山石网科安全技术研究院   2022-08-24 10:09  
  
#   
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Gw8FuwXLJnRiaic8BVIxZxJicozibmq4MXeEuicTP5vrISDD29Sn20cqVCtBFxicxgiaczQTomCIsFqLmWMXlXTzgg7QQ/640?wx_fmt=gif "")  
  
 1.  前 言   
  
  
#   
  
  
最近无意中拿了两套源码，刚想审计时发现控制器等主逻辑文件做了混淆，内容如：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRiaic8BVIxZxJicozibmq4MXeEsIK1Tiaqib5ug0XyicUBpXiaRZfLe5S8KgeG2hHMcOQJkN7W0IxxyuxLiaQ/640?wx_fmt=png "")  
  
  
图  
1  
   
混淆代码  
  
  
简单尝试后发现我解混淆的能力不足以解开这串东西，于是简单搜索了一些关键字，如sg_load  
这个函数，会发现这种混淆是一个名为  
SourceGuardian  
的  
php  
拓展，  
sg_load  
源自该拓展的某个函数，搜索了一下发现网上的解密都是需要人工解密，自然并不会免费提供，根据某些文章记叙是利用  
php vld   
扩展显示  
opcode  
去解密  
sg11  
。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Gw8FuwXLJnRiaic8BVIxZxJicozibmq4MXeEuicTP5vrISDD29Sn20cqVCtBFxicxgiaczQTomCIsFqLmWMXlXTzgg7QQ/640?wx_fmt=gif "")  
  
 2. sg11   
  
  
  
  
拿到源码后本想搭建起来玩玩，但奈何验证码功能跑不了，源码又加密改不了，单独访问后发现是SourceGuardian  
在作祟，需要我本地也安装一个拓展。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRiaic8BVIxZxJicozibmq4MXeEPRIN5F9ibQ0BicZOGhym0MgRBYnsM57Rdib5IRTwPoJ60VzsjwocWvWdg/640?wx_fmt=png "")  
  
  
图  
2   
报错  
  
  
安装起来倒是简单，官网：  
https://www.sourceguardian.com/loaders/download.php  
  
直接把我们的phpinfo  
内容贴到上面进行探测，随后会给出对应系统对应的方案，例如我是  
macos  
下的  
php7  
环境，他首先给出我所缺的拓展的下载链接。  
  
将拓展丢到拓展目录下，修改配置，加上extension=ixed.7.0.dar  
，重启服务器即可，其实就是普通的添加一个  
php  
拓展的操作。  
  
这时候再去访问发现站点已经能够正常运行了，但是缺少域名授权，进不去后台，简单尝试一番，发现还是只能从源码的解混淆入手。  
  
#   
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Gw8FuwXLJnRiaic8BVIxZxJicozibmq4MXeEuicTP5vrISDD29Sn20cqVCtBFxicxgiaczQTomCIsFqLmWMXlXTzgg7QQ/640?wx_fmt=gif "")  
  
 3. vld 拓展   
  
  
#   
  
项目地址：  
https://github.com/derickr/vld.git  
  
依次使用：phpize  
、  
./configure  
、  
make && make install  
即可编译好  
vld  
拓展，将拓展添加到配置文件内即可。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Gw8FuwXLJnRiaic8BVIxZxJicozibmq4MXeEuicTP5vrISDD29Sn20cqVCtBFxicxgiaczQTomCIsFqLmWMXlXTzgg7QQ/640?wx_fmt=gif "")  
  
 4.  分析  
  
  
  
SourceGuardian  
它会将源代码编译为混淆过的  
opcode  
，然后丢入  
sg_load  
函数内执行，要解密只能从  
opcode  
入手，通常来说，  
sg  
加密都是会在文件末端调用如：  
return sg_load('12345678CHECKSUM/BASE64/BASE64/BASE64/BASE64=');  
  
  
那么在解混淆时用到的一个方案就是利用vld  
去将代码转为  
opcode  
，通过手动逆向  
opcode  
去还原代码，然而在最终触发点为  
sg_load  
的源码中我无法复现这一操作，因为转出来的  
opcode  
最最终只会呈现为调  
sg_load  
，而参数为我想获得的代码的  
opcode  
，如：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRiaic8BVIxZxJicozibmq4MXeEvpdNO4y9upTzicf4gX7VOcoibgqHqCOoqWD6ZLaEhaLI0icL7mAu3ESnw/640?wx_fmt=png "")  
  
图  
3   
opcode示例  
  
  
同时需要明确一点，前面也提到了，sg11  
加密他会对源码的  
opcode  
也进行混淆，而  
vld  
拓展是不具备对混淆后的  
opcode  
做分析的能力，这一点在  
vld  
项目中也是明确提出了。那么我们要解混淆实际上只需要魔改  
vld  
即可，参照：  
https://blog.zsxsoft.com/post/40  
  
  
在一些混淆中只是将php  
代码进行加密，而在  
php  
源码中的  
compile_file  
或者  
compile_string  
函数皆是用于将  
php  
代码转为  
opcode  
，而这些混淆在代码运行时需要进行解密，最后调用的依旧是  
compile  
，此时  
hook  
住函数即可简单取得解密后的  
php  
源码，而  
vld  
拓展  
hook  
的正是这两处，这也正是我们使用  
vld  
时他会原样吐出  
sg_load  
和  
base64  
样式参数的原因，需知道直到  
sg_load  
之前的内容，对我们还原源码而言并没有什么用处，也就是说原生的  
vld  
中关于  
compile  
的  
hook  
输出我们可以直接删减掉。  
  
  
由于opcode  
的调用在于  
zend_execute  
，这也就意味着对于  
sg11  
加密而言，只需要在  
vld_execute_ex  
中调用  
vld_dump_oparray  
输出我们的  
op_array  
即可获取到  
opcode  
。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Gw8FuwXLJnRiaic8BVIxZxJicozibmq4MXeEuicTP5vrISDD29Sn20cqVCtBFxicxgiaczQTomCIsFqLmWMXlXTzgg7QQ/640?wx_fmt=gif "")  
  
 5. Patch   
  
  
  
  
说了这么多，已经有师傅写好这一个vld  
针对  
sg11  
的  
patch  
了：  
https://github.com/clouds-flight/php7-vld-sg11-patch  
  
需要注意的是，patch  
仅作用于  
vld0.17.0  
版本。  
  
patch  
后执行  
php -dvld.active=1 -dvld.execute=0 Index.php  
就能够看到一些比较令人欣慰的内容了：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRiaic8BVIxZxJicozibmq4MXeE3t5yh67MG5omzia9GHVMqBy33BlCUWyOrWVXmxqHwIic7XhoR7xsibh8Q/640?wx_fmt=png "")  
  
  
图  
4   
patch后的opcode  
  
#   
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Gw8FuwXLJnRiaic8BVIxZxJicozibmq4MXeEuicTP5vrISDD29Sn20cqVCtBFxicxgiaczQTomCIsFqLmWMXlXTzgg7QQ/640?wx_fmt=gif "")  
  
 6. 还原代码   
  
  
#   
  
  
到此还没有结束工作，因为要做的内容是还原代码，关于转储的opcode  
需要关注的有几列：  
  
  
line  
、  
#*  
、  
op  
、  
return  
、  
operands  
  
line  
：在代码中的行数  
  
#*  
：  
opcode  
的序号，在上文也提到了输出的是  
op_array  
，也就是说  
opcode  
是以数组的格式进行存储的  
  
op  
：  
opcode  
，最需要关注的一列  
  
return  
：  
opcode  
执行后的返回值  
  
operands  
：参数，对于特殊字符如空格，斜线等进行  
16  
进制编码后加上  
%  
（其实就是  
url  
编码）  
  
  
接下来以一个函数为例说明如何还原：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRiaic8BVIxZxJicozibmq4MXeEelfiatDPNDa837r6f6Q4pQZF3YC2GicKzzR83s86dRKD8VyILFViaTFFA/640?wx_fmt=png "")  
  
  
图  
5   
getreturn函数的opcode  
  
  
首先是第一行Function getreturn  
表明这一部分是  
getreturn  
这一个函数编译出的  
opcode  
，也就是  
getreturn  
函数包括参数，代码，逻辑等都在这一部分呈现。  
  
compiled vars  
指的是  
php  
程序中定义的变量，在此表明这一个函数的参数，而在  
opcode  
中使用  
!n  
来替代参数，这里表明函数有  
code  
、  
msg  
、  
data  
这三个参数。  
  
至于opcode  
可参照：  
https://www.wenjiangs.com/docs/php-7-docs  
  
那么还原也就不难了，函数内容实际上就是初始化一个数组，将三个参数加入数组后作为返回值，即：  
  
function getReturn($code=1,$msg='  
成功  
',$data=null){  
  return array($code,$msg,$data);  
}  
  
#   
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Gw8FuwXLJnRiaic8BVIxZxJicozibmq4MXeEuicTP5vrISDD29Sn20cqVCtBFxicxgiaczQTomCIsFqLmWMXlXTzgg7QQ/640?wx_fmt=gif "")  
  
7. Ref   
  
  
  
  
https://blog.zsxsoft.com/post/40  
  
https://www.sourceguardian.com/loaders/download.php  
  
https://www.xiapilu.com/web/web-tutorial/bt-php-7-4-sg11-ixed-7-4-lin.html  
  
https://gywbd.github.io/posts/2016/2/vld-opcode.html  
  
https://blog.csdn.net/hao508506/article/details/52432116  
  
        
