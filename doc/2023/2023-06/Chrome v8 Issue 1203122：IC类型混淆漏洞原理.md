#  Chrome v8 Issue 1203122：IC类型混淆漏洞原理   
苏啊树  看雪学苑   2023-06-09 17:59  
  
问题出现场景：  
  
假设对象  
A，其偏移  
+10的地方有一个属性  
x，这个属性为数字，同时存在一个  
B对象，这个对象偏移  
+10的地方是一个  
Object对象地址。(  
v8在性能优化的时候会使用对象地址加偏移的方法来直接获取属性，比如在  
IC内联缓存，还有  
JIT优化以后。)  
  
  
实际处理中如果  
A  
，  
B  
对象出现混淆，  
例如在  
v8在JS  
函数调用期待的是处理对象  
A  
的属性  
x  
，并且  
x  
为一个数字类型，如果实际上处理却传入了对象  
B  
，就会根据  
B  
的基址  
+10  
偏移取值，并将其当作  
A  
的数字属性  
x  
返回，这样造成的结果就会将  
B+10  
偏移的对象地址当作  
A  
的属性  
x  
数字返回给  
JS  
调用函数，出现信息泄露。  
  
  ![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GK23qLmrtWotXGxOo2yarXz9w662GDib03GDrbrwWKricPCsXrQ7bkonTjBU65H1icO60FiatmUPnFHA/640?wx_fmt=png "")  
  
  
                                                                                           如图1  
  
  
反过来，如果  
JS  
函数调用期待的是处理  
A  
对象的偏移  
+10  
的属性  
x  
，并且  
x  
为一个对象，如果实际上处理却传入的是对象  
B  
，那么就会根据  
B  
的基址  
+10  
偏移取值，并当作  
A  
的属性  
x  
返回，这样造成的结果就会将  
B+10  
偏移指向的数字，当成  
A  
的属性  
x  
对象返回给  
JS  
调用者，如果  
B  
偏移  
+10  
的这个地址指向我们预先设定的数据，就可以伪造一个对象结构。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GK23qLmrtWotXGxOo2yarXmz9Q58XSK55WQ7tLvR2iaa0kQ47SDjmmaWaqPiamvJF3PtfkLnAE4BeQ/640?wx_fmt=png "")  
  
                                                                                         如图2  
  
# 第一：关于v8内联缓存(IC 缓存)  
##   
## 1.1：v8对于执行一定次数的函数，会对函数操作的对象的属性进行内联缓存(IC)优化。  
  
  
比如函数：  
  
  
```
```  
  
  
  
v8在开始处理这个foo(a)的时候，会进行profiling data和feeback进行收集，然后根据profiing data和feedback的信息进行内联缓存优化。  
  
  
比如我们一直使用 a={x:1}进行foo(a)运算，那么v8会在处理这个foo(a)运行到一定次数后，记录下a的数据结构，然后下次如果再碰到这种foo(a)运算时，直接使用a的地址加上a对象地址与x属性的偏移来进行x属性数据的索引，提升v8运行的效率。  
  
## 1.2：v8使用super关键字来进行对父对象的索引。  
  
  
```
```  
  
  
  
比如上面这段JS代码里面，class A里面定义了prop函数，class B继承了class A，v8是通过super属性来获取class A中的属性x，严格来说，是获得A.prototype.x,然后返回给调用者的，v8有针对这种super索引的父类的情况有做专门的优化处理，这个处理阶段叫做superIC。  
  
## 1.3：还是这段JS代码：  
  
  
```
```  
  
  
  
在这段JS代码中b.m()返回的是class B的super.prop，根据super关键字，v8会去去寻找父对象class A，然后根据class A prototype返回x属性。  
  
也就是说在v8的处理中，b.m()会从class B再找到class A,再从class A的prototype里面找到x属性。  
  
  
理想的v8 superIC处理过程中，这个发起寻找属性的对象，以这个例子来说，这段JS代码中的b对象实例在v8中叫做receiver，然后用一个叫lookup_start_object的对象来标识进行这个寻找过程所用的对象，lookup_start_object先为class B，然后为class A，最后为A.prototype，最后根据class A的prototype中找到x属性，并返回给调用程序。  
  
  
之后如果出现同样的运算，v8会根据lookup_start_object的数据数据结构，利用lookup_start_object加上lookup_start_object与属性x的偏移，并将这个偏移的值取出返回。  
  
  
这里可以看到，receiver和lookup_start_object并不是一个东西，在实际的js中，我们可以通过B.__proto__这样的运算来修改掉B对象里面的super关键字指向的对象，这样可以造成receiver.x和lookup_start_object.x内存布局不一致。  
  
## 1.4 megamorphic  
  
  
如下JS代码：  
  
  
```
```  
  
  
  
如果每次传入的obj都为对象a，那么v8 IC之后，会标记该属性为MONOMORPHIC。如果传入的obj有a对象，b对象两种情况，会标记为POLYMORPHIC，如果大于4种情况，则会标记为MEGAMORPHIC。  
  
# 2.1：简单的漏洞分析  
  
  
```
```  
  
  
  
如上述代码所示，**2.1.1**，一开始运行的时候，因为没有feedback，会命中miss[6]，随后随着调用的增多，代码路径为[0]=>[1]=>[2]。创建feedback，然后执行LoadSuperIC_NoFeedback。  
  
  
**2.1.2**，接着由于feedback的增多，代码执行路径为[1]=>[4]=>[5]。这里的[5]注释已经说明lookup_start_object!=receiver。而在一开始命中miss的时候，输入的参数中有p->receiver()，和p->lookup_start_object()。这里标示了LoadIC_Noninlined(p,lookup_start_object_map,....)也就是期待使用的是lookup_start_object。  
  
  
```
```  
  
  
  
如上述代码所示，在随后的操作中：  
  
  
**2.1.3：**[6]在exit_point->ReturnCallStub()中，却使用p->receiver()来加入具体的函数执行，但如我前面2.1.2所说，v8使用的是lookup_start_object_map，期待的是lookup_start_object，出现了类型混淆(个人认为是因为v8的程序员认为使用p->receiver()和p->lookup_start_object()结果没什么差别)。  
  
## 2.2：poc的构造  
  
  
```
```  
  
  
  
这个poc构造过程如下：  
  
  
   **2.2.1：**创建一个class C,然后创建一个函数m()返回其super对象的prototype属性,也就是执行C.__proto__.prototype运算。  
  
  
   **2.2.2：**将C.__proto__改为指向f函数对象，当执行一定次数的main()以后，就会进行IC优化，此时进行c.m()运算，就会从class C中的m()成员函数进行super.prototype进行访问，最终访问到C的父类Object的prototype,然后会将C.__proto__,也就是函数f标记为lookup_start_object，然返回其prototype，并将lookup_start_object提供给后续的m()调用使用。  
  
  
   **2.2.3：**main中每次都function f(){}然后通过f.prototype来对prototype这个属性进行访问，制造出这个属性MEGAMORPHIC的情况。  
  
  
   **2.2.4：**添加x0,x1,x2,x3,x4属性添加给c。也就是上文所说的receiver，改变receiver的内存结构，使得和lookup_start_object不一致。  
  
  
   **2.2.5：**在触发内联缓存后，使用c.m()访问C.__proto__.prototype，v8正确的做法是使用lookup_start_object也就是函数f返回f.prototype来返回给JS,但实际上我们可以通过上面漏洞的代码片段看出，是使用receiver进行属性的查找，就会将我们设定的0x42424242 / 2代替f.prototype进行返回，并作为f.prototype的类型解析，最终出现了类型混淆报错。  
  
  
但是单靠这点问题没法RCE，这个POC更多的是验证这种代码的问题。  
  
# 2.2.3：漏洞的利用  
  
## 2.2.3.1通过Object对象和String对象进行混淆，然后通过String的length属性进行地址泄露：  
  
  
```
```  
  
  
  
如上所示如果receiver为String对象，在SuperIC过程中，会将receiver传进去，然后执行的为LoadIC_StringWrapperLength。  
  
  
```
```  
  
  
  
通过前面的介绍的漏洞原理，在多次调用f()过程中，会对f()里面对o.m()的过程进行IC优化，并且将这个优化后将O.prototype.__proto__指向的对象设置为lookup_start_object，紧接着我们将这个lookup_start_object改变为一个string对象，因为漏洞的原因(上述C++代码[0])实际上v8处理的对象为receiver，也就是我们的o，然后将o指向的Elements地址作为string对象的length属性返回。  
  
  
这样就造成了信息泄露。  
  
## 2.2.3.2：通过Array对象与Function对象混淆，然后用Function的prototype属性进行伪造对象。  
  
  
```
```  
  
  
  
在上面这段代码片段中，如果recever为Function对象，那么在IC过程中会用receiver来执行LoadIC_FunctionPrototype。  
  
  
```
```  
  
  
  
通过前面的介绍的漏洞原理，在多次调用f()过程中，会对f()里面对o.m()的过程进行IC优化，并且将这个优化后得到O.prototype.__proto__设置为lookup_start_object，紧接着我们将这个lookup_start_object设置为一个function对象，因为漏洞的原因(上述C++代码[1]处)实际上v8处理的对象为receiver，也就是我们的a，然后将a指向的da_elements_addr地址作为f对象的prototype属性处理。这样就将地址da_elements_addr的数据当成了对象。  
  
有了信息泄露+对象伪造，就能轻松完成RCE。  
  
# 第三：补丁  
  
  
有了前面的知识后，这补丁也就非常简单了，修补过程只要把上述代码片段中的receiver换成lookup_start_object就可以了：  
  
  
```
```  
  
  
  
不过因为IC过程中的中间对象众多，编写v8的程序员会混淆的不只是receiver和lookup_start_object，这个issue是这种类型的第一个，会混淆的还有别的对象，现在我看过的就有3个。  
  
# 参考：  
  
https://bugs.chromium.org/p/chromium/issues/detail?id=1203122&q=SuperIC&can=1  
  
https://zhuanlan.zhihu.com/p/28790195  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GK23qLmrtWotXGxOo2yarXKGgAz83aqW1hMglPkxAicJsgsXg0ciaV2l2N3aknvGg0vTwsMoNJpezg/640?wx_fmt=png "")  
  
  
**看雪ID：苏啊树**  
  
https://bbs.kanxue.com/user-home-808412.htm  
  
*本文为看雪论坛优秀文章，由 苏啊树 原创，转载请注明来自看雪社区  
  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458499288&idx=1&sn=b2b9cd6ff7388a8658d254e13c72f9ad&chksm=b18e885286f9014436a590f2531fda167be67e1e227ea395812968e828932bd44eade34b0dbf&scene=21#wechat_redirect)  
  
  
**#****往期推荐**  
  
1、[在 Windows下搭建LLVM 使用环境](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458500602&idx=1&sn=4bcc2af3c62e79403737ce6eb197effc&chksm=b18e8d7086f9046631a74245c89d5029c542976f21a98982b34dd59c0bda4624d49d1d0d246b&scene=21#wechat_redirect)  
  
  
2、[深入学习smali语法](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458500599&idx=1&sn=8afbdf12634cbf147b7ca67986002161&chksm=b18e8d7d86f9046b55ff3f6868bd6e1133092b7b4ec7a0d5e115e1ad0a4bd0cb5004a6bb06d1&scene=21#wechat_redirect)  
  
  
3、[安卓加固脱壳分享](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458500598&idx=1&sn=d783cb03dc6a3c1a9f9465c5053bbbee&chksm=b18e8d7c86f9046a67659f598242acb74c822aaf04529433c5ec2ccff14adeafa4f45abc2b33&scene=21#wechat_redirect)  
  
  
4、[Flutter 逆向初探](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458500574&idx=1&sn=06344a7d18a72530077fbc8f93a40d8f&chksm=b18e8d5486f904424874d7308e840523ebfb2db20811d99e4b0249d42fa8e38c4e80c3f622c6&scene=21#wechat_redirect)  
  
  
5、[一个简单实践理解栈空间转移](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458500315&idx=1&sn=19b12ab150dd49325f93ae9d73aef0c4&chksm=b18e8c5186f90547f3b615b160d803a320c103d9d892c7253253db41124ac6993d83d13c5789&scene=21#wechat_redirect)  
  
  
6、[记一次某盾手游加固的脱壳与修复](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458500165&idx=1&sn=b16710232d3c2799c4177710f0ea6d41&chksm=b18e8ccf86f905d9a0b6c2c40997e9b859241a4d7f798c4aeab21352b0a72b6135afce349262&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8FHJ5XNqGmzLUOYeEJc9zylullBt3UKTEQsoxy2icCZlrib0kGSnnibUmPhrtv1ic2HR4SZvjH2PiaQASw/640?wx_fmt=gif "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8FHJ5XNqGmzLUOYeEJc9zylullBt3UKTEQsoxy2icCZlrib0kGSnnibUmPhrtv1ic2HR4SZvjH2PiaQASw/640?wx_fmt=gif "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8FHJ5XNqGmzLUOYeEJc9zylullBt3UKTEQsoxy2icCZlrib0kGSnnibUmPhrtv1ic2HR4SZvjH2PiaQASw/640?wx_fmt=gif "")  
  
**球在看**  
  
