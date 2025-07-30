#  vctf apples leak libc操作复现(高版本libc overlapping)   
ElegyYuan0x1  看雪学苑   2024-04-20 18:02  
  
题目中存在off_by_one libc版本2.34以上我们没办法使用常规的overlapping 泄露libc地址。  
  
  
所以我们要精心构造一个chunk head来绕过新版本的检查机制，实现leak libc的操作。  
  
  
文章中我们先讲原理，在最后会将Arahat0师傅的脚本给出来。  
  
  
  
```
```  
  
  
  
◆2.34下的合并检查机制  
  
  
检查size是否对得上：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8EVZkYiaajv3pMhJIGXgiaBhXRJxN22Dy0GaNt3K6yD0zxIb8eEqzcjyFJia2uIjP3FnsGrxiarBCkglw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
unlink检查：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8EVZkYiaajv3pMhJIGXgiaBhXYnBkCqCJbbHoYEylujuFY5yqIeWicr0uaeZT6Geliak8P3Kd050GicxpA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
```
```  
  
> 这里先简单说一下我们要干什么，  
> 后面详细说一下我们的利用流程。  
  
  
  
◆构造一个chunkheader 让它的size fd bk都符合检查机制。  
  
  
  
```
```  
  
  
### 构造chunk header  
> 主要是构造合法的size fd bk 我们把我们构造的chunk叫做fake chunk  
  
  
  
◆代码  
```
add(0x410, "a" * 8)  # 0  290
add(0x100, "a" * 8)  # 1  6b0
add(0x430, "a" * 8)  # 2  7c0
add(0x430, "a" * 8)  # 3  c00
add(0x100, "a" * 8)  # 4  1040
add(0x480, "a" * 8)  # 5  1150
add(0x420, "a" * 8)  # 6  15e0
add(0x10, "a" * 8)  # 7  1a10
 
free(0)
free(3)
free(6)
# 触发合并 然后合成一个0x860的大chunk 让我们可以分割
# 并且我们的fd和bk在0x430+16字节的位置 也就是0x440位置存在fd和bk
free(2)
# add一个比chunk 0 chunk6都大的chunk这样就会去分割0x860chunk 然后我们控制我们的payload 设置一个size到原本size的地方
# 这样fd和bk分别指向chunk 0 和chunk 6 这样我们可以构造一个 合法的chunk head头
add(0x450, b"a" * 0x438 + p16(0x551))  # 0
# 将 chunk3 变为allocted
add(0x410, "a" * 8)  # 2
add(0x420, "a" * 8)  # 3
add(0x410, "a" * 8)  # 6
```  
  
  
◆free 3个chunk(chunk0 chunk3 chunk6) 这样chunk3(的fd和bk分别指向chunk 0 chunk6。  
> 这里需要特殊说明 这里的chunk3的地址要特殊一些 也就是最低的地址为00 这样方便我们后面使用off_by_one漏洞来实现修改fd/bk的低地址为0来让FD->bk BK->fd 指向我们伪造的chunk (后面会详细说明)  
  
  
  
  
◆free 一个chunk 让两个chunk(chunk3 与chun2)合并 这样就保留了fd(chunk 0)和bk(chunk6)在一个大的chunk中。  
  
  
◆然后我们将这个大chunk分割为chunk3 和chunk4 让我们自己构造的size刚好覆盖在原chunk3 size 位置 详细看下方图。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EVZkYiaajv3pMhJIGXgiaBhXKYT4a2AQibe1UY3kSp2SicpP6g5DOwk0k5ic21OgLBiaAcicrojHicsOVGXQ/640?wx_fmt=png&from=appmsg "")  
  
  
◆分割大chunk 并且构造size  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8EVZkYiaajv3pMhJIGXgiaBhXQmLfYfaQNscl5biaPsiaECZ8uibQrc53wpcbN8laeYNlzkBQYaa2uGjoQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
◆这里我们已经成功构造好了 size和fd bk 那么后面我们就要想办法让chunk 0的bk 和chunk6的fd指向我们构造的chunk。  
  
### 构造FD->bk  
> 这里主要是利用先让chunk0的bk 指向chunk3 然后利用off_by_one漏洞覆写bk 指向我们的fake chunk  
  
  
  
◆代码  
```
# 覆写chunk0的fd
free(6) #free的chunk 3
free(2) #free的chunk 0
add(0x410, "a" * 8)  # 2
add(0x410, "a" * 8)  # 6
```  
  
  
◆示意图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8EVZkYiaajv3pMhJIGXgiaBhXBAgpm2VAfXoUIHHLdXsfp89QF5lpWgKM9jkFuo8KibjppmwqDdyycKw/640?wx_fmt=jpeg&from=appmsg "")  
  
### 构造BK->fd  
> 这里就要复杂一点了，因为修改chunk 6 的fd不能像修改FD->bk那样直接free，然后add。  
> 我们需要利用 合并机制来修改，也就是先free chunk3 chunk 6 以及chunk5 触发chunk6和chunk5合并。  
> 然后我们分割一个chunk 5出来，并且向原本chunk6 size fd位置赋值。  
  
  
  
◆代码  
```
free(6)
free(3)
free(5)
 
add(0x4f0, b"b" * 0x488 + p64(0x431))  # 3
add(0x3b0, "a" * 8)  # 5
```  
  
  
◆示意图  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EVZkYiaajv3pMhJIGXgiaBhX1IJVu4s2dmjqZBj9YFQxfedu7nbvUppVzawBcHg8Hsg0DWvGqkdLHw/640?wx_fmt=png&from=appmsg "")  
  
  
◆add后  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EVZkYiaajv3pMhJIGXgiaBhXKszVQA4BmlWibSUbp4Vick4gAqTmaJOXwJXOCJdP4VoRjuN4QyYGW94A/640?wx_fmt=png&from=appmsg "")  
###   
### 构造合并chunk  
> 这里就要简单很多了，就是利用一次合并机制和分割机制，造成prev_inuse变为0，并且构造好prev_size。  
> 只不过我们还是得调整一下要选择合并的chunk的位置，因为我们刚才构造的fake chunk大小为0x550，所以我们要在fake chunk往下0x550位置弄出一个 allocted chunk。  
> 下面的解释其实有失偏颇，因为其实是我们专门计算的0x550这个数据，刚好对上一个chunk，但是为了方便理解我们选择倒推的方式。  
  
  
  
◆代码  
```
free(4)
 
add(0x108, b"c" * 0x100 + p64(0x550))  # 4
add(0x400, "a" * 8)  # 6
free(3)
add(0x10, "a" * 8)  # 3
show(6)
```  
  
  
◆首先我们看一下 fakechunk 0x550偏移位置坐标在哪里。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8EVZkYiaajv3pMhJIGXgiaBhXjk3OWU3sAwLaehKWN1thTqHxuyE1jsCRhvs8YfkvCZ9gEpU2SCqpxg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8EVZkYiaajv3pMhJIGXgiaBhXcqbxEsUUicOn5IduKMiciaJg1g0oTJpI7Vxicic3AyTJpY1NGlqT9n6xm4g/640?wx_fmt=jpeg&from=appmsg "")  
  
  
◆根据地址我们知道 也就是我们要修改的chunk为chunk 5 那么我们就去free掉chunk 4(大小0x110)然后malloc回来 写入数据覆盖到chunk 5的prev_inuse 并且构造好0x550的prev_size。  
  
  
◆示意图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8EVZkYiaajv3pMhJIGXgiaBhXxiaib0icE3ibOdH9pmyfO1rziao96PYfTCy3JSeLegmSHCIbRFL5vd6jDrw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
◆此时我们成功完成构造 最后只需要 free掉chunk 5触发合并机制 然后我们成功完成一次overlapping 可喜可贺。  
  
  
  
```
```  
  
  
  
```
```  
  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EVZkYiaajv3pMhJIGXgiaBhX2GF6sI0gxAJkTUxzntP4nib9ghzlS1sEyLUe6uLibN3chlHKINeeHphQ/640?wx_fmt=png&from=appmsg "")  
  
  
**看雪ID：ElegyYuan0x1**  
  
https://bbs.kanxue.com/user-home-994584.htm  
  
*本文为看雪论坛优秀文章，由 ElegyYuan0x1 原创，转载请注明来自看雪社区  
  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458550539&idx=1&sn=99d99a504e0b364140e6cfe6c561f0b1&chksm=b18db18186fa389736b29f09c357e9d8c3ecbc37c6411d7664c2876cb7d8d99311810e406a4c&scene=21#wechat_redirect)  
  
  
  
**#****往期推荐**  
  
1、[自定义Linker实现分析之路](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458550539&idx=2&sn=e3a883e6de9929783e4920b1ae75802d&chksm=b18db18186fa38971cf9a67439421e62a1c3e1dbeb2cdc974c70ab52186fe92738ed759cf003&scene=21#wechat_redirect)  
  
  
2、[逆向分析VT加持的无畏契约纯内核挂](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458550427&idx=1&sn=399ad869e9f33b368de123b079ca1ff2&chksm=b18db01186fa390707f03c65e957277ed4eb7d250bbce02130ab2d6324c0c4cd9ab837e01802&scene=21#wechat_redirect)  
  
  
3、[阿里云CTF2024-暴力ENOTYOURWORLD题解](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458550386&idx=1&sn=ef197d9dc41313d624d8e297d6cc5f9a&chksm=b18db0f886fa39eedca81d2ebee9e73e689d9db0bfdcb9831d8ebe4a759a5c55f98aff2a771b&scene=21#wechat_redirect)  
  
  
4、[Hypervisor From Scratch - 基本概念和配置测试环境、进入 VMX 操作](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458550275&idx=1&sn=c1b54dc12abbcb627796db92d4f9c2fc&chksm=b18db08986fa399ff036a52bbbe579808ba65111151b31af848628a464efe064e4fbd7c6c1d9&scene=21#wechat_redirect)  
  
  
5、[V8漏洞利用之对象伪造漏洞利用模板](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458550274&idx=1&sn=83844418c6e1fb22d4d8c2033abdea5e&chksm=b18db08886fa399ee2927fefc6f01c0213e126ef3248a8ecc439231526e9e56e69f937a29a3c&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8GJubmq65v9uBFmEJuoJD78321RiaLpp3FAylJv0nbibloCFmXdVe4wvW4ibgnCc6srNI8sGBkX14MpQ/640?wx_fmt=gif&from=appmsg "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8GJubmq65v9uBFmEJuoJD78321RiaLpp3FAylJv0nbibloCFmXdVe4wvW4ibgnCc6srNI8sGBkX14MpQ/640?wx_fmt=gif&from=appmsg "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8GJubmq65v9uBFmEJuoJD78321RiaLpp3FAylJv0nbibloCFmXdVe4wvW4ibgnCc6srNI8sGBkX14MpQ/640?wx_fmt=gif&from=appmsg "")  
  
**球在看**  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8GJubmq65v9uBFmEJuoJD78txPhfvI9WpuGSCawCN8NJCgzD16Y0IwdUkaI33Qr3DpwRRuvibgRQOg/640?wx_fmt=gif&from=appmsg "")  
  
点击阅读原文查看更多  
  
