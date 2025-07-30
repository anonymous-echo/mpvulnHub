#  V8 hole 类型漏洞利用总结   
XiaozaYa  看雪学苑   2024-02-14 17:59  
  
##   
  
```
```  
  
  
  
基本概念  
  
参考文章 [V8 Deep Dives] Understanding Map Internals（https://itnext.io/v8-deep-dives-understanding-map-internals-45eb94a183df）下面概念性的内容基本上就是对该参考文章的翻译或总结，建议看原文章。  
  
****  
V8中的Map是在哈希表的基础上构建出来的，但是不等同于哈希表，因为哈希表是不提供插入元素的顺序保证的，但是ES标准要求Map要记录元素的插入顺序。  
  
  
所以Map底层采用的是deterministic hash tables，当然对于我们而言无需关心其具体是什么，类似哈希表就完了。确定性哈希表采用的数据结构伪代码如下：  
  
  
```
```  
  
  
  
这里的CloseTable代码的就是代表的哈希表，其成员hashTable的大小代表buckets的数量，其第i个元素代表的就是第i个buckets头元素在dataTable中的index：![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HTGFyczu3h05X7kDaOrjJZLwHfy4R3uvmbicyJbFn7xFca6rwa2nLNictpicVGhn27icAxghd5N4CRCA/640?wx_fmt=png&from=appmsg "")  
其实这里把hashTable当作bucket使用数组，dataTable当作bucket数组就好了，这样做的目的就是为了记录元素的插入顺序。  
  
  
当删除元素时，这里仅仅就是将key和value设置为undefined，所以这里被删除的元素仍然占据内存空间。  
  
  
当然还有一个问题就是当dataTable满了，V8是如何进行扩容的呢？这里引入v8中的实现规则：  
  
◆dataTable.length = 2 * bucket = 2 * hashTable.length  
  
◆每次按照2的次幂进行扩容  
  
  
这里的验证可以看参考文章，后面讲了v8中Map的内存模型了在简单验证验证。  
## V8 源码分析  
  
在v8中，JSMap的内存布局如下：![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HTGFyczu3h05X7kDaOrjJZz2LicRVFGG1JNz8fGtaicqamufbibotdppyunBQcSsrBicCR6SuQUWjLRw/640?wx_fmt=png&from=appmsg "")  
  
  
  
◆Map：就不多说了，就是每个对象都有的，表示对象的shape  
  
◆FixedArray Length：整个OrderedHashMap的大小，其实就是一个FixedArray  
  
◆elements：存在的entry的数量  
  
◆deleteds：被删除的entry的数量  
  
◆buckets：bucket的数量  
  
◆hashTable、dataTable就是上面介绍的两个表  
  
  
考虑如下代码：  
  
  
```
```  
  
  
  
可以看到这里的OrderedHashMap：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HTGFyczu3h05X7kDaOrjJZliaKYGe7kcj3ZHTtbXGiaUVOoJgItiba3icWjpibx4yOWibZcxpibvhBBvlibg/640?wx_fmt=png&from=appmsg "")  
  
初始时，buckets的数量为2：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HTGFyczu3h05X7kDaOrjJZWO9Z4gyYPbUpIANPEcTYXyMSupiaa0HebePA55VCa62gr8ruWp8nhMg/640?wx_fmt=png&from=appmsg "")  
  
可以看到这里dataTable的大小为12（8字节为单位哈），而每个entry占 3，所以总的容量其实就是4，其为2 * buckets是满足之前说的dataTable.length = 2 * buckets = 2 * hashTable.length。  
  
  
当添加四个元素时：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HTGFyczu3h05X7kDaOrjJZwSaFNqXNJVD1gkvzyWUibl6nia7MxHvz0iagm2vcJcZk4ypSrHvQ0cjQA/640?wx_fmt=png&from=appmsg "")  
  
这里来看下hashTable和dataTable，这里我直接画了一个图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HTGFyczu3h05X7kDaOrjJZib2ibuicnSI017VzhorkQDB5aEJEMlwLibhERZ5WHxvoiaBDGrlc3anuiblA/640?wx_fmt=png&from=appmsg "")  
这里似乎与上面参考文章说的有点不同，这里采用的头插法？而且我也没看出来这里是咋记录插入顺序的，但是这里使用for...of循环确实是按照顺序打印的：  
  
  
```
```  
  
  
  
然后删除(3, 1)：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HTGFyczu3h05X7kDaOrjJZ13eE2bicQlWlbqvpgwvlaOic5nu7bl8PEWQvpicCica9iaYLaz1R3oJla9A/640?wx_fmt=png&from=appmsg "")  
  
可以看到这里的elements = 3，而deleteds = 1，这是符合逻辑的，并且hashTable并没有改变，仅仅将对应的entry的key/value设置成了#hole：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HTGFyczu3h05X7kDaOrjJZugvOKP6762bYyGgibI6SxklNsheiaSvgrpgSX1Jx1qGMDa1tvK1iack3w/640?wx_fmt=png&from=appmsg "")  
  
然后再添加一个元素：可以看到这里的OrderedHashMap已经发生了变换，即这里发生了扩容：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HTGFyczu3h05X7kDaOrjJZicCWdcJmyO1nDmFpsXfwkPwk3ibOia4zQetqamjJEQWDtL5HMAG3ZEpTQ/640?wx_fmt=png&from=appmsg "")  
  
来看下OrderedHashMap：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HTGFyczu3h05X7kDaOrjJZcicYYytxVFx8DxxQW4aoqllJFW0YPvEKsXVlI3sLXjYmReNiczja2MDg/640?wx_fmt=png&from=appmsg "")  
  
可以看到这里清除了deleted entry：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HTGFyczu3h05X7kDaOrjJZUXniagYUdia0JV6JhOPabTIu0ia3hsAiaPUT1Kc7m7lXaiauZ7bHmy3Ophw/640?wx_fmt=png&from=appmsg "")  
### set  
  
map.set(key, value)的作用就是给map添加元素（其实就是键值对，只是笔者习惯叫做元素，读者自己明白就好），其在V8层面的接口定义如下：  
  
  
```
```  
  
  
  
set的整个逻辑如下：  
- 检查 key 是否存在  
  
- 若不存在空闲的 entry，则进行扩容，然后填充 entry  
  
- 若存在空闲的 entry，则直接填充 entry  
  
- 若 key 存在，则直接更新 value  
  
- 若 key 不存在，则检查是否存在空闲 entry  
  
这里是用TryLookupOrderedHashTableIndex函数去寻找key对应的entry的，即判断key是否存在：  
  
  
```
```  
  
  
  
可以看到对于不同类型的key，有着不同的寻找方式，这里以Smi类型的key为例，对于Smi类型的key寻找其entry利用的函数是FindOrderedHashTableEntryForSmiKey：  
  
  
```
```  
  
  
  
该函数比较简单，就是先利用ComputeIntegerHash计算出key的哈希值，然后再用FindOrderedHashTableEntry进行查找，ComputeIntegerHash函数如下：  
  
  
```
```  
  
  
  
重点还是在FindOrderedHashTableEntry上：  
  
  
```
```  
  
  
  
整个逻辑我都注释清楚了，就不多说了，值得注意的是这里遍历bucket链表时存在范围检查。  
  
  
后面StoreFixedArrayElement函数我没有找到其定义，就分析下StoreOrderedHashMapNewEntry函数，其实都比较比较简单，值得注意的是这里写入的entry是根据hashTable的偏移计算得到的：  
  
  
```
```  
  
###   
### delete  
  
map.delete(key)的作用就是删除对应元素，其在V8层的接口函数如下：  
  
  
```
```  
  
  
  
逻辑比较清楚了，看注释吧，这里来看下Runtime::kMapShrink函数：  
  
  
```
```  
  
  
  
其主要就是调用的OrderedHashMap::Shrink函数：  
  
  
```
```  
  
  
  
话不多说，跟进Rehash函数：  
  
  
```
```  
  
#   
  
```
```  
  
  
  
前面对JSMap分析了那么多，哪么hole泄漏如何利用JSMap进行攻击呢？  
  
  
Hole是JS内部的一种数据类型，用来标记不存在的元素，这个数据类型通常是不能泄露到用户JS层面。Hole类型的漏洞利用是指由于内部数据结构Hole通过漏洞被暴露至 用户JS层，因此可以根据Hole创建⼀个长度为 -1 的JSMap结构，导致越界读写，从而实现RCE。  
  
  
根据前面的分析，我们知道当使用map.delete删除一个元素时，只是将该元素的key、value设置为hole，并没有实际的删除该元素，实际上只是做了个标记，当进行shrink操作时，这些被hole标记的元素才会被真正的删除。那么如果我们可以创建key = hole的元素，那么我们就可以多次删除元素从而导致map.size = -1（当然这里前提是不进行shrink操作，因为shrink操作会清除hole元素）。  
  
  
考虑如下代码：  
  
  
```
```  
  
  
  
可以看到这里的elements = -1、deleted = 0、buckets = 2：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HTGFyczu3h05X7kDaOrjJZtEGIia5S1daicVaKj4u9LpoRfNEvf6Mjwl9gAtwnPiazyRIrTJvzibqhYw/640?wx_fmt=png&from=appmsg "")  
  
当然这里的触发代码为啥这样写呢？为啥要map.set(1, 1)呢？直接map.set(hole, 1)，然后再delete两次不行吗？其实这里就是涉及到shrink操作会清除hole元素，比如考虑如下代码：  
  
  
```
```  
  
  
  
map.set(hole, 1)后：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HTGFyczu3h05X7kDaOrjJZq2ics3pAEVHRu1ycLXayuh7ibqYgxDKL7gVp6sLkNMYJp7YhIHPPWShA/640?wx_fmt=png&from=appmsg "")  
  
可以看到这里的：elements = 1、deleted = 0、buckets = 2  
  
第一次map.delete(hole)后：  
  
第一次map.delete(hole)后，elements = 0、deleted = 1、buckets = 2，由于elements < buckets / 2，所以第一次delete后会发生shrink、从而导致hole元素被删除，因此第二次map.delete(hole)时直接返回false（这里不理解的看上面delete操作的源码分析）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HTGFyczu3h05X7kDaOrjJZPdicAPpYTuBnBKEXXyyGeHXP1EOKUVU4No0ZrAIicYibkz6ibibIXYL2Now/640?wx_fmt=png&from=appmsg "")  
  
Ok，现在已经成功构造了map.size = -1了，哪么接下来该如何去进行OOB呢？先来看看如果现在我们继续向map中添加元素，这时会发生什么呢？  
  
  
在之前的set操作的源码分析中，我们知道当添加一个新的元素时（即key事先不存在）new entry的寻找方式为：&hashTable + buckets + occupancy * 3，这里的occupancy = elements + deleted  
  
而在构造好map.size = -1后，其相关字段的值为：elements = -1、deleted = 0、buckets = 2  
  
  
所以new_entry = &hashTable + 2 + (-1 + 0) * 3 = &hashTable - 1 = hashTable[-1] = &buckets  
  
  
所以new_entry = key|value|chain = buckets|hashTbale[0]|hashTable[1]，即下一次添加新元素时，就可以修改buckets = key1、hashTable[0] = value1  
  
  
然后我们再添加新元素，此时：new_entry = &hashTable + buckets + (0 + 0) * 3 = hashTable[key1]，而key1我们是可以控制的，所以new_entry也是可控的，从而导致越界写key/value，这里一般就是去写JSArray的length字段。  
  
  
但是需要注意的是，在之前分析set操作源码时，我们知道当对bucket链表进行遍历时会存在检查，所以我们得让bucket[hash(key) & (buckets - 1)] = -1从而避免遍历bucket链表。  
  
  
在构造好map.size = -1后，第一次添加新元素是无所谓的，因为此时bucket[0] = -1、bucket[1] = -1，但是第二次就得注意了，第一次添加时会导致bucket[0] != -1或者bucket[1] != -1，但是其实bucket[0] = value1，所以可以让bucket[0] = value1 = -1，这样在第二次添加时我们只需要让：hash(key2) & (buckets - 1) = 0即可，这里到时候爆破一下就 ok 了。  
  
  
模板如下：  
  
  
```
```  
  
  
  
key2爆破脚本，这里的ComputeUnseededHash函数以实际的V8源码为准：  
  
  
```
```  
  
#   
  
##   
  
```
```  
  
  
  
题目其实没啥好说的，关键就是利用漏洞把hole泄漏出来，后面基本都是一样的。所以这里直接用%TheHole()来获取hole，以此来演示利用手法：  
  
  
```
```  
  
  
  
效果如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HTGFyczu3h05X7kDaOrjJZmRDfx02hTVxqkGMeziaLqPTgvjynCDMZxticKc7s4iav4kTziaGuyu4TicQ/640?wx_fmt=png&from=appmsg "")  
  
可以看到这里的oob_arr.length成功被修改为0x2002导致越界读写。然后就是基本的OOB类型漏洞利用了，没什么好说的。  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HTGFyczu3h05X7kDaOrjJZ7EfxYmffaKT0U1Gmn6N9l9WhFldvS99RXuB7kcIQkz5lm3FJGPRtKg/640?wx_fmt=png&from=appmsg "")  
  
  
**看雪ID：XiaozaYa**  
  
https://bbs.kanxue.com/user-home-965217.htm  
  
*本文为看雪论坛优秀文章，由 XiaozaYa 原创，转载请注明来自看雪社区  
  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458540101&idx=3&sn=a4d6b9a3e70e4835e060d53c0a570b62&chksm=b18d68cf86fae1d93d7ad47013d03e922bf11c64e06e61a39c699e307aca451c2f85abc74413&scene=21#wechat_redirect)  
  
  
  
**#****往期推荐**  
  
1、[区块链智能合约逆向-合约创建-调用执行流程分析](https://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458532403&idx=1&sn=3cb169db2b7587d7679fdb4ab1b1e7db&scene=21#wechat_redirect)  
  
  
2、[在Windows平台使用VS2022的MSVC编译LLVM16](https://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458532326&idx=2&sn=1f474e4a32960bd62ca80b5172485589&scene=21#wechat_redirect)  
  
  
3、[神挡杀神——揭开世界第一手游保护nProtect的神秘面纱](https://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458531968&idx=1&sn=f5d10b971479f00b4ba1b4bc43d63f21&scene=21#wechat_redirect)  
  
  
4、[为什么在ASLR机制下DLL文件在不同进程中加载的基址相同](https://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458531931&idx=2&sn=c6d3d71c15a29a24e9fa288f963c82bc&scene=21#wechat_redirect)  
  
  
5、[2022QWB final RDP](https://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458531697&idx=1&sn=ce28e8201aee34f0be6a8b6a97c4d9e4&scene=21#wechat_redirect)  
  
  
6、[华为杯研究生国赛 adv_lua](https://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458531696&idx=1&sn=31c1dabbd80a62307ad24f4c119170fe&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8HTGFyczu3h05X7kDaOrjJZAZAacrKVGeZG849DfGJkcLo9Itf4etPL22GRXSkQxgnUSzkxaYul8g/640?wx_fmt=gif&from=appmsg "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8HTGFyczu3h05X7kDaOrjJZAZAacrKVGeZG849DfGJkcLo9Itf4etPL22GRXSkQxgnUSzkxaYul8g/640?wx_fmt=gif&from=appmsg "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8HTGFyczu3h05X7kDaOrjJZAZAacrKVGeZG849DfGJkcLo9Itf4etPL22GRXSkQxgnUSzkxaYul8g/640?wx_fmt=gif&from=appmsg "")  
  
**球在看**  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8HTGFyczu3h05X7kDaOrjJZEXHFUpl9CODMW6iat1cMAByIQFg50f60XgL3DEQRCZcEulQG3wOibsWA/640?wx_fmt=gif&from=appmsg "")  
  
点击阅读原文查看更多  
  
