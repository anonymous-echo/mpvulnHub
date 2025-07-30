#  V8 torque函数PromiseAllResolveElementClosure 相关的issue和POC的探索   
苏啊树  看雪学苑   2024-07-12 17:59  
  
```
```  
  
  
        
  
最近无意刷到看到一篇v8CTF的文章，原本想看一下学习下v8沙箱绕过的姿势，看了作者的slides却是第一时间被作者圈起来的这个PromiseAllResolveElementClosure builtin函数所吸引，查了下是v8处理Promise对象相关的torque函数。  
  
   ![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8FYXjic4EichcVGNsHQxXqO6vHftT6XNpskRSN2VQWZH5WcgkcxoFEWp4HomQZDJnBK0UQQ3CicwZxnQ/640?wx_fmt=other&from=appmsg "")  
  
  
                                                             图   1.1  
  
     
  
原slide  
  
https://kaist-hacking.github.io/pubs/2024/lee:v8-ctf-slides.pdf  
  
  
印象  
中在以往的漏洞报告上看到这个builtin的次数不少，随手google查了下就看到搜索记录显示：  
  
◆CVE-2020-6537  
  
◆chrome issue 40068417  
  
  
还有这个CTF slide所用的：  
  
◆CVE-2023-6702  
  
  
都和这个PromiseAllResolveElementClosure有关联。  
  
  
由于之前对这一几个问题都没有仔细的分析过，这次索性一起调试一遍，顺便尝试通过CVE-2023-6702的POC构造出issue 40068417和CVE-2023-6702的POC。  
  
  
  
```
```  
  
  
  
故事的源头从一个补丁开始：  
  
   ![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8FYXjic4EichcVGNsHQxXqO6vmRkGdZjftrBqpwXoBYR9ZXVia8iclVxE9TlLxzBFR6ZibEOwLyXOBHMTg/640?wx_fmt=other&from=appmsg "")  
  
  
                                                           图 2.1  
  
## 2.1：补丁分析  
  
          
  
如图2.1绿字的补丁注释，大意是说在闭包指向NativeContext作为marker调用之后，我们不能再访问reject element context。  
补丁修在了CaptureAsyncStackTrace函数。  
  
         
  
同时2.1图上还有红字，提示是在Promise.all()函数调用时发生的。  
  
         
  
根据查阅资料能得知CaptureAsyncStackTrace就是捕获Async函数调用的异常堆栈，发生在Async函数出现错误的时候，捕获到异常后能够访问到其堆栈的情况，这个函数就是v8对这个JS情景的处理。  
  
         
  
作者构造的POC：  
  
  
```
```  
  
  
     ![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8FYXjic4EichcVGNsHQxXqO6vIXwD4dpCPtbcAsIic6P1O5PGSiaSEoHx38QAucOx6afmdQtWQfr2ugmQ/640?wx_fmt=other&from=appmsg "")  
  
  
                                                                       图  2.1  
##   
## 2.2：崩溃分析  
  
  
◆作者使用了一个和ECMAScript标准上Promise相同的构造函数写了一个构造器Constructor，然后重写了该注册器Constructor的resolve方法，resolve方法只是简单的把接收到的对象返回。  
  
  
◆创建了一个对象p1，在p1里重写了then方法，在then方法里用闭包变量closure获取v8内部的fullfill对象(onFul)，然后把闭包变量Closure作为函数进行调用。  
  
  
◆创建一个async函数，将p1对象作为Promise.all.call的参数，并且调用Promise.all.call函数，然后使用await确保Promise.all.call调用中p1重写的then，完成闭包变量Closure解惑v8内部的fullfill对象，并且当成函数进行完成，并且随后抛出一个异常。结果在抛出的异常的堆栈的访问的时候，意外的能访问到内置fulfill(onFul)对象使用的NativeContext，造成数据结构的混淆，触发了v8 Debug版本下的Assert。  
  
## 2.3：原因小结  
  
  
◆onFul对象使用的是v8内部的builtin对象，然后使用的context为NativeContext。  
  
  
◆使用onFul这个内部对象作为函数调用的时候，v8内部会调用PromiseAllResolveElementClosure这个builtin函数。  
  
  
◆而在CaptureAsyncStackTrackt这个函数中的处理中，原本期待处理的数据结构为当前JS所处的GlobalContext，然而漏洞版本的v8却意外的使用了原本不应该访问的内置的builtinPromiseAllResolveElementClosure所使用的NativeContext，造成了数据结构混淆使用，引起了内存破坏。  
  
  
  
```
```  
  
##        
## 3.1：CVE-2020-6537 POC构造  
  
       
  
从2023年的POC倒推2020年的POC，现实工作和学习肯定不会有这种需求，听起来非常的无厘头。但是最近漏洞研究经历让我感觉，很多时候找漏洞只是在不同的地方反反复复的找相似而又遗漏掉的情况，前人会找到这个东西作为研究，肯定是这个点地方集合了很多要素，有鸡有篮球，有中分也有背带裤，你如果能发现新的要素就又可以玩之前的烂梗。大部分问题的发现不用需要覆盖得多么全面，对原本问题的理解更深更细致好像现实漏洞研究中更为重要。多做一些尝试能理解到的点就会多起来，由于我先看到的是这个v8CTF的paper，之前也从没看过CVE-2020-6537的POC，就想着尝试一下由这个paper作者构造的POC和之前本人知识的基础上，能否构造出CVE-2020-6537的POC。  
  
       
### 3.1.1：CVE-2020-6537 bug Issue分析  
  
       
  
看CVE-2020-6537的bug issue里面的这段描述，  
  
       
  
https://issues.chromium.org/issues/40052834  
  
In function PromiseAllResolveElementClosure  
, it will read {remainingElementsCount} from {context}'s slot firstly, subtract 1, and save it back to {context}. {remainingElementsCount} represents the number of pending promise and when it becomes to zero, the function will return an array of objects that each describes the outcome of each promise.  
  
       
  
根据上述的issue描述，貌似这个漏洞和remainingElementCount这个变量有非常大的关系。将v8切换到漏洞版本的commit以后，利用关键字搜索一下v8源码，发现这个变量remainingElementCount出现在PerformPromiseAll和PromiseAllResolveElementClosure这两个torque函数里面，表示的是一种计数。  
  
       
  
这里对这两个torque函数打了补丁，Print出remainingElementCount的的计数。  
  
      ![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8FYXjic4EichcVGNsHQxXqO6v86ZMNUw4ntoxGIiasuYDuo37x2SiaB0rgoYD2KpNGPyxxiaaZLryOX9SQ/640?wx_fmt=other&from=appmsg "")  
  
  
                                                                         图 3.1.1  
  
       
     ![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8FYXjic4EichcVGNsHQxXqO6vTo0ianqjDMAw0atXa8yC4KnPXS3qg25DBPqfDFohuTrfzyicuiavbTnxg/640?wx_fmt=other&from=appmsg "")  
  
  
                                                                          图 3.1.2  
  
  
如图3.1.1，3.1.2，所示的位置打上补丁后，重新编译v8，将v8CTF的POC简单的修改为以下POC：  
  
  
```
```  
  
  
   ![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8FYXjic4EichcVGNsHQxXqO6vkUoFgrRC5sn5CVT9moicphUuv7AJfmoU4SbXZxm43t53OyGCTqXI7dA/640?wx_fmt=other&from=appmsg "")  
  
  
                                                                          图 3.1.3  
###   
### 3.1.2 ：控制台输出分析   
  
      
  
如图3.1.3所示，成功进入PerformPromiseAll和PromiseAllResolveElementClosure这两个torque函数，并且使用了这个计数变量remainingElementCount。通过控制台的输出信息我们可以推测：  
  
      
  
 v8执行这个POC的时候，调用了PerformPromiseAll这个torque函数，增加了一次remainingElementCount，然后调用了PromiseAllResolveElementClosure，减少了一次remainingElementCount变量是平衡的，这里如果把onFul注释掉再运行POC，v8是不会使用PerformPromiseAll和PromiseAllResolveElementClosure这两个torque函数，那么这里我们可以得出PerformPromiseAll和PromiseAllResolveElementClosure这两个torque函数和onFul(fullfill)对象作为函数调用的情况有关，那么和onRej(reject)对象作为函数使用的时候有没有关系呢，现在并不能知道。  
  
       
  
根据另一段漏洞描述：  
  
Normally, either resolveElementFun  
 or rejectElementFun  
 should only be called once at most, which means turning a pending promise to fulfilled or rejected state. However, user can get resolveElementFun  
 and rejectElementFun  
 through some user defined js functions. Once both of them are called, {remainingElementsCount} will be substracted twice but only one promise has been processed. So the result of Promise.allSettled will be returned to user in advance. An attacker may use this vulnerability to cause type confusion, and achieve arbitrary code execution.  
  
      
  
通常情况下resolveElementFun  
 和 rejectElementFun情况是只调用1个，然后在用户JS劫持的情况下可以调用2次，稍微对JS Promise有过了解的都知道Promise返回的时候有resolve和reject 2种情况，全部成功的时候执行resolve回调，有错误的时候执行reject回调，只会出现resolve和reject其中1个回调调用的情况。  
  
     
  
这里却说在用户JS劫持后能实现同时调用了resolveElementFun 和 rejectElementFun两个函数的情况，这里我的理解就是调用了2次PromiseAllResolveElementClosure这个torque函数，导致导致出现安全问题，但具体的怎么出现所谓的resolveElementFun 和 rejectElementFun两个函数调用的情况呢，还不得而知。  
##      
## 3.2：分析总结：  
  
        
  
目前能知道按照v8CTF slide给我们的信息，如果重写了then方法，并且将其中内置的onFul对象当成函数调用，就会进入PromiseAllResolveElementClosure这个builtin，通过输出日志，我们能看到可以走到PerformPromiseAll这个torque，并且会把remainingElementCount这个计数+1，同时接下来会走到PromiseAllResolveElementClosure这个torque，然后把remainingElementCount这个计数-1，变量remainingElementCount的数字是平衡的。  
  
       
## 3.3：如何让remainingElementCount计数出现错误  
  
  
◆第一种尝试，如果截获onFull后，重复调用onFul()，会不会出现减两次remainingElementCount变量的情况呢，结果通过打印显示，只对remainingElementCount计数改变了一次。也就是说即使拦截了onFul然后多次onFul调用，也只是调用了一次PromiseAllResolveElementClosure这个torque函数。  
  
  
◆第二种尝试，分别重写onFul和onRej，然后调用onFul和onReg，但是结果还是只调用了一次PromiseAllResolveElementClosure这个torque函数。  
  
  
仔细的研究了下Promise和then的资料，发现ECMAScript标准下规定then接管以后，无论调用onFul和onRej这情况本质都是相同的，简单来说，结果有两种情况：  
  
        
  
第一种情况是全部处理正确，这时候由内部的resolve，也就是这里的onFul回调处理。  
  
        
  
第二种是出现了错误，返回第一个错误，交给内部的reject，也就是这里的onRej处理。这样的话在返回then的时候同时调用onFul,onRej是不会成功的，因为这两个对象在这个时候，只有其中一个在ECMAScript标准下是有意义的。  
##        
## 3.4：修改构造器resolve方法  
  
        
  
通过一段时间对标准的研究和尝试，我发现如果我们通过直接重写注册器Constructor的resolve方法，在这个注册器的resolve方法中获得对象的then方法，就能第一时间接管到onFul和onRej(resolve和reject)对象，这个时候其实v8还没有对结果进行判断，所以onFul和onRej都还是”有意义的“的对象，如果是在这时候劫持那很就能直接调用onFul()和onRej()，这样就能可能触发两次对PerformPromiseAll和PromiseAllResolveElementClosure torque函数的调用，将remainingElementCount减1两次。  
  
        
  
把POC改为：  
  
  
```
```  
  
  
   ![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8FYXjic4EichcVGNsHQxXqO6vSOia0Xeo9bJdM5b5QqQGuZ5SJ0qyrB7qnoqR1BkGkR7cJhDKY4NPAHA/640?wx_fmt=other&from=appmsg "")  
  
  
                                                                        图 3.3.1  
  
        
  
成功在控制台打出了hehe haha，说明onFul,onRej两个对象都劫持成功，并且也都调用成功了，成功在这个时候触发了v=>{}和e=>{}函数。  
##          
## 3.5: 成功的POC  
  
         
  
虽然在这一步成功劫持onFul,onRej两个对象然后将这两个对象作为函数调用，达到了issue描述里面说的resolveElementFun  
 和 rejectElementFun两个函数对象同时发生了调用的情况，但是  
remainingElementCount的变量计算结果并没有出现预期的错误。remainingElementCount虽然确实加了2次，但只减了1次，remainingElementCount依旧还是正的。按照这个issue的描述和我之前的理解，这POC应该是没有错误的。正当我疑惑的时候，随手把Promise.all.call修改为原issue描述的Promise.allSettled.call，如同中分和背带裤组合，出现了神奇的反应。  
  
  
```
```  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8FYXjic4EichcVGNsHQxXqO6vQyrrseNjKvlBtyAgRhqjKNNibhSEFabToouxNZFz8jicMkOjibshSPlpw/640?wx_fmt=other&from=appmsg "")  
  
                                                                       图 3.3.2  
  
  
成功触发了漏洞，remainElement变量先加了2次，然后连续减了2次，最终命中了remainingElementsCount==0的这个assert，发生了崩溃。  
  
至此由v8CTF的POC反推测构造出CVE-2020-6537的POC就成功了。  
##         
## 3.6：CVE-2020-6537 POC总结：  
  
  
◆我们可以直接修改构造器的resolve方法，实现同时调用onFul和onRej(fullfill和reject)函数对象，也就是issue里面描述的resolveElementFun  
 和 rejectElementFun函数对象。  
触发PromiseAllResolveElementClosure这个torque函数执行两次或两次以上的效果。这个无论是用Promise.all.call还是Promise.allSettled.call都能实现。  
  
  
◆Promise.all.call和Promise.allSettled.call虽然都会调用PerformPromiseAll和PromiseAllResolveElementClosure这两个torque函数，但是其实底层的逻辑并不完全相同，之前潜意思认为torque函数大概是和这些功能1：1的关系显然是错误的。可以推测出PerformPromiseAll和PromiseAllResolveElementClosure这两个torque函数都只是v8实现Promise.all.call和Promise.allSettled.call逻辑的一部分，而这个issue描述的remainingElementCount计数出现错误的情况却只有Promise.allSettled.call的实现中有。  
  
  
到了这一步成功触发了remainingElementCount计数结果为0的情况，命中了remainingElementsCount==0的这个assert，引发了Debug版本下面的崩溃，但是release版本下并没有这个DebugCheck，所以在release版本下，后续能会在这个错误逻辑之下继续运行。  
##        
## 3.7 ：从remainingElementCount变量计数错误到越界读写        
  
        
  
那么这个remainingElementCount变量计数的错误怎么会变成v8的安全漏洞呢？原因就是Promise.allSettled.call会将处理的结果作为FixedArray数组，传递回给用户JS环境，这时候我们就能任意操作这个FixedArray数组。然而因为remainingElementCount的计数错误发生了错误，v8在处理Promise.allSettled.call过程中会提前进入remainingElementCount==0的判断，在v8处理完Promise.allSettled.call全部逻辑之前，让我们的提前获得这个FixedArray数组，如图 3.3.3代码所示。  
  
     ![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8FYXjic4EichcVGNsHQxXqO6vPF4icYkjUcFCDVbMtnvGIEvPvrzThOsJQTUAWfU8Q0OWNF1xvLCEZcw/640?wx_fmt=other&from=appmsg "")  
  
  
                                                                          图 3.3.3  
  
         
  
这时候我们可以把获得的这个FixedArray改为dictionary Array。然而此时v8其实并没有完成处理完Promise.allSettled.call的全部逻辑，在我们改变这个数组类型以后，依旧会执行到这个torque函数，并在(图 3.3.4)values.objects[index]=updateValue代码片段中，还会将数组作为FixedArray的结构，写入进去后续的uodatedValue。并且延续FixedArray的数组结构来继续操作这个数组直到整个流程彻底的结束。造成的结果就是FixedArray和dictionary Array数组数据结构的混淆使用，导致了越界写入。  
  
         
  
因为覆盖写入的是回调的结果这种东西，所以覆盖写入的内容其实并不是我们能任意控制的，这个漏洞的实际利用可能不是那么容易。  
  
    ![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8FYXjic4EichcVGNsHQxXqO6vsRBia7n0ibO1rNFKwh4icwHR6Em4ticmt7vwStCME9Feia3N5wicUS0p0o0Q/640?wx_fmt=other&from=appmsg "")  
  
  
                                                                          图 3.3.4  
  
         
#   
  
```
```  
  
  
  
让我们仔细的看一下这段代码，  
  
     ![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8FYXjic4EichcVGNsHQxXqO6vz1rjmQibcPzCLXUrXfn5jkBeTR91hJsQ2rZPNARyzVONyO1DNXlHJJg/640?wx_fmt=other&from=appmsg "")  
  
  
                                                                           图 4.1.1  
##         
## 4.1：torque源码分析  
  
  
◆v8进入PromiseAllResolveElementClosure这个builtin中先是取出传进来的数组的values，然后将这个数组的values作为FixedArray，再以这个FixedA数组和Context作为参数创建1个arrayMap，接下来使用这个arrayMap来创建1个NewJSArray，随后把这个NewJSArray作为参数进入这个Call函数，通过前面分析我们知道这个数组即会当作参数，也会作为结果最后被用户接管。这时候这个Call的栈上面就会保留着对这个FixedArraay数组的引用，然后轮到用户JS接管这个数组。  
  
  
那如果我们想办法在JS层面触发垃圾回收，然后把这个数组释放掉，会出现什么情况呢，答案是什么都不会出现，v8会标记这个数组的内存，然后把内存相关的引用都放在一起，集中销毁都释放掉。  
  
  
https://blog.exodusintel.com/2023/05/16/google-chrome-v8-arrayshift-race-condition-remote-code-execution/  
  
          
  
但这里有一个和这篇文章提到相似的点，都是在同步过程中维持着一个FixedArray的引用  
  
  
◆如果这时候我们对这个数组进行.shift()操作，v8会创建一个新的FixedArray，同时会将原本的对象标记为Fillerobject，这个Fillerobject是垃圾回收中的一个特殊的类型，v8垃圾回收的过程中会认为这个地址后续还会被v8使用。所以在.shift()操作后立马触发垃圾回收的话，v8会新开辟一块新的内存，然后将新创建的FixedArray以及其他相关的对象一起放到新的内存空间，再将原本的内存释放掉，而这个call栈里的对这个数组因为被标记为Fillerobject，被认为后续还是能被v8使用，就并不会被垃圾回收处理掉，还会指着原本Fillerobject的地址，这样就形成了了悬垂的指针。  
  
           
  
如果在这个垃圾回收后再次进行垃圾回收的话，v8就会尝试对这个call的栈里面数组索引指向的空间进行回收，访问到已经释放的堆块，造成内存访问错误。  
  
          
  
关于v8数组的shift操作的详情，可以参考上面给的这个文章。  
  
       
## 4.2: POC构造的困境  
  
          
  
 虽  
然仔细的研究了一段时间这个issue的介绍，觉得也明白了这个root case，也想到了发生的问题跟  
  
https://blog.exodusintel.com/2023/05/16/google-chrome-v8-arrayshift-race-condition-remote-code-execution/  
  
里面描述的场景非常相似，不过忙活了好久始终没能写出POC，估计是自己对CG和这个issue的触发的理解还是差了点意思。  
  
           
  
参考原作者构造给出的POC，发现始终没有成功，导致失败的最大原因是使用的数组必须大于JSArray::kMaxCopyElements，才会让这个call的栈上保留着这个数组的引用，原因为什么暂时就还不得而知了，留着后续慢慢研究吧。  
  
      
  
最终POC变为：    
  
  
```
```  
  
  
  ![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8FYXjic4EichcVGNsHQxXqO6vmmEk45OeXwr7ibzL8PoRn6ScG2w2eg9GyoaNO3pibZVldkK2ouccAjKA/640?wx_fmt=other&from=appmsg "")  
  
  
                                                                       图 4.1.2  
  
  
这个issue的利用涉及的GC，需要对v8的堆管理策略比较了解，个人觉得利用难道可能比之前分析的两个更难点。都忘记了一开始是想研究v8沙箱的。     
  
  
# 参考：  
  
https://v8.dev/docs/torque  
  
https://issues.chromium.org/issues/40052834  
  
https://issues.chromium.org/issues/40068417  
  
https://blog.exodusintel.com/2023/05/16/google-chrome-v8-arrayshift-race-condition-remote-code-execution/  
  
https://kaist-hacking.github.io/pubs/2024/lee:v8-ctf-slides.pdf  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FYXjic4EichcVGNsHQxXqO6v5lUTqiamtY3xsIg2vDDUD2pDtZNzH3IQSayD6S2Z3RicHeckmPFppNTw/640?wx_fmt=png&from=appmsg "")  
  
  
**看雪ID：苏啊树**  
  
https://bbs.kanxue.com/user-home-808412.htm  
  
*本文为看雪论坛精华文章，由 苏啊树 原创，转载请注明来自看雪社区  
  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458562562&idx=1&sn=1b52c3eedf8c25b1f274cab92e461b3e&chksm=b18d808886fa099ea91ce8fdbc1de8c44154c1896e00b4af0bb378cb82cf7d7ab6de5de5fff9&scene=21#wechat_redirect)  
  
  
  
**# 往期推荐**  
  
1、[恶意木马历险记](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458562562&idx=2&sn=1d66bb3141b820c717f86d349660e9ec&chksm=b18d808886fa099efc353521af0839c9bf5fbd4cae2985cf3a9a6ea28fa617f8300c0ab115a7&scene=21#wechat_redirect)  
  
  
2、[VMP源码分析：反调试与绕过方法](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458562488&idx=2&sn=fe5bd1498948137775db5f454bd5a6a2&chksm=b18d9f3286fa162491072b9cd141784c1a60b2b00fd8203f865c51ef753e3f45573a78810949&scene=21#wechat_redirect)  
  
  
3、[Chrome V8 issue 1486342浅析](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458562487&idx=2&sn=b2d6ad2776d37f416933e1439f244430&chksm=b18d9f3d86fa162b5edfd1c8e616c9ea5460cf21afc5d41cfd8122fbc73830c61f125c8a4960&scene=21#wechat_redirect)  
  
  
4、[Cython逆向-语言特性分析](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458562186&idx=1&sn=bd95ad7951c93578ed5f0cbb1971332c&chksm=b18d9e0086fa1716382e78c54135a0a296fa215688b9a741576d41897729625284287e598faf&scene=21#wechat_redirect)  
  
  
5、[Boofuzz在二进制IOT漏洞挖掘中的简单运用](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458562108&idx=1&sn=690de0bb7bffe7752c4e3f3b48a0b5aa&chksm=b18d9eb686fa17a022250b626842ea7937dc14dcb6e226700ec5befcada72ef7d0509427c388&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fgp5LpLicJzyZBcAObibW18fB4z3Cib1L88C8iaTm7RUNM60aITCu3gGEsPDHJ1CqI3iamHfF4HCicjlLg/640?wx_fmt=gif&from=appmsg "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fgp5LpLicJzyZBcAObibW18fB4z3Cib1L88C8iaTm7RUNM60aITCu3gGEsPDHJ1CqI3iamHfF4HCicjlLg/640?wx_fmt=gif&from=appmsg "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fgp5LpLicJzyZBcAObibW18fB4z3Cib1L88C8iaTm7RUNM60aITCu3gGEsPDHJ1CqI3iamHfF4HCicjlLg/640?wx_fmt=gif&from=appmsg "")  
  
**球在看**  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fgp5LpLicJzyZBcAObibW18fKNoDzicfjlGZia14Kjc7lYCXZZwglgVRKt20dLSGDBALfiaNJD5WMnkIw/640?wx_fmt=gif&from=appmsg "")  
  
点击阅读原文查看更多  
  
