#  ALPC 之殇 - 8月未知 Windows 在野提权 Nday 漏洞研究   
 奇安信 CERT   2025-01-09 00:01  
  
综述  
  
该漏洞样本为前段时间奇安信威胁情报中心日常在野漏洞监控运营经发现，其最早被上传时只有6个查杀。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmS6B6eD5WlBrIb1ymOO4BLwcShicXfr8n8KYcjuWGTTjxmL9lbTUFdQjw/640?wx_fmt=png&from=appmsg "")  
  
  
经过分析确认该漏洞应该是在八月的微软补丁中被修复，是一个被修复的未知nday利用，运行的具体效果如下所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmS0Qr4sI7mCic1PphsgQu5K2qDMUs19eD0I05BCRtSvF5o4Gh1Za3qd9A/640?wx_fmt=png&from=appmsg "")  
  
  
漏洞样本分析  
  
这里首先过一下整个样本，样本开始首先启动了一个cmd，之后调用核心fun_vulstar。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmShO9wqChtS7ia25uVKjoO8fZtyNRdHpBGKbl1eSQq82MiaWQsBcAHFwJA/640?wx_fmt=png&from=appmsg "")  
  
  
fun_vulstar中判断当前的机器的相关版本。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSqRzrib0KQtEULmoRKLbyqBy8miapEONKoCqFp9Hxk8dpMBhkpKx5FkzA/640?wx_fmt=png&from=appmsg "")  
  
  
之后动态获取部分系统api的函数地址。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSkEFvOn1XOeib7GR9vNO9tcEYXjiatE1znibHm8rskibwJ025lBnflBmplw/640?wx_fmt=png&from=appmsg "")  
  
  
开启一个新线程，调用漏洞利用函数fun_expProc。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSZU0jb1GYkDr8Mjn6FkTowEpVicO5jVYZooYjb9l25TtSQ655ym9qiaNg/640?wx_fmt=png&from=appmsg "")  
  
  
fun_expProc调用fun_IoRingandPipeinit。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSxt98A7XymW5cAibO8qCzwdZT6HqecQudic9N3vuPVVBKnNiarsNQ2wdPw/640?wx_fmt=png&from=appmsg "")  
  
  
该函数中判断目标系统的版本是否支持I/O ring的提权方式，如果支持，则完成相关的初始化工作，并返回   
var_ioringRegBuffers/var_ioringRegBuffersCount，这种方式具体利用细节可以看以下文章（https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/），简单来说这是一种Windows 11 22H2+后独有的利用原语，可以将 Windows 内核中的任意写入甚至任意增量错误转变为对内核内存的完全读/写，在i/o ring的利用中通过任意地址写入修改_IORING_OBJECT对象的以下两个字段（var_ioringRegBuffers/var_ioringRegBuffersCount），从而实现全局内存读写。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmShMoFf7iaPFMllaUB0IHGRHPNwiaAibAmQsNl2RpeozZrmFae2qMEuZE6A/640?wx_fmt=png&from=appmsg "")  
  
  
之后根据是否使用I/O ring提权来完成先相关的初始化工作。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSgs9bxEeKzLGN49dWicc9Nzmt4E7wlChJ73ibuXribpeXFpKrwQHZibq18Q/640?wx_fmt=png&from=appmsg "")  
  
  
以使用I/O ring提权方式举例，这种情况下会在0地址上spray 0x2000长度的var_ioringRegBuffers-0x2c地址。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSklJ6t30htbRydlribzXt2fZTMeeS0TaH0icuEfBibyT1m6KmFibja5hQ7w/640?wx_fmt=png&from=appmsg "")  
  
  
Fun_init中则用于在0x1000000000的地址上分配长度0x10000的内存，并获取NtCreateWorkerFactory返回的WorkerFactory对象的地址var_KWorkerHandleaddr。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSz9yKEqCCH4SRfpnVMmakV5CbFNZObJC8HiaPMJAaG5gZlHcEgZ8Grbw/640?wx_fmt=png&from=appmsg "")  
  
  
 接着往下，进入一个大循环，其中fun_NtAlpcConnectPort用于调用NtAlpcConnectPort创建一个Alpc连接对象，连接对象创建完毕，开启两个线程分别调用函数fun_NtRegisterThreadTerminatePort/fun_expWorker。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSABbmVgkINyxqo7icXsAZRWpWIymhAwxcwnCeBrlbfPibrIGCTuiccxCAQ/640?wx_fmt=png&from=appmsg "")  
  
  
fun_NtAlpcConnectPort的功能很简单就是调用NtAlpcConnectPort，和系统的pdc alpc port 服务连接，并返回对应的alpc porthandle。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSefGrBCRydVRrLRhrY8Mq2AJ5bjbzhXEKwMkasNaZ8qFQkzHicGnPHTw/640?wx_fmt=png&from=appmsg "")  
  
  
如下图，两个线程开启后，调用fun_setEvilmessage设置一段自构造的内存，之后通过WaitForSingleObject监控fun_NtRegisterThreadTerminatePort对应的线程1是否结束，如果结束，则进入图中红框的部分，这里的核心是函数fun_NtCreateEvent。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSrWyl317WdP3dQUOCbDulfswwdiciaWetOEicIfLJTMHjicTKvPLRxdeia5A/640?wx_fmt=png&from=appmsg "")  
  
  
fun_setEvilmessage完成了一段内存的构造，其会根据一开始获取的系统版本，进入不同版本的内存构造。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSFf8PKQHickFCJksZk97Lk6JdAvibEb3X8icUxYZKJNhu6dHrphz1iaYVjQ/640?wx_fmt=png&from=appmsg "")  
  
  
最终的效果如下所示，构造的内存都是从66130这个位置开始，这里我们测试的系统版本构造的内存如下红框中所示，可以看到无论哪个版本，最后位置放置的都是前面获取到的var_KWorkerHandleaddr的地址加一个偏移。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSgPWufbicxP1UnMqQPmWQYicIVgLq4oxz4G7fHibZBjxzqDcI30OeTuzJA/640?wx_fmt=png&from=appmsg "")  
  
  
可以看到fun_setEvilmessage调用完之后，再次初始化了一段7FF7F21671B0 开始的内存，fun_setEvilmessage中构造的7FF7F2166130被放置到7FF7F21671B0 +0x20处的7FF7F21671D0位置。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSaRgxbU7IAxydqMFCCXaPoT74XAwVyONXhzG2ZE64ibDEWagicPk05gjQ/640?wx_fmt=png&from=appmsg "")  
  
  
7FF7F21671B0 最终的内存构造如下所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSBhbic1JibLcImBcCQSPUCGxy1nG7S5xibOKp1t8ZvqOHejCewyaeoyYqw/640?wx_fmt=png&from=appmsg "")  
  
  
fun_NtCreateEvent函数会根据第三个参数进入两个分支，如果非零，则进入以下分支，循环调用NtQueryLicenseValue。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmS7vEribicIj1lnW7FprljYvnL2Sb26Cd4wnB6X6GlBY2yWfbiavE9kLSuQ/640?wx_fmt=png&from=appmsg "")  
  
  
否则进入以下分支，可以看到主要核心是调用NtCreateEvent，注意第二个大红框中同样在设置7FF7F21671B0处的地址，设置的内容和外层函数中一致，而7FF7F21671B0则被设置为NtCreateEvent参数ObjectAttributes.ObjectName。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSKqVBAvE5FicpRMWdsOvNXwNNQBwYwQaPWg9kVkicfibh4A9uJ3PWptGzg/640?wx_fmt=png&from=appmsg "")  
  
  
接下来详细看两个线程的作用，线程一调用函数fun_NtRegisterThreadTerminatePort，该函数很简单，前面的alpc porthandle var_alpcConnectionHandle创建成功，则对其调用函数NtRegisterThreadTerminatePort。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSJPZpIRvH8o1n9Exy9OlcsjiaPet57bF4yfOnoPOotgvr8XBo947sqEw/640?wx_fmt=png&from=appmsg "")  
  
  
NtRegisterThreadTerminatePort这个函数是一个未公开的函数，但是网上有不少相关的信息，简单来说这个函数的作用是将一个的alpc porthandler和当前的线程关联，当线程退出时，内核调用NtTerminateThread后会已发送一条LPC_TERMINATION_MESSAGE到对应的alpc服务端口。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSbhKJibsWIgxMYdjkiaicWyAFJzyZSfHFiacDYvugljB2pICwsZicZgGJmgA/640?wx_fmt=png&from=appmsg "")  
  
  
实际来看该函数，调用ObReferenceObjectByHandle获取该porthandle对应的内核alpcport对象，之后分配一个长度为0x10的内存pool，将该对象保存在该内存pool 0x8偏移处，之后将该内存池和当前线程_ETHREAD对象相互引用，有意思的是该函数NtRegisterThreadTerminatePort在k0shl的对CVE-2022-22715漏洞（https://whereisk0shl.top/post/break-me-out-of-sandbox-in-old-pipe-cve-2022-22715-windows-dirty-pipe）的利用中作为一个工具函数以实现长度为0x20的对象spray。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmS28KjrJmF0SPULiaGE3RMnf8QAibINibEFbibkiboDquFRn2fVJb5iaLqdLUQ/640?wx_fmt=png&from=appmsg "")  
  
  
之后则是第二个线程调用函数fun_expWorker，其内部根据标记位调用fun_loopNtSetInformationWorkerFactory。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSq3pOnXEOra1lByKCupSF3R7U4FR1eQnMQPjGTQZW4nvRVnYjSpnwxg/640?wx_fmt=png&from=appmsg "")  
  
  
fun_loopNtSetInformationWorkerFactory中首先调用fun_setEvilmessage，  
之后后调用NtAlpcSendWaitReceivePort，该函数通过前面NtAlpcConnectPort函数获取的pdc porthandler向pdc alpc port服务发送了一条消息，消息内容为v6。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmS0wqZddxW2HjuzJe28L1OAmRrHDf2RNGwHeu6O5PvY5NsHKR7HblpYA/640?wx_fmt=png&from=appmsg "")  
  
  
有趣的是当NtAlpcSendWaitReceivePort调用完毕后，似乎之前的WorkerFactory被修改了，这导致通过该WorkerFactory调用NtSetInformationWorkerFactory可以实现任意地址写入，代码中分为两种类型进行利用，如果是通过I/O ring的方式，则依此通过修改I/O ring利用中的关键var_ioringRegBuffers/var_ioringRegBuffersCount地址从而获取全局读写的能力，可以看到NtSetInformationWorkerFactory的第三个参数为写入的内容，而写入的目标地址则被spray在0x1000000000上，也就是说此时通过NtSetInformationWorkerFactory可以实现基于0x100000000-0x1000002000范围上保存随机地址的写入，而另一种提权方式则是通过该任意地址写入直接修改PreviousMode，PreviousMode地址同样被spray在0x100000000-0x1000002000上，NtSetInformationWorkerFactory调用设置PreviousMode后，通过NtReadVirtualMemory/NtReadVirtualMemory来获取全局读写的能力。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSiapiaNueiaatJjibJMbPSfOzWNibGcUme1Vbrs3LTzfU32G3VcjWsxqM1pQ/640?wx_fmt=png&from=appmsg "")  
  
  
修改PreviousMode的利用方式最终在fun_eopCmdProcess中通过NtReadVirtualMemory/NtReadVirtualMemory实现提权。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSmgADRpbp7YYdJA0dYEicSBnlYpHaV2XQIWoeRznpxbW1ORpFg6yW56Q/640?wx_fmt=png&from=appmsg "")  
  
  
I/O ring的利用方式则在fun_tokenChangewithSystem中通过全局读写能力直接替换cmd进程的token为system实现提权。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSPj98D4tX2K4ONrWQoGOaZicV0sCgZ7fnL4K723HhduMmIvtTTzz9PjA/640?wx_fmt=png&from=appmsg "")  
  
  
I/O ring任意地址读。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSeQmicbY3XtT4gV6JlPMeP4ibF48q8p0NM8ibTeG1luUEcelhYofuKdh8w/640?wx_fmt=png&from=appmsg "")  
  
  
I/O ring任意地址写入。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmS3yKWvLBILicj14NkmMLdGmBuaibIpLDfVOOqiayPDHnwic900AeUtGqUeg/640?wx_fmt=png&from=appmsg "")  
  
  
之后通过的写入功能修改畸形的WorkerFactory，可以看到其修改的位置是分别是WorkerFactory-0x28/-0x30的位置。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSiaLQEq0tlChJYiaAGuRl6bcx4XndoeHaj2PRm5mb7ktHp6BLRmMtFJ0w/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
漏洞详细分析  
  
通过以上样本的分析，我们基本可以得出一个结论，即NtAlpcSendWaitReceivePort调用之后，对应的var_KWorkerHandleaddr内核对象应该是被修改了，从而导致使用该var_KWorkerHandleaddr调用函数NtSetInformationWorkerFactory可以做到0x100000000-0x1000002000地址范围上的指针内容的写入，但是这里目前来看也是猜测（只是从我多年的直觉而言非常确信），因此此时我们总结出以下几个核心的问题：  
  
  
1.NtSetInformationWorkerFactory中的var_KWorkerHandleaddr是否是被修改了，为何会导致NtSetInformationWorkerFactory可以在0x100000000-0x1000002000地址范围上的指针内容的写入。  
  
2.如果var_KWorkerHandleaddr是被修改了是如何实现的？  
  
3.在基于以上两个问题成立的情况下，NtRegisterThreadTerminatePort/NtAlpcSendWaitReceivePort的作用如何，我们的猜测是NtAlpcSendWaitReceivePort导致了var_KWorkerHandleaddr的修改。  
  
4.fun_NtCreateEvent中大量的NtCreateEvent调用起到什么作用。  
  
5.fun_setEvilmessage中的7FF72DE66130及外围的7FF72DE671B0中构造的内存有何作用？  
  
  
 针对第一个问题我们直接来看NtSetInformationWorkerFactory函数的实现，这里我们知道该函数的第三个参数是写入的value，因此直接在该函数中找该参数的赋值位置，可以看到比较合理的只有这里，直接下断。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSSGDj3usu8E5TK5X7Cguu4jhGtNEc5eTvN0l5V6IOhz2G9dADkCic7Zw/640?wx_fmt=png&from=appmsg "")  
  
  
运行之后断下，赋值目标rcx通过!object看就是一个TpWorkerFactory的内核对象，其地址也和exp运行时获取var_KWorkerHandleaddr的地址一致，可以看到这里var_KWorkerHandleaddr+0x10的位置已经被修改为0x10000000110。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSQp6qfOuoILBKYOBZM0Hs33Jjp6ia4ZJIicgUkmzf9B33Xby0s68Ry0ew/640?wx_fmt=png&from=appmsg "")  
  
  
而0x10000000110这个位置之后则被exp spray上成了var_ioringRegBuffers。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSSmQd15R7WSt101CI1iaPZENvujwvWo3aZkYEklic4TVFrtv96YI6TurQ/640?wx_fmt=png&from=appmsg "")  
  
  
赋值完毕后var_ioringRegBuffers被修改为ffff0000。之后通过将ffff0000设置为0，以实现I/O Ring的全局读写原子，因此这里确认NtSetInformationWorkerFactory实现了任意0x100000000-0x1000002000位置范围上指针的写入，是因为var_KWorkerHandleaddr+0x10位置的指针被设置为了0x100000000-0x1000002000区间的一个地址，这也是为什么var_KWorkerHandleaddr需要spray到这个区间的原因。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSARRT3lQRCLIphsT4tIgiaypTapyI5XImTQ2084NgP8icfBE5HovZEOuw/640?wx_fmt=png&from=appmsg "")  
  
  
那紧接着第二个问题，var_KWorkerHandleaddr是如何被修改的了？我们直接对exp中获取到的var_KWorkerHandleaddr+0x10处下内存写入断点，运行exp断下之后如下所示，此时是还未修改前，可以看到0x10偏移处这个地址通过!object并不能识别出来。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSmOibvd6yqaMkWmr1uhZK3g5qHFo1QiakcMBGia5jd2jlS3R4MXQDzbsEA/640?wx_fmt=png&from=appmsg "")  
  
  
继续运行后，其修改发生在内核的KeSetEvent函数中，需要注意，这里的修改并不是一蹴而就的，KeSetEvent执行的过程中该指针被修改多次，这里只列出比较重要的两次，如下是第一次修改。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSv4D2kahyWHjmBRgBDvGq1v4mx3iaicdgibKZa1vLLWAG6GMlnMv0oEhLA/640?wx_fmt=png&from=appmsg "")  
  
  
第二次修改：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSj4sandc0YEasd7648zJEASOI8UVNKUop115nic89Ro7Q5tVYoP490og/640?wx_fmt=png&from=appmsg "")  
  
  
在ida中可以看到，实际上KeSetEvent中是在修改event对象中的header，第一次修改如下。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmS1gpxujkIJlonSBMvApUqibQpOSfMCszLygqr0UTnlJxD5ribzibGoDUicQ/640?wx_fmt=png&from=appmsg "")  
  
  
第二次修改如下，从这里就可以确认我们的var_KWorkerHandleaddr地址的对象+0xd/var_KWorkerHandleaddr地址的对象+0x11被直接传入了KeSetEvent函数中作为一个event对象处理，最终造成了该var_KWorkerHandleaddr地址的对象0x10处指针的修改，由于每次var_KWorkerHandleaddr地址的对象都不一致，因此0x10处的指针也是变化的，这就造成了0x10处的指针最终被修改的地址是一个区间值（处于0x100000000-0x1000002000），因此写入时目标地址才需要在该区间内进行spray。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSBSkkib8r3WC19UXiaueAnfOJMDr4yNapw78qGpQPbJkjXy4zgGXpIvSA/640?wx_fmt=png&from=appmsg "")  
  
  
此时调用KeSetEvent时的堆栈如下，可以看到其调用的源头正是NtAlpcSendWaitReceivePort，因此之前的猜测就没有任何问题了，由于漏洞导致NtAlpcSendWaitReceivePort修改了var_KWorkerHandleaddr地址的对象，从而使得在NtSetInformationWorkerFactory实现的任意0x100000000-0x1000002000范围位置保存指针的写入。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmStHKMSV737ZypcKnHxDt3YsU6fiaFtLSrkIB7qiapLibVbFIOf8nuQCCtg/640?wx_fmt=png&from=appmsg "")  
  
  
完整调用栈如下所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSEYE95Y1XUyUzaR9XsdrNX2WQ1oXwtBeHroHFWTP0zuLaOCRJZxskEg/640?wx_fmt=png&from=appmsg "")  
  
  
那到底是什么样的漏洞导致了NtAlpcSendWaitReceivePort可以修改var_KWorkerHandleaddr地址的对象？从上述分析可以基本确认和NtRegisterThreadTerminatePort/NtAlpcSendWaitReceivePort这两个alpc函数有关，这里最简单的分析思路即直接逆向推导，监控调试NtAlpcSendWaitReceivePort到KeSetEvent的整个过程既可以知道var_KWorkerHandleaddr对象的修改是如何实现的，但是在这个之前我们需要先对Windows中ALPC这个机制有一个了解。  
  
   
  
**ALPC**  
  
ALPC 是一种快速、功能强大且在 Windows 操作系统（内部）中使用非常广泛的进程间通信机制，ALPC 通信的主要组件是 ALPC 端口对象。ALPC 端口对象是一个内核对象，其使用类似于网络套接字的使用，其中服务器打开客户端可以连接的套接字以交换消息，ALPC通信场景涉及3个ALPC端口对象，第一个是由服务器进程创建的、客户端可以连接的ALPC连接端口Connection port（类似于网络套接字） 。一旦客户端连接到服务器的 ALPC 连接端口，内核就会创建两个新端口，称为ALPC 服务器通信端口Server Communication Port和ALPC 客户端通信端口Client Communication Port。  
  
一旦服务器和客户端通信端口建立，双方就可以使用ntdll.dll公开的函数NtAlpcSendWaitReceivePort向对方发送消息，客户端可以使用函数NtAlpcConnectPort 开启一次连接，因此作为客户端的使用来说，以下两个函数就够用了。  
- NtAlpcConnectPort  
  
- NtAlpcSendWaitReceivePort  
  
首先是NtAlpcConnectPort，该函数用于连接alpc服务端，调用成功后会返回一个PortHandle，其在内核就是前面提到的ALPC 客户端通信端口。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSzqicPqbFWyKe7gxaooaWxbFkQZMsrp9KFSGV2J3wVWWnZibWBurDEYLg/640?wx_fmt=png&from=appmsg "")  
  
  
完成Connect，获取对应的portHandle后，就可以通过NtAlpcSendWaitReceivePort进行消息的发送和接收，这里需要注意该函数同时可以进行发送和接收的操作，此外，客户端通过该函数发送消息并不是直接发送到服务端，其需要通过内核进行一层转发，内核会负责路由所有消息，内核负责将消息放置在消息队列，通知各方收到的消息以及验证消息和消息属性等其他事情。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSQCkMfiaOe2CExribTw7Ur3MK332Q7TC1jllQuibspGgDGbrdrYDnnZuUg/640?wx_fmt=png&from=appmsg "")  
  
  
   
如下所示可以看到触发var_KWorkerHandleaddr地址的对象修改的NtAlpcSendWaitReceivePort函数调用堆栈以红线为分割，首先是NtAlpcSendWaitReceivePort的发送消息部分，之后通过callback通知对应的pdc alpc port服务实际处理程序pdc.sys，在pdc.sys中完成相关的处理，因此我们直接跳过NtAlpcSendWaitReceivePort进入pdc中来看看pdc.sys是怎么处理收到的消息的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSnNkPJXmMW5VTTF2o9ibjOdk3nqhl9VI1alI8VMgkjAe8Xc5Hdgpjzew/640?wx_fmt=png&from=appmsg "")  
  
  
首先pdc中处理alpc的核心函数在PdcpAlpcProcessMessages中，该函数中是一个while循环，其内部调用ZwAlpcSendWaitReceivePort接受内核发过来的消息，ZwAlpcSendWaitReceivePort就是对NtAlpcSendWaitReceivePort的一个包装，我们前面提到过alpc的机制中发送和接收都是通过函数NtAlpcSendWaitReceivePort实现，且发送和接收方不直接对接，中间由内核进行路由，并最终在PdcProcessMessage中进行消息的处理，其两个参数分别是ReceiveMessage;MessageAttribute，我们结合之前的调用栈来看看var_KWorkerHandleaddr地址是怎么传入修改的，这里注释中已经给出了答案是在poi(poi(poi(poi(MessageAttribute)+0x20)+0x20)+0x6c8)的位置，其来自于MessageAttribute。MessageAttribute则为poi(ReceiveMessageAttributes(v5)+8)的位置。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSvbofE0VGjXmEQUCoozQ3h9N5K0NtmdgSqTG1gbARgDMVSiaf2ScYU7Q/640?wx_fmt=png&from=appmsg "")  
  
  
下面我们实际来看看整个传入的过程，函数PdcProcessMessage调用PdcProcessReceivedUserMessage。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSa7pmuu5oyEeHnpiaka7WzXjlBLb7LzicXexXwaq5XfwO3Srjg9IRNpAg/640?wx_fmt=png&from=appmsg "")  
  
  
PdcProcessReceivedUserMessage中调用PdcpTaskClientReceive。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSBtUJjP93UfNrVLrj4zmk58MS3iaYhByG0g949Ys1DjaiaM1UsTtw7ib0Q/640?wx_fmt=png&from=appmsg "")  
  
  
PdcpTaskClientReceive中调用PdcpDereferenceTaskClient。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmS76GibFeedG7kAlTxBqic6HOhBicyvSYKxicgAGQ8oTNFCmvrEzEMHu0bibA/640?wx_fmt=png&from=appmsg "")  
  
  
PdcpDereferenceTaskClient中调用PdcpTaskClientAcknowledge。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSibWyYyWa1NT5CL4B8wtckP1vkENnqtpIG9ibsiadTlPH7xq0PQiaLdv06Q/640?wx_fmt=png&from=appmsg "")  
  
  
PdcpTaskClientAcknowledge中调用PdcSendKernelMessage。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSGZ7gxBFql0ueE4fLaqDcIDkjw3tfHexwDgQrFdjSE6OjIGLCn4sBiaA/640?wx_fmt=png&from=appmsg "")  
  
  
PdcSendKernelMessage中调用PdcPortQueueMessage。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSjLnXejO5Et5ueDYFbqIyxDqGchAysX5UibDPEh4wHxQbtCia3UvCjRjQ/640?wx_fmt=png&from=appmsg "")  
  
  
PdcPortQueueMessage中调用KeSetEvent，最终传入的poi(poi(poi(poi(MessageAttribute)+0x20)+0x20)+0x6c8)将被修改。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSDqON6cJuCq9TTvEica4sP3wpoM4RhXX1JvvLGoYU2N0oMCAZOOQwPcg/640?wx_fmt=png&from=appmsg "")  
  
  
看到这里仔细的读者可能会发现有问题的地方，即MessageAttribute是怎么来的，要知道我们的利用样本中调用NtAlpcSendWaitReceivePort时只有前三个参数，且只设置了SendMessage，而对应的SendMessageAttributes参数则是空的，为什么我们在PdcpAlpcProcessMessages中，却能收到对应的v5 ReceiveMessageAttributes，还能从中提取到MessageAttribute，MessageAttribute是怎么来的？  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSQVyunaBZargG2x8m7O04f26ncyEEk4tY49mUEYDj8NzwegCcX18Zyw/640?wx_fmt=png&from=appmsg "")  
  
  
这一问题其实开始也困扰了我许久，但是这其实是一个思维误区，我们发送的时候确实是没有设置对应的SendMessageAttributes，但是由于alpc中发送方和接受方并不是直接对接，这里接收方对接的其实是内核，而pdc接收方在接受ZwAlpcSendWaitReceivePort中是设定了对应的ReceiveMessageAttributes的，因此该参数会在内核路由的时候通过内核生成。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSWE9o0q9BhibfEQsDJI55DF8PCDIODo6m3ykiaYWzV3KXl07pwGibdlpSQ/640?wx_fmt=png&from=appmsg "")  
  
  
这里来看NtAlpcSendWaitReceivePort的接受分支代码即可知AlpcpExposeAttributes调用的前提就是先判断ReceiveMessageAttributes是否存在，pdc中的ZwAlpcSendWaitReceivePort设置了该参数，因此内核路由这条消息时会在其中自动设置对应的ReceiveMessageAttributes。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSfLvnn5A1v939Ys0UJbqlic5ZaFUtAskOSvtBo4BC5JYszjeqDHAkngA/640?wx_fmt=png&from=appmsg "")  
  
  
该过程的调用栈如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSoNjWibQPy92xvZkbGEfoBaCj0y1uzZKDwhOLj2licYlHlAyFSYwhtUyg/640?wx_fmt=png&from=appmsg "")  
  
  
搞清楚了messageattribute的来历，我们现在需要确认poi(poi(poi(poi(MessageAttribute)+0x20)+0x20)+0x6c8)是如何被修改的了？通过以上的分析我们可以确认问题应该不出在NtAlpcSendWaitReceivePort的位置，这种情况下就只有另一个函数，即NtRegisterThreadTerminatePort。  
  
这里通过测试发现该利用样本在安装了2024年8月的补丁后，将会失效，为此我们通过bindiff对2024年7/8两月的Windows内核文件进行对比，发现新版本的内核文件中，利用样本使用的NtRegisterThreadTerminatePort函数被删除了！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmS9j7zFNN2fNC9oXv05ibRQJOehxu3kqgAYL6ckFgic0TicpdycYl11NuoA/640?wx_fmt=png&from=appmsg "")  
  
  
该函数的作用如前面的分析可知，是将一个的alpc porthandler和当前的线程关联，当内核调用NtTerminateThread后会已发送一条LPC_TERMINATION_MESSAGE到对应的端口，其调用逻辑如下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmS397zCqkuSBBL80AE57yFD7Ud5rRFm2rtzKDSLkcoxeUh0B783zxX6A/640?wx_fmt=png&from=appmsg "")  
  
  
最终会调用PspExitThread，PspExitThread中有以下的处理，该函数会查看当前线程并获取之前通过NtRegisterThreadTerminatePort绑定的alpc端口对应的内核对象，并通过函数LpcRequestPort向对应的alpc服务端(利用代码中就是pdc alpc port服务)发送一条消息，该消息内容是以300008006开头，也就是前面说的LPC_TERMINATION_MESSAGE。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSuOOwXvWtYpgsKICibaeKO0swnfFBDWssL7oebzHXbL3mpDJozn0TNHQ/640?wx_fmt=png&from=appmsg "")  
  
  
LpcRequestPort如下所示，最终发送通过AlpcpSendMessage实现，实际上Lpc是Windows中Vista之前内部进程进行通信的一种机制，Vsita后被替换为更高效的Alpc，为了保持兼容，可以看到所有的Lpc调用本质上最终都是转向了Alpc  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSNpwhezBY0wpSRn1ic9xSEKUiaYJerW6kmpuwiclARiaYTicK1T9k60MOAvQ/640?wx_fmt=png&from=appmsg "")  
  
  
而我们这里的alpc porthandler实际上同样是pdc alpc port服务对应的alpc端口，其对应的驱动是pdc.sys。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSw0ZBBNGZ2EBm7zYHlbF2l5eZKvHNAK8iahMrQQiaEnpGiazxjVcb3V4Gw/640?wx_fmt=png&from=appmsg "")  
  
  
而进入PdcProcessMessage后，其中有一个分支用于处理LPC_TERMINATION_MESSAGE，如下其判断的正是我们刚才发送的消息300008006中+4的6的位置，而这里PdcFreeClient将用于释放poi(poi(MessageAttribute)+0x20)，而该释放的位置之后应该是被exp中占据，并修改为了一段恶意的内存，该恶意内存中poi(poi(evil+0x20)+0x6c8)指向了一段var_KWorkerHandleaddr，从而在函数KeSetEvent中传入poi(poi(poi(poi(MessageAttribute)+0x20)+0x20)+0x6c8)并修改  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSAKNJGOByUjibwfR7cAbhdR98AdicenG76c0tic8fHEVKSDsCw23YHAEIQ/640?wx_fmt=png&from=appmsg "")  
  
  
那我们接下来的问题就是需要确认：  
  
1.是否是PdcFreeClient造成释放，并之后被重用  
  
2.问题1成立的情况下，这段释放的内存是什么，如何生成的，其为什么在系统发送的LPC_TERMINATION_MESSAGE消息及我们通过NtAlpcSendWaitReceivePort发送触发的消息之间没有修改  
  
3.如何实现的内存占据，我们的猜测是NtCreateEvent，毕竟代码中部NtCreateEvent的spray的操作过于明显。  
  
   
当对应的绑定线程退出时，触发LpcRequestPort的调用，内核将向对应的pdc alpc port服务发送一条300008开头的LPC_TERMINATION_MESSAGE消息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSTnqKhTTDq2lxUfHypIKGMvvSWWl2mwTjP7YsKGJicd0OnAu0tWgic8BA/640?wx_fmt=png&from=appmsg "")  
  
  
pdc alpc port服务在pdc.sys的PdcpAlpcProcessMessages函数中处理接受的消息，如前文所说，alpc中的消息是由内核路由，这里调用ZwAlpcSendWaitReceivePort接受消息，由于此处ZwAlpcSendWaitReceivePort中指定了ReceiveMessageAttributes(v5)，因此内核在路由该消息时也会生成该数据，哪怕实际发送发送方发并没有发送。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSOJXNfTkCJwibR3QHia7CUMo1LojtnVUYquTTIG6WlQyF4nEaPtgVRJ6Q/640?wx_fmt=png&from=appmsg "")  
  
  
PdcpAlpcProcessMessages中调用ZwAlpcSendWaitReceivePort前，通过AlpcInitializeMessageAttribute创建一个ReceiveMessageAttributes的对象。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSGpV1pWLj3lDhlBz73lONMjJQ9wzaJmClhhC2EKlISXic0P3iaBjMiaBBQ/640?wx_fmt=png&from=appmsg "")  
  
  
ZwAlpcSendWaitReceivePort调用，实际还是进入到内核中的NtAlpcSendWaitReceivePort，并进入AlpcpReceiveMessage，并调用AlpcpReceiveMessagePort。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmStYuny4QEdMwiaMUOMAfNuCtnneDw7CY0Ficn1XyAJ1KYLBUsBJYALcYQ/640?wx_fmt=png&from=appmsg "")  
  
  
如下所示，AlpcpReceiveMessagePort的核心在于返回接受消息对应的_KALPC_MESSAGE。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSM6w8WpjJQwW9cGY3bgictJwWFy9BgbWxQMZPicp9wo63gNw9BFDjw1Dg/640?wx_fmt=png&from=appmsg "")  
  
  
这里对应的server connection port端口对象如下所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSr7oMGDwtURVQQIFp9TBnMvLG65bx7SsEfRf9d2hyWENs0IRHKb8yXQ/640?wx_fmt=png&from=appmsg "")  
  
  
nt!_ALPC_PORT的整体结构如下。  
```
0: kd> dt nt!_ALPC_PORT
   +0x000 PortListEntry    : _LIST_ENTRY
   +0x010 CommunicationInfo : Ptr64 _ALPC_COMMUNICATION_INFO
   +0x018 OwnerProcess     : Ptr64 _EPROCESS
   +0x020 CompletionPort   : Ptr64 _KQUEUE
   +0x028 CompletionKey    : Ptr64 Void
   +0x030 CompletionPacketLookaside : Ptr64 _ALPC_COMPLETION_PACKET_LOOKASIDE
   +0x038 PortContext      : Ptr64 Void
   +0x040 StaticSecurity   : _SECURITY_CLIENT_CONTEXT
   +0x088 IncomingQueueLock : _EX_PUSH_LOCK
   +0x090 MainQueue        : _LIST_ENTRY
   +0x0a0 LargeMessageQueue : _LIST_ENTRY
   +0x0b0 PendingQueueLock : _EX_PUSH_LOCK
   +0x0b8 PendingQueue     : _LIST_ENTRY
   +0x0c8 DirectQueueLock  : _EX_PUSH_LOCK
   +0x0d0 DirectQueue      : _LIST_ENTRY
   +0x0e0 WaitQueueLock    : _EX_PUSH_LOCK
   +0x0e8 WaitQueue        : _LIST_ENTRY
   +0x0f8 Semaphore        : Ptr64 _KSEMAPHORE
   +0x0f8 DummyEvent       : Ptr64 _KEVENT
   +0x100 PortAttributes   : _ALPC_PORT_ATTRIBUTES
   +0x148 ResourceListLock : _EX_PUSH_LOCK
   +0x150 ResourceListHead : _LIST_ENTRY
   +0x160 PortObjectLock   : _EX_PUSH_LOCK
   +0x168 CompletionList   : Ptr64 _ALPC_COMPLETION_LIST
   +0x170 CallbackObject   : Ptr64 _CALLBACK_OBJECT
   +0x178 CallbackContext  : Ptr64 Void
   +0x180 CanceledQueue    : _LIST_ENTRY
   +0x190 SequenceNo       : Int4B
   +0x194 ReferenceNo      : Int4B
   +0x198 ReferenceNoWait  : Ptr64 _PALPC_PORT_REFERENCE_WAIT_BLOCK
   +0x1a0 u1               : <unnamed-tag>
   +0x1a8 TargetQueuePort  : Ptr64 _ALPC_PORT
   +0x1b0 TargetSequencePort : Ptr64 _ALPC_PORT
   +0x1b8 CachedMessage    : Ptr64 _KALPC_MESSAGE
   +0x1c0 MainQueueLength  : Uint4B
   +0x1c4 LargeMessageQueueLength : Uint4B
   +0x1c8 PendingQueueLength : Uint4B
   +0x1cc DirectQueueLength : Uint4B
   +0x1d0 CanceledQueueLength : Uint4B
   +0x1d4 WaitQueueLength  : Uint4B
```  
  
  
AlpcpReceiveMessagePort会从_ALPC_PORT对象中获取消息队列MainQueue 中的消息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSd0xicNUfYQbZpa9ZgW0XBCSs0XwMyzNWt8jYSLOvQ7ohQD4qNU2MsKQ/640?wx_fmt=png&from=appmsg "")  
  
  
消息队列中的消息为nt!_KALPC_MESSAGE对象，如下所示可以看到取出的消息对象+0xf0的位置正是发送的3000008消息实体。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmShvTsdr3fKJiaibJibibGHvgaYrxlquzNMs383eY3aBQKopgKls5hdwzskg/640?wx_fmt=png&from=appmsg "")  
  
  
_KALPC_MESSAGE的结构如下所示，0x68开始就是MessageAttributes，0xf0则是对应的消息实体。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmS4EqAxSAldEYYEkHVvWusoPIXKgkWmDGXQVbCYJl65NnGsbVWHncDww/640?wx_fmt=png&from=appmsg "")  
  
  
之后对该_KALPC_MESSAGE进行一些设置，跳转到Label_19。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSRz0ToqS4Q1xSHzwicAZ2n2h0zaJoxzh1PeOBGOymRecUhVmX9ibLGRzg/640?wx_fmt=png&from=appmsg "")  
  
  
AlpcpReceiveMessagePort函数最后将该_KALPC_MESSAGE通过a4返回。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSy66dJpVCQ0ZtY6aUQjCX0rc6xG4Y3r6WyPhVHuPuBKtt1IQqsxYJeA/640?wx_fmt=png&from=appmsg "")  
  
  
如下所示，返回的_KALPC_MESSAGE。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSRqSsCqAxfq7sDWlmalc1BGNTq4LrpmJrPWE7TypgDKUgib8cbm7tuYw/640?wx_fmt=png&from=appmsg "")  
  
  
由于PdcpAlpcProcessMessages中ZwAlpcSendWaitReceivePort设置了ReceiveMessageAttributes参数，也就是这个地方的a4，因此进入函数AlpcpExposeAttributes。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSjiac40N38y6m0MegRCNCkWRmnibg2oic0w8MEpP5bz0zF0Z21ck0iauUwg/640?wx_fmt=png&from=appmsg "")  
  
  
AlpcpExposeAttributes函数调用的参数如下所示，需要注意的是a2=0，a3则是前面AlpcpReceiveMessagePort返回的_KALPC_MESSAGE对象，a4=2000000，a5则是ReceiveMessageAttributes。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSODa6xMRteF5rziciclNhLDUyHibWYibW88R7ticiakticwjM2zdWjSzowp9Hw/640?wx_fmt=png&from=appmsg "")  
  
  
因此这里AlpcpExposeAttributes经过a2，a4的判断后直接进入下图红框中的位置。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSzhyQplQOSibQEaockI2ong9ywtKRrs1wgJn1vEqkNLjnia7ibfjhvT9Bg/640?wx_fmt=png&from=appmsg "")  
  
  
之后会设置ReceiveMessageAttributes，其数据原就是_KALPC_MESSAGE对象中的数据。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSWkxYnTugacaRvKiavAtCWywrPlqPL1NHqNCzEPibiclZmwibq8U5d7zySw/640?wx_fmt=png&from=appmsg "")  
  
  
如下所示rcx就是ReceiveMessageAttributes+8。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSAEHJJxibrb8pItUvG8dvhgLNvZtoxibjIrsicFLRtWbt8WINEQmySDFeg/640?wx_fmt=png&from=appmsg "")  
  
  
这次赋值中核心的是ReceiveMessageAttributes+8位置的赋值，可以看到这里传入的是_KALPC_MESSAGE->MessageAttributes->PortContext。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSAFudYrxcG8BuxP5zCLxTZtQezbg9Z0oSmibxff2NeNx8cibBiaOvAicsEg/640?wx_fmt=png&from=appmsg "")  
  
  
PortContext被设置到ReceiveMessageAttributes+8。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSnBSNTic6pZC11h3CftpEEZbp75pj6klD43c2ghzkib6scwFyibfSWn5Fg/640?wx_fmt=png&from=appmsg "")  
  
  
完成设置的ReceiveMessageAttributes+8如下所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmS9l5p2T6MSzRTiawlibxuzCribyWVYMauBlKzpSxqutcz7m4VgmslkxT7Q/640?wx_fmt=png&from=appmsg "")  
  
  
可以看到该ReceiveMessageAttributes被设置的内容如下所示  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSJuCIOpNlH6cUZKvhndNHWWRvIk9iaZoLxD2twQn1ia0TxC8XICQVVA6A/640?wx_fmt=png&from=appmsg "")  
  
  
PdcpAlpcProcessMessages中ZwAlpcSendWaitReceivePort调用返回，此时的传入函数PdcProcessMessage的第二个参数MessageAttribute就是ReceiveMessageAttributes+8，第一个参数则是300008的消息实体，如前文分析，该消息实体+0x4位置处的6将导致进入PdcFreeClient。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSiblWFSOVQiayzQo7QJbcf4vyAfUosz4TEaKR1sdAY2ec5Y47m3PesFmw/640?wx_fmt=png&from=appmsg "")  
  
  
PdcFreeClient中将依次释放poi(poi(poi(MessageAttribute)+0x20)+0x20)及poi(poi(MessageAttribute)+0x20)。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSutIibHPJ5fBnPwk0R9icCkACh2QBcC3RtGeTZDZzDg262V1DZkLhIxdw/640?wx_fmt=png&from=appmsg "")  
  
  
如下所示poi(poi(poi(MessageAttribute)+0x20)+0x20)实际指向了poi(MessageAttribute)，因此这里两次释放的实际是poi(MessageAttribute)及poi(poi(MessageAttribute)+0x20)。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSw0Amd3C9oZ8sEt2WQh0AMUckfzqAo16ia47ohXztq5Yp35EOnYlBGiag/640?wx_fmt=png&from=appmsg "")  
  
  
首先释放的poi(poi(MessageAttribute)+0x20)，如下所示，其大小为0x50的pool。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSMEFib79QmawerCuGAmGsKv6tmAib5dT5bTBWm9W3uXgAVGpuRBTH2Ghw/640?wx_fmt=png&from=appmsg "")  
  
  
之后是poi(MessageAttribute)。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSRbRvZ7k4PK5aWp18sw6KGia91edg2iaFDbzyu4bicUYatf5gJXqQf4reg/640?wx_fmt=png&from=appmsg "")  
  
  
poi(MessageAttribute)的大小同样是0x50。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSdFEdr5z4JGEymMk77YS9ZYzSRnDTVqTMjgdzkZnSaXuictZwPBIlXGA/640?wx_fmt=png&from=appmsg "")  
  
  
PdcFreeClient返回后，这两个位置皆被释放。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSLUUUpp5dV3SkFZDavOZYTwfoLGKPHoQktkgiaZHGkqq5jiczXXTGWicibA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmS9mbPz7eU7IjFOHUYF1fgT9KxBp4JsficniaJeA5ub3GfYZz3IG3ic5n7A/640?wx_fmt=png&from=appmsg "")  
  
  
3000008消息导致释放时的调用栈。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmS0ibDTrh6al7LQhqILK8Qh69p8mFvofibKDH25BavjIicGSZbuh2P2PDnw/640?wx_fmt=png&from=appmsg "")  
  
  
因此这里我们就明白了该漏洞的核心，NtRegisterThreadTerminatePort会将当前的var_alpcConnectionHandle绑定到当前的线程CreateThread1，当CreateThread1退出时，内核中会通过该线程对象获取var_alpcConnectionHandle对应的alpc port内核对象，并向pdc alpc port发送一条LPC_TERMINATION_MESSAGE消息，PdcpAlpcProcessMessages中在处理该LPC_TERMINATION_MESSAGE消息时会调用ZwAlpcSendWaitReceivePort获取该消息，由于此时函数中传入了ReceiveMessageAttributes参数，因此，内核在路由该消息时将生成对应的ReceiveMessageAttributes，ReceiveMessageAttributes+8的位置会被设置为了该条消息的KALPC_MESSAGE->MessageAttributes->PortContext，ZwAlpcSendWaitReceivePort返回后，进入PdcProcessMessage处理LPC_TERMINATION_MESSAGE消息，并最终调用PdcFreeClient释放掉了ReceiveMessageAttributes+8指向的KALPC_MESSAGE->MessageAttributes->PortContext。那该释放的KALPC_MESSAGE->MessageAttributes->PortContext是通过什么方式被重用的了？答案是通过NtCreateEvent的spray，这里直接对释放地址下写入断点，可以看到NtCreateEvent最终调用ObpLookupObjectName，并通过ExAlloctePool完成释放pool的重用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSjsfZ2rT2I1hAibFWNaBy2DcQBSbnzAVNliaI7DrcpUIicvHV3EpX06mnw/640?wx_fmt=png&from=appmsg "")  
  
  
如下所示实际位置如下，并在之后的memove中将NtCreateEvent调用时设置的ObjectAttributes.ObjectName拷贝到该释放地址，而ObjectAttributes.ObjectName此时的内容在一开始被设置指向了恶意构造的evil message PortContext。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSyB84DDJOnyZZdicqJ9QLMFCiaMfXF4a1yJCWx7R07lDOh19LCbRp3t0A/640?wx_fmt=png&from=appmsg "")  
  
  
如下所示可以看到此时poi(MessageAttribute)+0x20写入的就是我们的evil message PortContext的地址。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSZpuNlQZFLsRIOLGWon840xUYicBBC5fQKqO1icDem9GGUWyjAUIho8GQ/640?wx_fmt=png&from=appmsg "")  
  
  
如下即为重用时的函数调用栈  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSeUoeeflbzVbfCgBkKq17zg0eQicLwbZeH8ysTLh4vhexSnLn5icibyAhw/640?wx_fmt=png&from=appmsg "")  
  
  
而这里fun_NtCreateEvent中是有两套占据重用的方案。除了NtCreateEvent外，其下还有一个NtQueryLicenseValue。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSZcquBKWyYwfqjGCJiayjkQF0GU0gs9ibF59XUp2WrKEgjaMjjkDkBickA/640?wx_fmt=png&from=appmsg "")  
  
  
NtQueryLicenseValue这里同样是通过传入的第一个参数分配一段0x40的pools，正好可以占据释放的PortContent内存，之后会将7FF72DE671B0处的内容写入这段pools，其0x20位置正好就是Evil message portcontent，但是在实际利用中，这个函数基本上不需要用到，exp代码中哪怕直接将其调用patch掉，也不会影响实际的利用效果。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSbv0BuunRCQ9fib1TJpuONzFjYC1gHkUuW3IDCpSkbwDEicA4aZ3NKS3A/640?wx_fmt=png&from=appmsg "")  
  
  
   
NtCreateEvent完成释放的PortContext重用后，exp中使用该var_alpcConnectionHandle调用NtAlpcSendWaitReceivePort，如下所示为此时PdcProcessMessage调用时接收到的由内核路由的exp发送的30002d8消息，同样该消息通过ZwAlpcSendWaitReceivePort从内核接收，因为设置了ReceiveMessageAttributes，因此这里300002d8的消息同样也会返回ReceiveMessageAttributes。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmStTH0r1htia6wAjpHYZ6MEhC6tQY5LtiaosbsjS7Ls90VoTCFAR0gNBzQ/640?wx_fmt=png&from=appmsg "")  
  
  
由于都是由内核的connection port返回，因此尽管Mainqueus中的KALPC_MESSAGE不同，但是KALPC_MESSAGE->MessageAttributes->PortContext却是一致，而PortContext在之前的300008消息的处理后已经被释放，并被NtCreateEvent重用被写入了构造evil message PortContext。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmS6jOzXmDtIjdxEMYA3Nu04FGc9KWiblTRtnjUZnHw2G5vLsDZYNW0iaog/640?wx_fmt=png&from=appmsg "")  
  
  
可以看到此时PortContext+0x20就指向了evil message PortContext，而evilmessage+0x1798的位置就保存了var_KWorkerHandleaddr + 0xD的地址  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSIoOSJ4lUIxmvDNQmkrYibJXdWicnnwnbL8w3oFsLpX7S4PoTrrM1ibOsA/640?wx_fmt=png&from=appmsg "")  
  
  
而实际的寻址则是遵循poi(poi(poi(poi(MessageAttribute)+0x20)+0x20)+0x6c8)。最终找到保存了var_KWorkerHandleaddr + 0xD的位置。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSxreCMho8fJ9Xe5z59M5ic5hickrMFMbuKlUiaWxZm4QRjfPXwvLygkeBg/640?wx_fmt=png&from=appmsg "")  
  
  
也正是我们一开始构造的evil message PortContext。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSPnsick8WMEyXrYkRn9peKHTSCDFTaPYPtqewJc3eoF6nErCRr0odZrQ/640?wx_fmt=png&from=appmsg "")  
  
  
如下可见30000008消息时对应的PortContext为0xffffe30b16a0d850。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSux2cia7wZ4f8H1YCibUeupxHgYxXpnrGyQ8reeouRv9AAFib6dicbsKKcQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSOgTYZx4a8ENHdrA61ExwAY1Ct2wLE9wmZIaer8IPHloMcmLicX7ltOw/640?wx_fmt=png&from=appmsg "")  
  
  
而同样在30000d28消息时PortContext依旧是0xffffe30b16a0d850，因此才会保证UAF的复用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSUKYuKxkiafsEicLtibg37z2rYZ4bXFpdjV3OXppQNZlAKbmaVIibicaTAdg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmScK2v2t9tRWqAOhNrUDqSffu1KX4x6RrRicEQk0NmrWia8QwYFn47RzTw/640?wx_fmt=png&from=appmsg "")  
  
  
300002d8消息的处理中，后续会通过该evil message portContext修改var_KWorkerHandleaddr+0x10处的指针，详情前面已经分析过，具体的调用栈如下，最终在KeSetEvent中完成修改。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmS0ibW3rYdMwaMon1ibqB51C1ibTnMlC3Kxm0ImFxaknWCuUBdRXnjoJJ3g/640?wx_fmt=png&from=appmsg "")  
  
  
这里每次调用只是完成四个字节的修改，因此要完成8个字节长度指针的修改需要触发两次，这也是为什么要设置var_countsForintoLoopWorkerFactory保证调用NtAlpcSendWaitReceivePort两次以上的原因。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSiaHRjY70MCL4tVSFcGSEibb9KQzSrXhaIler4hsormg1c76ibXiczsowRw/640?wx_fmt=png&from=appmsg "")  
  
  
第一次修改四字节，可以看到此时evilmessage中设置的是var_KWorkerHandleaddr+0xd开始的四字节。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSwbO7hlncOPcuobnyNxq5LE6DcibCjzrYBzZt6YWaP5FPdng0AibtDwyw/640?wx_fmt=png&from=appmsg "")  
  
  
第二次发送3000002d8消息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSUP1mwzfROssd3dicCF9uM9Pj2m6E9RI02fe8aFiakxxAVvZeuL7zFgnQ/640?wx_fmt=png&from=appmsg "")  
  
  
可以看到第二次则修改var_KWorkerHandleaddr+0x11开始的四字节，通过KeSetEvent最终将该指针控制在0x100000000-0x1000002000的范围。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSib2IZdZWM716IUAoNGLteDxibYxq84IgZg2vFgVaSQUfht2DD4jKA2Lw/640?wx_fmt=png&from=appmsg "")  
  
  
最终在将目标写入地址spray在0x100000000-0x1000002000范围，通过调用实现对i/o ring的修改，从而获取任意地址读写原子。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmSUje2LLEqB38GicxyY9FOWOJYdtCErgUFVGEFX2QicHOEW5lcmOe3CWAA/640?wx_fmt=png&from=appmsg "")  
  
  
总结  
  
整个利用的流程如下所示：  
  
 **1** 调用NtAlpcConnectPort连接pdc alpc port服务，获取一个var_alpcConnectionHandle。  
  
 **2**  
  在线程1中调用NtRegisterThreadTerminatePort，将var_alpcConnectionHandle绑定在线程1的_ETHREAD 内核对象上。  
  
 **3.1**  
 监控线程1的情况，当线程1退出时，内核中PspExitThread调用，_ETHREAD内核对象上绑定var_alpcConnectionHandle内核对象会调用LpcRequestPort向pdc port服务端发送一条LPC_TERMINATION_MESSAGE消息。  
  
**3.2** pdc服务端通过PdcpAlpcProcessMessages函数处理相关的消息，该函数中接收内核路由的alpc消息是通过ZwAlpcSendWaitReceivePort实现，该函数的调用中设置了参数ReceiveMessageAttributes，这将导致ZwAlpcSendWaitReceivePort->NtAlpcSendWaitReceivePort->AlpcpReceiveMessage->AlpcpExposeAttributes调用，通过AlpcpReceiveMessagePort获取该消息的_KALPC_MESSAGE，并设置对应的ReceiveMessageAttributes，这里ReceiveMessageAttributes+8的位置会被设置为_KALPC_MESSAGE.MessageAttributes.PortContext，该值和connection port绑定，即此时所有的接收到的消息中的_KALPC_MESSAGE.MessageAttributes.PortContext都是固定的指针。  
  
**3.3** 调用PdcProcessMessage处理该消息，并最终在PdcFreeClient中释放掉ReceiveMessageAttributes+8保存的_KALPC_MESSAGE.MessageAttributes.PortContext指针。  
  
 **4**  
 确保ReceiveMessageAttributes->_KALPC_MESSAGE.MessageAttributes.PortContext释放后，循环调用NtCreateEvent，这里将其参数ObjectAttributes.ObjectName设置为7FF72DE671B0，而在7FF72DE671B0+0x20的位置则保存了evil message PortContext 7FF72DE66130，最终NtCreateEvent调用，并在ObpLookupObjectName中通过ExAllocatePool2占据了释放的ReceiveMessageAttributes->_KALPC_MESSAGE.MessageAttributes.PortContext内存，并随后通过memory将ObjectAttributes.ObjectName中设置的7FF72DE66130写入到ReceiveMessageAttributes->_KALPC_MESSAGE.MessageAttributes.PortContext这段内存+0x20的位置，实现重用及修改。  
  
**5.1** 线程2中，当确保了NtCreateEvent占据完毕，ReceiveMessageAttributes->_KALPC_MESSAGE.MessageAttributes.PortContext+0x20指向了evil message PortContext 7FF72DE66130后，通过var_alpcConnectionHandle调用NtAlpcSendWaitReceivePort，向pdcport服务端发送一条30002d8的消息  
  
**5.2** 类似于前面3000008 LPC_TERMINATION_MESSAGE消息的处理，此时通过ZwAlpcSendWaitReceivePort从内核获取ReceiveMessageAttributes，ReceiveMessageAttributes+8的位置指向了_KALPC_MESSAGE.MessageAttributes.PortContext，由于该指针在同一个connection port下的所有_KALPC_MESSAGE一致，因此这里返回的_KALPC_MESSAGE.MessageAttributes.PortContext，其中的0x20偏移处已经在第四部分被修改evil message PortContext 7FF72DE66130。  
  
**5.3** PdcProcessMessage处理30002d8消息，最终会导致poi(poi(poi(poi(poi(ReceiveMessageAttributes+8))+0x20)+0x20)+0x6c8)处的var_KWorkerHandleaddr + 0xd/0x11在KeSetEvent被设置，两次NtAlpcSendWaitReceivePort调用后(每次修改4个字节)var_KWorkerHandleaddr+0x10处的指针将被修改为一个 0x100000000-0x1000002000范围的值，这里我们抢占的是poi(poi(poi(poi(  
poi(ReceiveMessageAttributes+8))+0x20)+0x20)+0x6c8)红色指针释放的内存，poi(poi(poi(poi(  
poi(ReceiveMessageAttributes+8))+0x20)+0x20)+0x6c8)，替换的则是蓝色部分的指针，将其设置为evil message PortContext。  
  
 **6**  
 var_KWorkerHandleaddr+0x10处的指针被修改为0x100000000-0x1000002000范围的值，通过在该范围的地址上spray目标写入地址，使用var_KWorkerHandleaddr调用NtSetInformationWorkerFactory，将可以获取一次任意地址写入的能力，通过该能力最终提供了修改i/o ring/PreviousMode 的两种提权方式。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmS3mHzy8ju6n9p3U4TEXlSgVwx8aChs49DaZiasLCO02zIcSg1kmnbX8Q/640?wx_fmt=png&from=appmsg "")  
  
  
参考链接  
  
[1].https://github.com/avalon1610/ALPC/blob/master/ALPC/ntlpcapi.h  
  
[2].https://whereisk0shl.top/post/break-me-out-of-sandbox-in-old-pipe-cve-2022-22715-windows-dirty-pipe  
  
[3].https://recon.cx/2008/a/thomas_garnier/LPC-ALPC-slides.pdf  
  
[4].https://csandker.io/2022/05/24/Offensive-Windows-IPC-3-ALPC.html  
  
[5].https://i.blackhat.com/Asia-22/Friday-Materials/AS-22-Xu-The-Next-Generation-of-Windows-Exploitation-Attacking-the-Common-Log-File-System.pdf  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/2AqAgxkehic8w8noVE4qD1UXoq9ciaaWmS61pwGia33jFh1XGEGOepx6P1X2ggKwYOaKF645SGYwCeWL8Atibl3bOQ/640?wx_fmt=gif&from=appmsg "")  
  
点击  
阅读原文至**ALPHA 7.0**  
  
即刻助力威胁研判  
  
