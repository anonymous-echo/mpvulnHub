#  DFA攻击白盒AES复现——某新能源车企   
原创 Lychow  逆向成长日记   2024-12-17 02:46  
  
原文链接 ：  
  
https://wx.zsxq.com/group/51111114544514/topic/4844528181528428  
  
样本下载链接：  
  
aHR0cHM6Ly93d3cud2FuZG91amlhLmNvbS9hcHBzLzM2NjM1NS9oaXN0b3J5X3YyMjE=  
  
  
近几个月遇到的白盒AES挺多的，再加上群里有人说这个案例没复现出来，今天终于抽出来时间来学学了  
  
（愿大家少写点业务代码【抱头痛哭】）  
  
  
原文中佬写的细得不行，每一步咋走都直接写好了，只能说，牛，就差手把手教你敲键盘了  
  
  
心里莫名有点不得劲，没了探索的成就感，于是开始参照逻辑自己探索一把，所以本文主要是对原文部分内容的补充  
  
其次是给不想依赖教程，想自己摸索的人，一个大概的逻辑自己去实现（墙裂推荐）  
# 大概思路  
  
1、java层就别浪费时间了，入口在  
com.bangcle.comapiprotect.CheckCodeUtil  的  
checkcode 方法  
  
2、方法为静态注册——Java_com_bangcle_comapiprotect_CheckCodeUtil_checkcode，方法体里很明显可以看到aes和base64  
  
3、unidbg 补环境很基础，然后直接func-trace，用base64的地址进行定位，往上的函数调用有很明显的四个方法循环调用，然后挨个看下四个方法  
  
4、四个方法依次是 明文转state、加密计算、方法调用、方法调用  
  
5、hook 查看第一个方法和第二个方法的传参，找出代表轮数的参数  
  
6、DFA攻击  
# 补充  
### 1、抓包  
  
群里有人说用佬的frida过ssl的脚本，还是抓不到包  
  
我拿来就试了一下，确实依旧抓不到包，而且控制台没有打印任何东西  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Odiav18wMFE3OP6nfdcvlibVUQHVsrxqAISQuklm9lb89Ne9Ccosb5lnK1XSthh0blSP5PV8s8sCnjaMbEzuKhXA/640?wx_fmt=png&from=appmsg "")  
  
习惯性看一眼logcat，看看有没有报错信息、或者APP自带的日志可能会打印关键信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Odiav18wMFE3OP6nfdcvlibVUQHVsrxqAIlM6s27hic0Dpibjpgf6L8bNTAKxqSiagXibONMTZEuOCg7vjjqgHLuQw3A/640?wx_fmt=png&from=appmsg "")  
  
  
SSLHandshakeException，堆栈前面是系统库，那关键部分就在okhttp3.internal.connection.RealConnection.connectTls 了  
  
直接看代码  
  
其实佬已经画出来了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Odiav18wMFE3OP6nfdcvlibVUQHVsrxqAIlWvCwYGXz3EgZsMM8JyPcKqNgEBCSrsaEsB96AFaI4cMo3BLLqiaNoA/640?wx_fmt=png&from=appmsg "")  
  
  
第二条h.a和第三个hostname校验就是佬的脚本hook的地方  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Odiav18wMFE3OP6nfdcvlibVUQHVsrxqAImU3lmzjIFgdHtFm0385NMjaicCa3a62Rr1pak6LbNiaDdhJsbgUIicxicA/640?wx_fmt=png&from=appmsg "")  
  
别想了，就这玩意儿，握手的时候证书不对，自己hook一下就完了  
  
### 2、主动调用  
  
建议在frida 中写一个循环主动调用这个加密，后面分析的时候就不用每次都手动去触发，而且主动触发日志比较多  
  
### 3、加解密分析  
  
unidbg补环境都很基础，没啥东西按照佬的走就行  
  
佬在分析的时候看了很多汇编，说实话我看不懂一点，我比较常用的是func trace，打印方法调用流程，然后挨个跟着看大概每个方法做了啥  
```
        Debugger debugger = emulator.attach();        
        debugger.traceFunctionCall(module, new FunctionCallListener() {           
         @Override            
         public void onCall(Emulator<?> emulator, long callerAddress, long functionAddress) {           
          }           
           @Override           
            public void postCall(Emulator<?> emulator, long callerAddress, long functionAddress, Number[] args) {         
                   System.out.println("onCallFinish caller=" + UnidbgPointer.pointer(emulator, callerAddress) + ", function=" + UnidbgPointer.pointer(emulator, functionAddress));
                   //                finalTraceStream.println("onCallFinish caller=" + UnidbgPointer.pointer(emulator, callerAddress) + ", function=" + UnidbgPointer.pointer(emulator, functionAddress));            
                   }        
    });
```  
  
  
这里直接拿base64方法的地址进行定位  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Odiav18wMFE3OP6nfdcvlibVUQHVsrxqAIRJGnug7icFZdy35ibO2YTVzagXFCEnbv7hpGJBUxha5v94ib7rV3UUdBg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Odiav18wMFE3OP6nfdcvlibVUQHVsrxqAIlhmI90KThnWVNh6Y9vcDzpVlXqFlrof0trY4QmuM4Lb6hAysufDwkA/640?wx_fmt=png&from=appmsg "")  
  
  
往上看方法就会发现很有规律  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Odiav18wMFE3OP6nfdcvlibVUQHVsrxqAIKtrbh5ozQamUtChItrTuDY4GhmUgWjviaZb3icdMxN0NMlfXTfusO76A/640?wx_fmt=png&from=appmsg "")  
  
  
这四个方法连着调用了28次，这下整个流程就比较清晰了  
  
把这四个方法挨个看一遍  
  
第一个方法： 0x70e4  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Odiav18wMFE3OP6nfdcvlibVUQHVsrxqAIUUVAYWB9LQIWdt8YSIWVSUBC9g4X5UYyUeV8dKnJ44qyseJKCNl5Eg/640?wx_fmt=png&from=appmsg "")  
  
  
按照佬的分析，这里是明文转state块，很明显可以看出a3就是明文  
  
第二个方法：0x7f68  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Odiav18wMFE3OP6nfdcvlibVUQHVsrxqAIFBBiaYeasGgqKPqozVnhtnKYB0Bicc3ibKibNaxGibPm2ow3OqXicyAty6VA/640?wx_fmt=png&from=appmsg "")  
  
  
  
很明显的计算过程，这里就不看他的具体计算了，  
  
第三个方法和第四个方法 就啥也没干了就方法调用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Odiav18wMFE3OP6nfdcvlibVUQHVsrxqAIFc5vo9DXLrX4zJ557mOWpq87fpjBduOW6VWwNBodonIZzXcaIyQg9Q/640?wx_fmt=png&from=appmsg "")  
  
    所以关键的就是 第一个方法 明文转state，第二个方法 加密计算  
  
第二个方法加密计算的最后一个参数a4就是调用次数，传过来就是10  
  
不会用unidbg的调试，所以我选择使用dobby hook  
```
        Dobby dobby = Dobby.getInstance(emulator);
        dobby.replace(module.base+0x7f68, new ReplaceCallback() { // 使用Dobby inline hook
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                System.out.println("WBACRAES_EncryptOneBlock.onCall a4="+context.getIntArg(3));
                return HookStatus.RET(emulator, originFunction);
            }
            @Override
            public void postCall(Emulator<?> emulator, HookContext context) {

            }
        }, true);
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Odiav18wMFE3OP6nfdcvlibVUQHVsrxqAIggocbVZgz4panw4QmLRyxeHfqhQKJmSPgTJibScYxA8lWPG1mHQ4UIA/640?wx_fmt=png&from=appmsg "")  
  
    所以就直接 DFA在第二个方法里，按照佬写的进行DFA攻击就行  
  
    but  我在复制粘贴运行后，发现 DFA一注入，程序就会闪退  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Odiav18wMFE3OP6nfdcvlibVUQHVsrxqAILDEC7cvRHG32Bybic3F0c3cc7beLAYz6avVoQ8BUzzKszI7lVyjsT4g/640?wx_fmt=png&from=appmsg "")  
  
  
复制粘贴多了，动不了一点脑子，现在让看一下报错，突然有点不适应 全文唯一有点问题的，估计就  
  
UnidbgPointer.pointer(emulator, 0xe4ffeb10L);  
  
这一行代码了，问一下佬，这个方法是数字转指针，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Odiav18wMFE3OP6nfdcvlibVUQHVsrxqAID8SStGvicbhaY949ny16lmJMyJ9hfibAeBVV9FFWlYfcTZBTNfibpVUcw/640?wx_fmt=png&from=appmsg "")  
  
那就好办了，总共就俩方法，要么选择加密方法那里，要么选择明文转sate的地方  
  
  
之前写了第一个方法（明文转sate方法）的第三个参数是结果，查看一下第二个方法中调用第一个方法的代码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Odiav18wMFE3OP6nfdcvlibVUQHVsrxqAIHdBqFuwcZyJib5PbN95zahqHLu41VHNLnP9sbHniazj8aoic8ia7yxMJUA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Odiav18wMFE3OP6nfdcvlibVUQHVsrxqAIZ5PmcJ3R79vp0KzqPneUqgVTJ1esHNLzztJhyppIEvcEVbUIagAnEQ/640?wx_fmt=png&from=appmsg "")  
  
  
可以看到v52=0LL，然后取地址 传进了第一个方法  
  
**又因为第二个方法传进来就已经是最后一轮了，那我们DFA攻击选择的肯定就是这个地址**  
  
****  
这个地址就是最后一轮加密之前的 state块，那我们修改这个块的内容就可以达到DFA攻击的目的了  
  
所以所以，上面的运行后直接报错闪退，是因为他的地址跟你的可能不一样，hook一下看传入的哪个地址，然后把这个地址改成你的再进行DFA攻击即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Odiav18wMFE3OP6nfdcvlibVUQHVsrxqAIbPBGR6iazPvaAPmXFxHA70Wf1iaoME3QdQgLwib52Jp9miaKMwfVJ3WwxQ/640?wx_fmt=png&from=appmsg "")  
  
写个循环一百次调用，一直产生故障文  
```
for (int i = 0; i < 100; i++) {    
  BYD demo = new BYD();    
  String encryptdata = demo.checkcode();    
  System.out.println("encryptdata:" + encryptdata);
}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Odiav18wMFE3OP6nfdcvlibVUQHVsrxqAI6waOl8P0byhGPLNJhUypDU68QqkMV3bjos9cdYzUTaRJiadNaVmibMiaw/640?wx_fmt=png&from=appmsg "")  
  
  
使用  
phoenixAES 跑一下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Odiav18wMFE3OP6nfdcvlibVUQHVsrxqAIcCxKicXzLYz7OWQ9xUYAdPkWyUXvFvghEo14L5DdZLPWl68U0qH7IIg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Odiav18wMFE3OP6nfdcvlibVUQHVsrxqAICsYibwric9SbMKVUDSm4iant0HF6lskuZrCbCibnMNeZSpyK1GnDJJQaZA/640?wx_fmt=png&from=appmsg "")  
  
最后结果都能对上，欧克结束  
  
  
