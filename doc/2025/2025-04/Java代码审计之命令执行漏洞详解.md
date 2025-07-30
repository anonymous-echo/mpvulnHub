#  Java代码审计之命令执行漏洞详解   
 船山信安   2025-04-21 16:00  
  
## 0x01 漏洞简介  
  
在Java代码审计中，命令执行漏洞指应用程序未对用户输入进行严格过滤，直接将外部可控参数拼接到系统命令中执行，导致攻击者可注入恶意命令并获取服务器控制权。其核心原理是开发者误用危险函数执行系统命令时，未对用户输入的参数进行安全校验或转义，导致用户可通过构造特殊字符（如管道符|  
、命令分隔符;  
）或参数注入（如${}  
表达式）将恶意指令与原始命令拼接。该漏洞常出现在参数动态拼接的场景，且受操作系统特性影响。  
  
**Windows系统命令注入表**  
  
![1744878211_6800ba8358af6f16b8ba0.png!small?1744878211876](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM4u30JMeUMpKoyQJyy9By5VsA4ErCtFSicM1KXsa7urw1FDHBDE91NrPibpIrv7RYnwTMZOgzJHkZg/640?wx_fmt=jpeg&from=appmsg "")  
  
**Linux系统命令注入表**  
  
![1744878219_6800ba8b6b453fd756923.png!small?1744878219992](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM4u30JMeUMpKoyQJyy9By5xpfQ4G635S7b3vnKDIFV3maD3IblUqSFyZhfqDWk81MJT35ClapFfw/640?wx_fmt=jpeg&from=appmsg "")  
## 0x02 Java命令执行方法  
### 2.1 Runtime.exec()  
  
Runtime.exec()  
是Java中执行系统命令的核心方法，提供多种重载形式，本质是启动子进程执行外部命令。直接拼接用户输入会导致命令注入漏洞，需使用参数数组形式并严格校验输入。Java中命令执行用到最多的方法就是java.lang.Runtime#exec()  
。  
```
```  
  
![1744878228_6800ba947437825745a29.png!small?1744878228893](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM4u30JMeUMpKoyQJyy9By5yPM0ibAOD3vJdm2SVHPibJTnZLsT0O4OsvINPCbTFhViadRiaiaawUaeCNA/640?wx_fmt=jpeg&from=appmsg "")  
  
从上面可知exec()方法在执行命令的时候，传入的参数有字符串和字符串数组两种形参，将这种方法封装到靶场上且限制必须包含ping来执行观察其效果，分析可利用的方式。  
  
![1744878234_6800ba9a8a52346ffb4b4.png!small?1744878235229](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM4u30JMeUMpKoyQJyy9By5ibqSL8C1M80vm9yY9YWVJUefALL5E5oMllChlFx685u5IwKbxPgut8Q/640?wx_fmt=jpeg&from=appmsg "")  
  
首先使用exec(String)执行ping命令，正常返回结果，执行其他命令则异常  
  
![1744878241_6800baa1d49b31fae1a8e.png!small?1744878242946](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM4u30JMeUMpKoyQJyy9By5NE80V77HXGo2ZTG2jmqJreZ8muGia9rKvoiaNP5K2ja7Cgw8xITt3BKg/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744878248_6800baa8df000cf87bd32.png!small?1744878249314](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM4u30JMeUMpKoyQJyy9By5UwBLZI7jgiakFPe6woClTSx1nUMw3mWnPm2704iboGD8mfDMcuojriakA/640?wx_fmt=jpeg&from=appmsg "")  
  
使用&  
进行命令拼接，但是发现也异常了  
  
![1744878255_6800baaf9502863781edc.png!small?1744878255957](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM4u30JMeUMpKoyQJyy9By5sRXGMh7zcFWkzb8CCmic9nWX2iaXfUgvuibe8ziae3J1l2lABvW9lFpvNQ/640?wx_fmt=jpeg&from=appmsg "")  
  
切换为exec(String[])  
时，直接使用&  
拼接，发现两条命令都可以被执行。  
  
![1744878261_6800bab5c79e9cd52960d.png!small?1744878262528](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM4u30JMeUMpKoyQJyy9By5Qo2WSAGVB9fLicw8801xBAfybDWeWm3no9icCnibD75t613N1JDm5KLqw/640?wx_fmt=jpeg&from=appmsg "")  
  
思考下，为什么exec(String)  
使用了&  
会异常，而exec(String[])  
不会呢？来动态调试exec(String)  
的调用链加深理解，开始断点调试，发现调用的是exec(command, null, null);  
  
![1744878268_6800babcc65fbf8fcc4fc.png!small?1744878269210](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM4u30JMeUMpKoyQJyy9By5Prof0icweMmw2lQpSRreia6yEmpfRnuLRbhCw14MmClqDmDS2IJdXOQA/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744878274_6800bac24c95d454e04c7.png!small?1744878274706](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM4u30JMeUMpKoyQJyy9By5EQsqZX3O9svMK96SIhwkBkkWiavI7gCibg1tXlMiaQrBJDiavib7iaDmxH4A/640?wx_fmt=jpeg&from=appmsg "")  
  
继续跟进，发现这里最终也去调用的是exec(cmdarray, envp, dir)  
，那为什么最终的命令执行的结果不一样呢，分析下面的代码可以发现，传入的command  
是经过了StringTokenizer  
进行处理的，那么问题的关键就是StringTokenizer  
是怎么去处理的  
  
![1744878281_6800bac9620bed6e54d9e.png!small?1744878281806](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM4u30JMeUMpKoyQJyy9By5aAHcIqewRlnBodib0cFpNbD0Mp7biaH5FF886AUer2w6g9cnkM09TqoA/640?wx_fmt=jpeg&from=appmsg "")  
  
跟进StringTokenizer  
，发现这里对传入的命令做了一个分割，将传入的字符串str  
按照默认的空白分隔符（包括空格、制表符\t  
、换行符\n  
、回车符\r  
和换页符\f  
）进行分割，将字符串拆解为一系列连续的子字符串  
  
![1744878287_6800bacf98adc66ebaeba.png!small?1744878287955](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM4u30JMeUMpKoyQJyy9By53w5EibTRJLrOiaLm6aXibfGviabKvnohL3K4pBdrOvHc8PKuzjoSELOWaQ/640?wx_fmt=jpeg&from=appmsg "")  
  
String[] cmdarray = new String[st.countTokens()];  
的作用是创建一个字符串数组cmdarray  
，其长度等于StringTokenizer  
对象st  
中分割后的子字符串数量，最终命令变成了["calc&ping","baidu.com"]  
传入了exec(cmdarray, envp, dir)  
  
![1744878293_6800bad5d337139efefaf.png!small?1744878294339](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM4u30JMeUMpKoyQJyy9By5aKst4biaaJVZYFycKj1SbEd1pZ6XMFvK2zDpXia8phKjSuBoQbbvapWw/640?wx_fmt=jpeg&from=appmsg "")  
  
最终交给ProcessBuilder  
去执行，命令被错误的分割成<font style="color:rgba(0, 0, 0, 0.88);">["calc&ping", "baidu.com"]</font>  
，Java会尝试执行第一个参数calc&ping  
，视为可执行程序名，calc&ping  
不是一个有效程序，因此抛出IOException: Cannot run program "calc&ping"  
。  
  
![1744878302_6800baded674fd60e7cfb.png!small?1744878307009](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM4u30JMeUMpKoyQJyy9By5ZbMqxL0qDQt1ELCibbDTpbQ5iawljicf7OBMVicrEyYI8qPntNgyYP93gw/640?wx_fmt=jpeg&from=appmsg "")  
  
如果是exec(String[])  
呢？最终命令是["cmd", "/c", "calc&ping", "baidu.com"]  
，Java调用cmd.exe  
，并传递参数/c  
和后续参数calc&ping baidu.com  
。cmd.exe  
会将calc&ping baidu.com  
整体视为一个字符串，并按照 Shell 规则解析其中的&  
符号，将calc&ping baidu.com  
解析为两条命令，故而执行成功。  
  
![1744878308_6800bae482a4315c88111.png!small?1744878318090](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM4u30JMeUMpKoyQJyy9By5IzZvjSAhqy6VR6JaLicuejnG5wVv86trnzyJVrgcTtPemlhED7Y3S5Q/640?wx_fmt=jpeg&from=appmsg "")  
  
那exec(String)  
怎么去进行漏洞利用呢？可以利用Shell的解析逻辑实现命令注入，直接拼接cmd /c  
即可  
  
![1744878315_6800baeb38f282c037bf9.png!small?1744878318088](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM4u30JMeUMpKoyQJyy9By5mREKxdEdfzyXD81f7fHjBxOmOD8LxaVmxmOJJgk4b8OY4KT83YbZrw/640?wx_fmt=jpeg&from=appmsg "")  
  
### 2.2 ProcessBuilder  
  
ProcessBuilder命令执行漏洞的核心在于通过ProcessBuilder  
类直接构造并执行系统命令时，若未对用户输入参数进行严格过滤或拆分，攻击者可注入恶意命令实现任意代码执行，ProcessBuilder  
不支持以字符串形式传入命令，只能拆分成List或者数组的形式传入。  
  
![1744878322_6800baf2847d5d046cadd.png!small?1744878323181](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM4u30JMeUMpKoyQJyy9By5r2gYnicdtmRQOS7ibS1RVPfP8t0FYqvMJ1jbeddNuPeO0Nyq28ZxKicnQ/640?wx_fmt=jpeg&from=appmsg "")  
  
从靶场漏洞代码中可知道，是直接将用户输入的参数传入到ProcessBuilder  
进行命令执行，从而攻击者可以拼接恶意命令造成漏洞  
  
![1744878328_6800baf8f2dfa5585a353.png!small?1744878329666](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM4u30JMeUMpKoyQJyy9By5WSib2dTGtILfKGpLjrp0bX3oERyf8hTC1T3hcxT57MfsPZoKDa2MicQg/640?wx_fmt=jpeg&from=appmsg "")  
  
跟进ProcessBuilder.start()  
方法，ProcessBuilder.start()  
是Java中启动外部进程的核心方法，其底层实现最终通过调用ProcessImpl.start()  
完成操作系统级别的进程创建。  
  
![1744878337_6800bb01b98c52ce68bbd.png!small?1744878338394](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM4u30JMeUMpKoyQJyy9By5aQoBKc0UmhQDWiacXen3H4kMouIHMylVW2TkUlsMibLxjJdnYQrrjGcA/640?wx_fmt=jpeg&from=appmsg "")  
### 2.3 ProcessImpl  
  
ProcessImpl  
是 Java 中Process  
抽象类的具体实现类 ，其设计目的是为ProcessBuilder.start()  
方法提供底层支持，用于创建和管理操作系统进程 。由于ProcessImpl  
的构造函数被声明为private  
，无法直接通过new  
实例化，开发者通常需通过ProcessBuilder  
或Runtime.exec()  
间接调用其功能 。若需直接操作ProcessImpl  
，必须通过反射技术绕过访问限制。ProcessImpl  
的start()  
方法是静态的，可通过反射获取该方法并传入参数（如命令数组、环境变量等）创建进程。  
```
```  
  
靶场效果  
  
![1744878346_6800bb0a56bea6df6daed.png!small?1744878346954](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM4u30JMeUMpKoyQJyy9By5MEeGlSHdmtzozvcPsruJp6x6GWibLYAWpQgK23sreichsUJkdP69W1icg/640?wx_fmt=jpeg&from=appmsg "")  
  
## 0x03 代码审计思路  
  
学习完Java命令执行的一些方式，就可以知道需要审计哪些危险函数了，是否手动创建了shell，然后关注参数是否可控，若不可控则无法命令注入，若参数可控注意空格等会导致分割，可编码绕过（如${IFS}  
代替空格）。核心思路是识别所有可能导致命令注入的代码路径，重点围绕“参数可控性”和“Shell调用方式”两个维度进行分析：  
  
1、定位危险入口点，识别所有可能执行系统命令的代码位置  
- Runtime.getRuntime().exec()  
  
- ProcessBuilder.start()  
  
- 反射调用ProcessImpl  
、UNIXProcess  
等底层类的方法  
  
审计技巧：  
- 使用IDE全局搜索关键词：exec(  
、ProcessBuilder  
、start(  
、getRuntime()  
。  
  
- 检查反射调用：搜索Class.forName()  
、Method.invoke()  
等代码块，确认是否操作危险类（如ProcessImpl  
）。  
  
2、分析参数来源，判断命令参数是否完全或部分可控。  
- HTTP请求参数（GET/POST）、Headers、Cookies  
  
- 文件上传内容、数据库查询结果  
  
- 配置文件（如YAML/Properties）中的动态值  
  
- 是否存在字符串拼接（如"sh -c " + userInput  
）  
  
- 是否通过String.format()  
、StringBuilder  
动态生成命令  
  
3、验证调用方式与参数解析，确认是否通过Shell环境执行命令，以及参数解析是否安全，Shell会解析命令中的特殊符号（如;  
、&&  
、$()  
），导致命令注入。  
- 检查是否显式调用Shell，如使用sh -c  
、bash -c  
、cmd.exe /c  
等Shell解释器，如new ProcessBuilder("sh", "-c", userCmd)  
  
- 检查参数分割逻辑，如使用exec(String command)  
传递单个字符串命令  
  
- 检查反射绕过，通过反射直接调用 <font style="color:rgba(0, 0, 0, 0.88);background-color:rgb(246, 246, 246);">ProcessImpl.start()</font>  
，绕过参数安全检查。  
  
## 0x04 防御与修复  
  
1、避免执行系统命令  
  
优先使用Java原生API替代直接执行系统命令。例如：删除文件使用File.delete()  
而非rm  
命令 ，网络请求使用通过HttpClient  
而非curl  
命令等等，规避命令注入风险，同时提升跨平台兼容性。  
  
2、无法避免系统命令执行时，优先使用Runtime.exec(String[] cmdarray)  
或ProcessBuilder  
的数组传参方式，避免将命令与参数拼接为字符串  
```
```  
  
3、避免shell调用，禁止通过sh -c  
、cmd.exe /c  
等方式创建Shell环境，直接调用可执行文件路径。  
```
```  
  
4、危险字符过滤，过滤|  
、&  
、;  
、$()  
等Shell元字符，以及路径遍历符号（../  
），可使用OWASP ESAPI等安全库进行编码处理  
```
```  
  
来源：  
https://www.freebuf.com/ 感谢【xmsec  
】  
  
