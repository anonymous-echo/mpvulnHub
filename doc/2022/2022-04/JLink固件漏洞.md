#  JLink固件漏洞   
曾半仙  看雪学苑   2022-04-21 17:59  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8GF1nTWVDhXRmGjhhpZcXicictJ0sM8qSoJKfKSPPkEnZIThbyEbBsjaW72KlzR0hE4u02X8gwXgLzw/640?wx_fmt=jpeg "")  
  
本文为看雪论坛精华  
‍‍‍文章看雪论坛作者ID：曾半仙  
  
  
JlinkV10的固件验证缺陷我年前已发布刷机工具，但缺陷是利用就得刷机一次再刷回。  
  
  
发布前在某移动设备开发群谈论时候，群友说v10会检查固件签名，你怎么搞。我就说签名区外面的空间我可以放代码，能放五百字节完全塞得下。  
  
他表示以前的很老版本固件倒是有过任意写bug，可惜修复了，虽然没有透露细节，但我想群友能找到我也来找个。  
  
  
然后我挨个看命令处理，还真看到个栈覆盖bug。这个bug并不是他说的那个，而且栈太小了不大好利用。  
  
  
这我可就不同意了，数着字节写代码是我们中年程序员的基础技能啊!  
  
  
先看看出问题的函数fine_write_read反编译代码：  
```
    usbrxbuf(arg, 12); // 接收三个len
    usbrxbuf(writebuf, arg[0]); // 可覆盖LR
    readed = syncM0FINEGPIO(writebuf, arg[0], replybuf, arg[1]);
    memcpy((char *)&arg[7] + arg[1], &readed, sizeof(int)); //任意地址清4字节
    usbtxbuf(replybuf, arg[1] + 4);
```  
  
  
此代码有用户控制缓冲区长度问题。首先会接收三个长度变量，我把它们取名为writelen, readlen, somelen。第一个writelen控制接下来的缓冲区接收尺寸，然后usbrxbuf函数接收对应长度的字节放入writebuf，此数组分配在栈上。这里可以超写，覆盖LR。  
  
  
然后再看memcpy的目标，以writebuf地址+第二个长度偏移=最终地址，复制4字节readed值到此地址。构成了一个任意写，正常情况下readed值等于readlen，但可以不正常。  
  
  
这个writebuf是栈上的数组，打开栈结构窗口看看：  
```
-0000003C readed          DCD ?
-00000038 arg             DCD 3 dup(?)
-0000002C writebuf        DCB 16 dup(?)
-0000001C replybuf        DCB 24 dup(?)
-00000004 LR              DCD ?
+00000000 ; end of stack variables
```  
  
  
只要从writebuf地方写0x2C个字节，就覆盖到了保存的LR了。因为程序序言是一个单纯的PUSH {LR}，所以也没有其他寄存器的值需要恢复。  
  
  
最简单的利用方法就是让usbrxbuf函数对writebuf写入0x2C字节，覆盖保存的LR到我们写入的缓冲区地址。首先我们需要知道执行到此处时，sp具体的值，好跳转到我们写入的代码中。  
  
  
我写了一个小工具，通过usb命令触发fine_write_read这个处理函数，接收长度writelen给了2C，这2C的内容都是AA，然后使用SWD连接jlink的芯片， 在BL usbrxbuf处下断，然后执行命令断下，查看此时的sp值， 100840A0。执行usbrxbuf后writebuf, replybuf, 返回地址(LR)都被填充成了AA。  
  
  
因为从BL usbrxbuf直到函数返回还有三个BL, 要让栈里LR生效, 必须执行到POP PC。我们依次执行这三个BL, 在执行第一个BL syncM0FINEGPIO后就出了问题, 我们送进来的AA被这个函数给清零了! 从replybuf开始的0x2C字节都被清了, 都超过了栈上的LR清到了父函数的栈里面。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HC9vEuQ32cnTSs4Uk6HxnRVOdbYgH1K91AvqPPHGHuy9rCYjRZ3qePd5F2yRolm0aUCE2duptQZQ/640?wx_fmt=png "")  
  
为了直观一些, 我画了fine_write_read函数的栈。这个函数顾名思义, 是上位机和使用FINE接口(瑞萨的协议)的开发板通讯用的, 上位机送出writelen长度的数据, 调试探头通过操作GPIO引脚送给开发板, 然后由引脚读回readlen长度的数据放到replybuf, 并连同读取长度一起发给上位机。  
  
  
我们当然不想让replybuf被覆盖, 所以readlen写的0, 按理说syncM0FINEGPIO也会返回0, 也不会往replybuf写值, 只有memcpy会将replybuf开始4字节覆盖为0(readed)啊。  
  
  
跟进去syncM0FINEGPIO调了一下, 发现执行了某条写入内存指令后, 栈里的replybuf连同后面的LR等瞬间清零了。  
  
  
这指令操作就是[20000008]=1, 这个地址在数据手册里描述为M4/M0共享内存, 经过分析这个syncM0FINEGPIO函数是给M0配参数和等待它完成的协作函数。  
```
APP:1A016864 008 20 60                       STR     R0, [R4]        ; 执行到这里会破坏LR
APP:1A016866 008 BF F3 4F 8F                 DSB.W   SY
```  
  
  
此时就要讲一下这个J-Link V10的硬件特征了, 他的cpu有M4/M0两个核心, 看来为了让GPIO模拟协议保持时序稳定不受RTOS影响, J-Link程序员单独用M0来完成协议模拟。20000008是M4/M0之间的状态量, M4切换状态到1等待0, M0等待1完成后切换为0并继续等待1。  
  
  
那为什么本应该按照readlen来跳过读取的M0会按照writelen来覆盖我们的replybuf呢? 为了覆盖到位, writelen是不可以设置成0的。  
  
  
我估计应该是因为我们没有经过前置的操作, 直接发送FINE请求, M0里运行的程序并不是为了FINE协议准备的。我没有瑞萨的开发板, 没法实际接上FINE接口看看固件命令执行流程。  
  
  
不过连翻带猜发现了一个select_if命令, 当选择3号interface时候, M0的app(Reset Vector地址的函数)就是匹配FINE读写的。  
  
  
在我们工具加入select_if命令后, 经过调试, 成功走到了POP {PC}。  
  
接下来我们就要考虑下塞下更多代码的办法了。目前我们能利用的空间是分开的两段, somelen应该是fine_write_read命令中一个保留的字段, 因此函数中没有用到他, 内容会保留。从他开始0x14字节的绿色区域可以放代码, 然后replybuf的内容前面4字节会被memcpy覆盖为m0程序返回的readed, 所以需要避让开4字节。后面到LR也有0x14字节的蓝色区域, 也是可以放代码的。  
  
  
那么最后的父函数栈是不是可以继续覆盖作为代码呢? 实际是不行的。走完uxbrxbuf函数, 可以观察到父函数栈确实可以被覆盖, 但是走usbtxbuf函数发送回应时候, 设备就会崩溃重启, 回不到POP {PC}了。  
  
  
usbtxbuf函数会发送replybuf, 长度为readlen+4, 查看usbtxbuf函数, 我们会看到如果buf或者len任一项为0, 该函数就会直接返回, 不会调用其他子函数。那么如果我们把readlen设置为-4, 这个发送函数不就直接返回了吗?  
  
  
话虽如此, 但readlen同时还传给M0作为从GPIO引脚读取到replybuf的长度, 如果传个负值会不会M0又开始狂写replybuf呢?  
  
  
查看M0的app后发现, 读取部分是判断readlen非0后至少读一个字节再判断已读字节数是否小于writelen的。这里的判断是BLT, 有符号。因此读了1字节后循环条件1小于-4不成立不再循环。  
  
  
但…节外生枝的是M4往M0传readlen参数时候会左移3位将readlen字节数转换为bit数, 然后在M0中右移3位转换回byte, 因此readlen传FFFFFFFC(-4)会丢掉高3位变1FFFFFFC(536870908)。程序员看似为了设计做的无意义转换恰好封堵了这种绕过发送函数的办法。  
  
  
不过还不能绝望, 因为J-Link没有让M0从flashA执行(估计是因为放在sram中是零等待周期, 模拟出来的时序更准), 而是放在sram0中。所以我们可以实时补掉M0的app。  
  
  
我们可以分两步, 第一步不超收, 补掉M0的app后就返回, 因为我们payload执行时候, M0是位于循环等待20000008的状态, 而M0也没有icache, 所以补了别的地方下一轮gpio操作执行就是补丁后的代码。我们补的就是这个右移3位的代码LSRS    R5, R5, #3, 直接补为EORS R5, R5, 这样下一次协作函数发什么M0都以为readlen是0, 从而不会动replybuf。外面的M4看来readlen还是-4, 还能用来绕过uxbtxbuf发送函数。  
  
  
测试果然可行, 收个12c大小, 已经破坏了父函数栈, 甚至穿了task的栈空间, 但usbtxbuf没有用到栈直接返回了, 最后POP {PC}流程到我们代码。测试中12C实际写穿到IP栈的栈了, 但只要我payload里禁用中断, RTOS也不会切换到IP栈线程。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FU1VewsrAqFyYf4ibXXx7nKj0noibN8GibJfdzsUhuX39b9bsjKfBdf15O5qyVvMxjyaFoZ15U2Kjzw/640?wx_fmt=png "")  
  
  
这是出厂版固件的embOS的各线程的栈分配表。  
  
  
这样我们能够放代码的空间就增大了很多, 因为改了readlen等于调节了随意写bug, readed的值相应的会复制到replybuf-4的地方, 我们可用的是0x10+0x18+超写部分长度。最大写多少我没试, 应该只要能成功接收不崩溃, 就不会异常。  
  
  
现在是不是可以告一段落了呢? 显然不完美啊。这样破坏的话我们执行完自己的payload后只能通过重启的方式恢复环境了, 有没有什么办法还能继续返回执行呢? 比如写入其他空闲地方?  
  
  
当然有, 还恰好能塞在0x28的大小里。目标地址选择了20000048这是IP Stack才会访问的地方, 估计是联网功能预留的代码。也可以选择sram0的10000160处, 推测segger程序员将整个sram0预留给M0独占使用, FINE的M0 APP就只用了前面0x160。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HC9vEuQ32cnTSs4Uk6HxnRva0YskmPMicFdGHRgnO16oZFCRpWdibARtJRxIeBe9NeBhhTPDhxmKZQ/640?wx_fmt=png "")  
  
此处第一个留空的readed是memcpy的目标, 第二个留空LR是栈上返回地址。  
  
  
注意这里的sub sp, #0x30是因为我们要在payload里调用usbrxbuf, 而执行到我们的payload时候, sp刚好指向的是payload结束后的地址, 第一次调用BLX R2就是usbrxbuf, 它和它调用的子函数写入栈会往前破坏我们的payload末尾。  
  
  
当然减掉28也是可以的, 因为执行了blx r2指令后才进入子函数, 此时前面几条指令空间用不到了。  
  
  
然而这并不能让我满足, 我又思考了, 能不能我们激活并保持住M0的重启信号, 并把我们自制的M0 App给覆盖到sram0, 然后App保持”后台”执行呢?  
  
  
经过精简, 载入代码要0x2C连续空间, 因为我们M0卡重启会导致下次fine_write_read命令时候双核协作函数syncM0FINEGPIO无法返回, 无法拆分为2次执行。那我们能不能把中间存readed的位置继续往前挪呢? 答案当然是可以的!  
  
  
实际上这个readed刚才已经因为我们的readlen往前挪了4字节, 如果继续往前不就挪到当前函数栈空间外了吗? 可是减少readlen又会造成最后usbtxbuf时候长度为负, 无限发送。因为是先memcpy再usbtxbuf, 能不能让readlen在memcpy取参数时候是-0x18, 但执行后把-4回写到readlen位置, 供最后usbtxbuf凑成0呢? 只要让M0固定返回-4即可。  
  
  
我改进了补M0的代码, 多补了一个地方, 让返回变为-4。  
```
sram0:10000150                 loc_10000150                            ; CODE XREF: FINE_Reset_Handler+10A↓j
sram0:10000150 000 40 1E                       SUBS    R0, R0, #1
sram0:10000152 000 FD D5                       BPL     loc_10000150
sram0:10000154 000 20 46                       MOV     R0, R4
```  
  
  
最后一句R0的值会在后面写入20000024, 给M4同步函数读取为返回值, 本来是从前面R4(readed)的值传给R0, 我改为了subs R0, #4, 因为循环到这里时候R0是0。这样等下M4取回来的就是-4了。  
  
  
总结一下第一次打完补丁返回后, 第二次溢出, 上位机传过来readlen为-0x18, 导致memcpy的目标指向readlen自身, 执行完mempy以后readlen变为了M0给的-4,调用usbtx时候这个readlen+4=0不会调用usb函数直接返回了。这样就避开了payload破坏函数执行问题。  
  
  
这样我们的工具就有了三种方案:  
  
（1）经典原地超收 需要补丁M0外加负偏移跳发送。完整payload从当前函数栈往后覆盖。缺点是执行后必须重启, 而且payload代码里不能做usb发送。  
  
（2）空闲内存M4执行 第一次溢出时候额外调用usbrxbuf接收完整payload到空闲内存位置, 然后跳转执行并返回。因为没有破坏栈, payload中可以继续usb收发。  
  
（3）M0专属app后台执行 在M4的准备阶段将M0App整个替换, 我们此后再发fine_write_read指令就可以通过原本的协作函数让M0App响应处理。  
  
不过经过测试, 方案3用简易刷新法(卡着M0复位并覆盖它程序代码的操作过后放开复位控制位), 系统会在500ms后重启。使用固件里的完整刷新函数bootm0app不会重启, 但我们要额外解析该函数地址。  
  
  
这就结束了吗, 还没有, 还有最重要的一步: 兼容性。  
  
  
为了发布一个成熟的利用, 我们还要兼容更可能多的版本固件。我们需要知道sp的值, usbrxbuf的值, 用来填充不同版本的固件下payload末尾的指针。一种办法是收集所有驱动, 逐个解压固件然后人工分析。  
  
  
还有一个办法是用程序自动寻找。虽然最早我们得到SP是通过真机调试, 但我此刻意识到SP的值可以通过主线程执行时候的初始值减去每层调用时候的SP差值得到。初始值应该就是RTOS创建时候传入的栈空间的底部值, 因为ARM传统的required 8兼容, 初始值还需要按8对齐一次。  
  
  
IDA脚本功能是, 针对IAR特征找到main, 然后提取出栈初值, 在主线程函数中, 定位usb分发函数, 寻找usb命令处理程序数组, 定位fine_write_read函数, 将这三层跳转处的sp偏移减去。  
  
  
然后考虑到在用户机器没有ida还得架个服务器跑idapython, 那能不能用普通的反编译库来本地找呢? 以前写insanelinker时候也写过一些解析, 但只是个别指令。懒得完善了不如看看开源的吧!  
  
  
capstone有点大, 但找了其他俩轻量的更坑, 最后还是从ida脚本移植了一个capstone的版本。因为不能像IDA那样确定函数结束, 也不能给出SP偏移, 通用性肯定不如ida脚本了。  
  
  
经过调整和验证, V10固件直到最新版都可以搜到所有特征, 顺便测试了下V11, 直到7.52a里面也适用, 但在7.52b第一步就定位错误, 目测从这个版本起已经不是IAR编译的了, 可能是SES(Segger Embedded Studio)编译的, LDR基本都变成了MOVW/MOVT组合, 不好搜索了, usbrxbuf全部成为了inline调用, 静态解析只能得到二级指针地址。  
  
  
导致”M4接收器”无法挤下取接收函数地址的代码, 但可以绕过, 比如多溢出几次用蚂蚁搬家的方式拼出一个接收器再执行, 又或者第一次溢出后取函数地址并发回给主机用来装配接收器。  
  
  
同时因为编译器的改变, 新款fine_write_read的栈底多了R4,R5,R6, 我们覆盖时候还要知道原来的值。比如7.60a里面R4的值在执行前是修正后的命令索引, R5和R6在主线程里面寻找MOVW/MOVT组合可以得到, 但在7.52b里面, R6才是cmd相关的。  
  
  
所以想要静态分析通用处理已经太难了(后面会说原因), 得想办法做个能模拟外设单元的模拟器, 或者干脆用实际硬件把这些版本跑一遍下断点加记录, 再提供个服务远程接收新出的测试版固件上传刷机。  
  
  
还有另一个冷门办法, 我们看一下read_emu_mem这条命令, 它比较复杂应该也保护了这些寄存器, 果然, 入口是PUSH.W  {R4-R9,LR}。那么用它来读当前的栈里面R4-R6的值, 再在fine_write_read里装配到LR前面可不可行呢, 完全可行。  
  
  
因为主线程这里就是个无限循环, 不同的命令全是走同一个BLX指令调用的, 除非这三个寄存器有一个是存了命令索引, 但这个索引在获取命令指针后就没有用到了。  
  
  
这个保留作为最终手段, 我们先来试试静态分析。我改进了搜索代码, 在遇到BLX调用usb命令前, 持续跟踪movw/movt对, 记录R4R5R6得到的最后一次组合值。  
  
  
对比输出结果, 目前来看, 汇编静态解析和动态获取的相同。我这套解析的隐患是解析代码没有处理跳转, 所以如果是后面代码初始化了R4R5R6再跳回前面代码执行cmd的固件, 那么我的记录方式就会失效。当然了目前版本没有遇到。  
  
  
接下来载入器也要适配SES编译版V11固件, 但发现SES版的临时变量readed从栈顶部跑到了尾部, 占用了replybuf结尾的4字节, 因为replybuf代码里本来是0x14大小, 只是IAR版由于8字节栈对齐原因尾部有4字节无用空间。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HC9vEuQ32cnTSs4Uk6HxnRUMicuC9rSnQQM9ic8Gck1Mq6dOGSq3ib0SY8DAuj4g4nySJicDSb3MoWiaw/640?wx_fmt=png "")  
  
当replybuf被打回原形后, 又少了4字节可用空间。不过我发现栈里r4r5r6其中总是有一个是cmd索引, 因为cmd索引的寄存器在取完命令指针后直到准备下一次接收都没有再引用, 能不能把LDR的pool末尾动态挪到它对应位置呢？  
  
  
经过调节, 加了重定位处理, 成功把M4载入器的代码塞进最新V11的栈里, 还富余俩字节。  
写了个红灯闪烁的payload执行后, 正常继续执行也没崩。  
  
  
那么如果cmd索引它不是r4r5r6咋办? 因为我们方案2里面返回的是调用cmd的函数, 所以可以在payload返回前恢复对应寄存器的值, 不过这样需要payload配合了。  
  
  
如果不想在payload里配合, 那么这个流程也必须做一次M0App的补丁, 将+14处的四字节省出来。  
  
  
我还在琢磨只给正版用户利用, 不想给做盗版的商家用, 用usb协议的验证签名命令是不靠谱的, 我怀疑盗版的不能升级的那种也改掉了签名验证。我想的是把bootloader读出来检查代码区和部分参数, 首先确保bootloader没被改, CRP调试保护也存在, 再查序号和OTS签名不为空。  
  
  
我在自己的V10上测试, 可以识别对bootloader的修改。  
  
  
因为我没有V11真机, 目前还没测试。无意间听说一位群友有正版V11, 特地向他求助, 在他帮助下, 增加了V11的正版验证。  
  
  
至此我就可以支持v10/v11所有版本了, 让我们想想能写点儿啥好玩的呢?  
  
  
（1）Blinky 最经典的闪灯  
```
    //LPC_SCU->SFSP2_4 = 0x54; // P2_4 -> Fun4, No Pullup
    //LPC_GPIO_PORT->DIR[5] |= 1 << 4; // GPIO5[4] Output
    for (int loop = 12; loop; loop--) {
        LPC_GPIO_PORT->CLR[5] = 1 << 4; // ON
        FeedWWDT();
        delay200ms();
        LPC_GPIO_PORT->SET[5] = 1 << 4; // OFF
        FeedWWDT();
        delay200ms();
    }
    return;
```  
  
  
GPIO5[4]是红灯, 主程序已经帮我们初始化好了, 头两条初始化可以不要。效果就是红灯闪烁12次后, 机器仍正常运行。因为此芯片WWDT看门狗起来就关不掉的, 时间超过了500ms就要喂狗, 所以加上了喂狗调用。  
  
  
（2）SWDUnlock 解除调试限制  
  
  
V10的电路板预留了jtag/swd调试接口, 但因为它出场时候设置了CRP代码读出保护, 导致此接口不能用来调试(当然就不能用来dump), 但我们可以代码方式改写CRP标志所在的页, 将其关闭。  
  
  
因为LPC4322自带的ROM里面有flash操作函数, 我们经过init, prepare, erase, prepare, write五步操作, 可以完成修补。因为返回时候栈在上层函数, 因此大概有Dxx大小的栈可以在payload里用。  
  
  
（3）去除bootloader固件校验, 或者刷自制bootloader  
  
  
Segger为了保证固件是官方固件, 增加了RSA签名验证. 之前的帖子虽然也讲了这个RSA检查没有覆盖整个固件, 能够让我们插入自己的代码, 但如果bootloader补掉, 我们就可以完全自制固件了。Segger的信任策略是bootloader相信自己不会被修改, 然后不信任固件去检查固件。  
  
  
（4）让JLink自动补用户开发的固件  
  
  
这个就比较特殊了, 假设知道对方是开发者, 或者偏执的断网编译固件烧写的钱包用户。可以接触到他的调试器的usb连接的话, 通过以上方式给调试器刷固件加入匹配代码, 烧写的产品固件里植入后门, 例如特定的保密设备, 只有flash代码能够访问的安全存储, 但很遗憾的是, 这个估计没法做通用, 因为无法把固件全部缓冲下来分析, 只能流式修补。  
  
  
此bug在JLinkV9, JLink Pro, JLink Wifi最新固件中都存在, 估计Segger家只要支持FINE协议的产品都有同样的漏洞。其中Wifi版可能不需要usb连接也可溢出。而Pro版没有M0协处理器, 因此不能使用负偏移技巧。  
  
  
此bug我已在1/5日报给Segger, 不过不知道由于啥原因, 厂家没有重视。后来催了下, 说我给的密码打不开压缩包。再后来又催了下, 说产品经理病了。那好吧, 那我发布时候为止, 通用JLinkV10/V11所有固件。  
  
  
最后总结一下, 嵌入式环境有其固有特点, 缺点是内存资源极其有限, VFT用的少, 一些基于函数指针的利用没法在这里用。优点呢, 就是执行的环境比较洁净, 没有其他进程/OS干扰, 只要不搞出bug, 走同样路径触发的函数, 不管是多少次, 现场都一样, 甚至可以在电脑上静态计算出来。  
  
  
特别感谢: thxlp, XX, Status:Headcrabed。  
  
  
工具已上传, 加了一些限制防止taobao. 目前具有闪灯, 去除features, V10/V11互转等功能。  
代码已发github。  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HC9vEuQ32cnTSs4Uk6HxnRpaV8KSyiaRRflW59HwDicyDVj2EtYoMmtJibmfpdoKvZsrmHqO3iax81IA/640?wx_fmt=png "")  
  
  
**看雪ID：曾半仙**  
  
https://bbs.pediy.com/user-home-670.htm  
  
*本文由看雪论坛 曾半仙 原创，转载请注明来自看雪社区  
  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458436715&idx=2&sn=8327e4309660c8b8abb65c84351bc413&chksm=b18ff4e186f87df7ce6da1090c2892546d544fb5f7cc384ea62a3d24eed4e637b2901ca5dad8&scene=21#wechat_redirect)  
  
  
**#****往期推荐**  
  
1.[CVE-2022-0995分析（内核越界 watch_queue_set_filter）](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458438427&idx=1&sn=a265492f38362801447a5423d49a51ce&chksm=b18ffb9186f87287b1fd247325b81803b4c18429d9238be1213ff186842ddfcea51fb5be09e2&scene=21#wechat_redirect)  
  
  
2.[ZJCTF2021 Reverse-Triple Language](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458438388&idx=1&sn=12782ff88bd2bde0f6981850b4b02a1c&chksm=b18ffa7e86f8736851bfeb653c55706f1fdb8d11b0b3569bde3b91464ca646064fbb54e13dc0&scene=21#wechat_redirect)  
  
  
3.[Docker-remoter-api渗透](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458438261&idx=1&sn=db108871abb61e4d88dc959d49da8b7d&chksm=b18ffaff86f873e9074ff93f3fe883920990a522e963ebea4d32bd0198997776fadafa6dbdc4&scene=21#wechat_redirect)  
  
  
4.[Writeup-ROP Emporium fluff](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458437956&idx=1&sn=271bc92240559c32ae45d030af2dd2d7&chksm=b18ff9ce86f870d81e7b7d54e94b0af8108e1dddf57190baaccecaa2ef0c98e92a7a235a017f&scene=21#wechat_redirect)  
  
  
5.[APT28样本超详细分析](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458437941&idx=1&sn=294e4e5b8c644383f89a00ac95a424ae&chksm=b18ff9bf86f870a9a94c03c1036a44b6161718391bbaf3c22d0c23c9fbdb3ef62dee4d21b1a7&scene=21#wechat_redirect)  
  
  
6.[CVE-2016-0095提权漏洞学习笔记](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458437828&idx=1&sn=757e514c0e584a83ef03cf08800abc7c&chksm=b18ff84e86f8715871d22cd9a97b87320aca67bbefd4eea77b02404e859ac9de15fce1c2efa0&scene=21#wechat_redirect)  
****  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EbEJaHl4j4oA4ejnuzPAicdP7bNEwt8Ew5l2fRJxWETW07MNo7TW5xnw60R9WSwicicxtkCEFicpAlQg/640?wx_fmt=gif "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EbEJaHl4j4oA4ejnuzPAicdP7bNEwt8Ew5l2fRJxWETW07MNo7TW5xnw60R9WSwicicxtkCEFicpAlQg/640?wx_fmt=gif "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EbEJaHl4j4oA4ejnuzPAicdP7bNEwt8Ew5l2fRJxWETW07MNo7TW5xnw60R9WSwicicxtkCEFicpAlQg/640?wx_fmt=gif "")  
  
**球在看**  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EbEJaHl4j4oA4ejnuzPAicd7icG69uHMQX9DaOnSPpTgamYf9cLw1XbJLEGr5Eic62BdV6TRKCjWVSQ/640?wx_fmt=gif "")  
  
点击“阅读原文”，获取附件！  
