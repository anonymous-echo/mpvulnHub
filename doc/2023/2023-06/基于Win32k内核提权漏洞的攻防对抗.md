#  基于Win32k内核提权漏洞的攻防对抗   
原创 正在写  SecIN技术平台   2023-06-21 18:00  
  
**点击蓝字**  
  
  
  
  
**关注我们**  
  
  
  
****##   
##   
###   
###   
##   
# 产生原因  
  
  
1.1Callback机制  
  
Win32k组件最初的设计和  
编写是完全建立的用户层上的，但是微软在 Windows NT 4.0 的改变中将 Win32k.sys 作为改变的一部分而引入，用以提升图形绘制性能并减少 Windows 应用程序的内存需求。窗口管理器（User）和图形设备接口（GDI）在极大程度上被移出客户端/服务端运行时子系统（CSRSS）并被落实在它自身的一个内核模块中。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYicZVBuLukYcvvVkhRuUAn1IOvZqOn5IntiaMZCibIRrlacyvb8kWjMSeQ/640?wx_fmt=jpeg "")  
  
这样的设计无疑是为内核增添了一部分压力，win32k.sys需要处理大量的用户层回调，在这之后国外安全研究人员Tarjei Mandt公开了他对Win32k User-Mode Callback机制的研究成果，从此User-Mode Callback的攻击面得到广泛关注，UAF的漏洞也不断的涌现。  
  
下图代码为一个经典UAF漏洞，用户层执行的某个函数通过syscall传入到内核层，当内核代码执行到xxxSomeCallback这一句时，用户层可以在用户定义的callback函数中获得代码执行的机会，如果用户在callback函数调用了DestroyWindow函数销毁窗口p，内核层的相应销毁代码将会被执行，p的相应内存被释放，回调执行完毕，NtUserSysCall函数继续执行，当执行到xxxSetWindowStyle(p)一句时，由于p的内存已经被释放从而导致UAF漏洞的产生。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYVZwNzibC4a7rNlzYvwO4kKLgFeWiaofticzyhDIuh3Npk33S0uWJmNzwQ/640?wx_fmt=jpeg "")  
## 1.2 GDI对象  
  
在TypeIsolation机制的引入之前，windows内核中以bitmap为代表的GDI对象成为内核漏洞利用时的首选，对于WWW漏洞来说，GDI对象就是它的“左膀右臂”，借助GDI对象可以很容易构造出稳定内核内存的任意地址读写原语，以此来绕过Windows的安全机制（KALSR、SMEP等）。  
  
****##   
##   
###   
###   
##   
# 利用框架  
  
  
漏洞成功利用漏洞触发、漏洞利用这两大环节，而漏洞利用又有以下三个阶段，分别是堆喷射阶段、信息泄露阶段、代码执行阶段。下面将结合CVE-2019-0808、CVE-2021-1732进行详细阐述。  
  
  
2.1漏洞触发  
  
漏洞的类型虽然五花八门，但基于win32k的内核漏洞是存在者一些共性的，也就是它的用户层回调，近年来所爆出的win32k的漏洞，其触发点大多都在用户层回调被hook。下面将通过两个案例来进行介绍。  
  
案例1：  
  
在CVE-2021-1732中，攻击者正是hook xxxClientAllocWindowClassExtraBytes的用户层回调函数，强行改变窗口对象tagWND的扩展数据的保存位置以及寻址方式，从而触发一个任意地址覆盖写漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYS312icLYSo7BpnE1nx4BqLe3xymXpDqRcMW6DLCzFNlRMhiaSZ0Sia0fQ/640?wx_fmt=jpeg "")  
  
针对这种触发方式，我们可以直接对用户层的usertable进行检测，usertable存在于PEB+0x58偏移处:  
  
案例2：  
  
CVE-2021-40449 是Win32k 的 NtGdiResetDC 函数中的一个释放后使用漏洞，在执行其自己的回调期间针对同一句柄第二次执行函数 ResetDC 时触发UAF漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYLI0n4W3zbcDhc2OlibsvyntPknx89yJeJB1AGRggK9u7YRhShMuPA2g/640?wx_fmt=jpeg "")  
  
针对这种触发方式，可以通过开启Driver Virifier进行检测，UAF的漏洞再此环境下会触发蓝屏。  
## 2.2漏洞利用  
  
漏洞成功被触发仅仅是一个好的开端，更重要的是漏洞利用点的寻找过程。笔者将此过程大致划分为信息泄露、堆喷射、原语构造、代码执行这四个阶段。  
1. 信息泄露阶段  
  
在win32k漏洞利用过程中，内核对象的泄漏是至关重要的。可以说成功利用一个漏洞的大前提就是获取win32k内核对象的地址。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYibGDia9MicjMMphXcuniceRib9DaKU8S7HRmiatXzqI8oLmicUIPKl7jxJLYw/640?wx_fmt=jpeg "")  
  
上图是对Windows内核地址泄漏的总结（来自GitHub），表格中包含截止目前泄漏内核对象的各种技巧。下面也是拿两个demo来阐述内核对象泄露的细节：  
- Demo1，通过GdiSharedHandleTable去泄露bitmap对象：  
  
在R3通过CreateBitmap创建位图成功后会得到一个hBitmap,如果要在R3去泄露该对象在内核中的地址可以通过GdiSharedHandleTable获取。GdiSharedHandleTable位于PEB+0x94的位置。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYTnwJIAiaS4FibWXryvZKxVM2gI9exv2ZWbb7mEf22xChJDhZQgJ698jg/640?wx_fmt=jpeg "")  
  
GdiSharedHandleTable的本质是一个指向GDICELL结构体数组的指针。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYKfPnnRib0P5ZlVjz9gM8georibHVh4pHoL9AicxeibBQ2LoJJgkuiadoSag/640?wx_fmt=jpeg "")  
  
同 CreateFile 类似，其实Windows 都用句柄（Handle）来标识用户态对内核对象的引用。这个句柄低 16 位其实是数组索引。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYP5k8ckans1wCTFWjlV58I4TQ2gicEXc6dxZqzdiahA6oTYsK4lsNj8gQ/640?wx_fmt=jpeg "")  
  
通过上文，就可以计算出bitmap在内核中的地址。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZY69nJkmqxQyg4oUv5IhRLTxSgSD68zI4ynVP50ASHSFKeNndI1Uoe3A/640?wx_fmt=jpeg "")  
- Demo2，通过HMValidateHandle函数泄漏内核对象：  
  
HMValidateHandle是微软未公开的一个函数，凭借此函数可以通过传入句柄获取对于内核对象的地址（win32k对象）。HMAllocObject创建了桌面堆类型句柄后，会把tagWND对象放入到内核模式到用户模式内存映射地址里。为了验证句柄的有效性，窗口管理器会调用User32!HMValidateHandle函数读取这个表。函数将句柄和句柄类型作为参数，并在句柄表中查找对应的项。如果查找到对象, 会返回tagWND只读映射的对象指针，通过tagWND这个对象我们可以获取到句柄等一系列窗口信息。  
  
该函数地址是通过R3的user32.dll!IsMenu函数获取到的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYlzyGg0Am0JngEMfiaNojoyicD0d42GbIuNBqQWP3DgS9icFVKhCFeW0dQ/640?wx_fmt=jpeg "")  
  
具体获取方式如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYIfCjibq86lCebmhJr6ASEgw6rD78sy7qJGlK7WtHtaicVjDYcRIQibLtA/640?wx_fmt=jpeg "")  
  
2.堆(池)喷射阶段  
  
堆（池）喷射是进行内存布局的常用手段, 通过在分配关键的内核对象之前，首先分配和释放特定长度和数量的其他对象，使内核内存首先处于一个确定的状态，来确保在分配关键的内核对象时，能够被系统内存管模块分配到我们所希望其分配到的某些位置，例如接近某些可控对象的位置。攻击者可利用此种方法构造完美的内存布局从而达到自己的目的。此技术没有固定的方法（“因地制宜”），但是所要达成的目的比较一致--执行shellcode以及信息泄露。  
  
案例1：  
  
Bitmap对象的地址在RS1中是通过AcceleratorTable获取到的。先申请大量的AcceleratorTable对象然后释放其中一个，接着申请大小相等的bitmap对象。通过泄漏AcceleratorTable对象的地址，即可等到bitmap的内核地址。（内存大小计算方式将在下一章节进行详细阐述）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZY5N0lJlf3KF3jSO8ia3ABn69Afg0ke92Kves86Tb6gJh83iaVOGcyOFQw/640?wx_fmt=jpeg "")  
  
代码框架如下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYxkPFA0TfiaD9heibgdyaicGib10u395BicIMsOfTVE61EcZDhP3hTRYVFaA/640?wx_fmt=jpeg "")  
  
3.RW原语构造阶段  
  
在win32k内核漏洞利用中，RW原语同样扮演着重要角色。它可以对所分配的关键内核对象后面的内存区域进行操作，以控制原本不能控制的相邻对象的成员数据，这些数据将作为后续利用操作的重要节点。  
  
下面将对win32k漏洞常用到的读写原语进行介绍：  
- Bitmap系列：SetBitmapBits/GetBitmapBits可对内核对象bitmap的pvScan0指向的像素数据内存进行修改。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYpUBSJVDBPDevC95XYhhJasSt4q8KeWrSeu0Xzml6CuBuM2D5OMblBA/640?wx_fmt=jpeg "")  
  
此系列一直到RS3微软把Bitmap header与Bitmap data分离后，彻底失效。  
- Palette系列：GetPaletteEntries/SetPaletteEntries可对内核对象Palette的成员pFirstColor（指向4个bytes的数组PALETTENTRY）修改构造RW原语。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYXrzrNvQIBjU6ZZQpgsrsYiap6jdVBiabsHVkxYk7ZNQsIpDRUax3cD6Q/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYGUG2vggJ5q5icIRdsAHk0iceh9wRIxQnYUwwsoE789zyhJjVj8XohticQ/640?wx_fmt=jpeg "")  
- Wnd系列：SetWindowLog/SetWindowLogPtr对wnd(tagWnd)内核对象的修改能力。  
  
应用场景1：  
  
Wnd->StrName 字段是指向窗⼝标题名的指针，通过修改此变量，再借助⽤户态下 的 InternalGetWindowText 和 NtUserDefSetText 函数则可实现任意内核地址读写  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYWibibuZuIVQapqHKiaFANvaa4AlVuyicRWX3EN4M4iaQc0RiaLgh2jaoFdicQ/640?wx_fmt=jpeg "")  
  
应用场景2：  
  
a)申请两个连续的Wnd对象（Spray），Wnd0与Wnd1  
  
b)通过漏洞能力将Wnd0的pExtraBytes字段变为可越界读写的。  
  
c)通过Wnd0.的越界写入能力，修改tagWND1.pExtraBytes到指定地址  
  
d)借助SetWindowLongPtr的修改能力，最后使Wnd1获得任意地址写入能力。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYQCcSDqibyvhqEllXBKCO7QHtklpkbcZHgfLWX7mnR7ftnhlfp9Zjvaw/640?wx_fmt=jpeg "")  
- Menu系列（最新）：GetMenuBarInfo，当其第二参数、第三参数分别设置成-3,1的时候，可以借助menu bar info获取16字节的读取能力。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYia9yXibsd8DSG43492zc3GEClDzzKbkmhFW2v8qwYBTTLkZe4qLXZbaA/640?wx_fmt=jpeg "")  
  
一般仅需tagMenuBarInfo.rcBar.left 和 tagMenuBarInfo.rcBar.top读取指定地址的8个字节的数据。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYiciccxOp5LrSxJiccHMeVuiaveE7CTYQ1J5Vf6dmpKWMd7LdvVRIRlFfUA/640?wx_fmt=jpeg "")  
  
另外，通过GetMenuBarInfo构造Read Primitive时，需要提前构造Fake Menu（用户层），再通过SetWindowLongPtr对Target Wnd的Menu（内核层）进行替换，以达到读取地址可控的目的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYLFs6RojCKbQCVL8rTO1N9GBofK7AIsosBCaNjsSxtm3WrMuSGbibAaA/640?wx_fmt=jpeg "")  
  
4.代码执行阶段  
  
对于win32k内核漏洞，其最终利用方式就是本地提权，而提升权限的主要手法就是进行Token替换，共以下两种方式：  
- Token指针替换（_EX_FAST_REF替换）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYhNtDWmgeawmOenIfvicyGhEPibofJZqp6xosnnCtGXOMvEr2FBIKFe3A/640?wx_fmt=jpeg "")  
  
将当前进程 EPROCESS 中存储的 Token 指针替换为 System 进程的 Token 指针。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYtf5gfLt3iaSlUiaoTtLLiciblsxpDh09JXoIyyU1NmwDmYmHbvreCYXsLA/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYQ8QT1CB5icVbNuT6Cvl4SERCB5Yc4rQA9sVEoDD9ichpAI7iaszAWSUkA/640?wx_fmt=jpeg "")  
- Token中的成员替换  
  
将当前进程 EPROCESS 的成员 Token 指针指向的 Token 块中的数据替换成 System 进程拥有的 Token 块的数据  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZY5PzOjlY9kiaN1gQiaQhqsKace13c0xbwibNcrCBLh1hnAiaIGUtHPjDyEw/640?wx_fmt=jpeg "")  
  
将Present和Enabled的值更改为SYSTEM进程令牌的所有权限。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYXjbEBUJJl7J7shP8lcuDwd1Iq58p6vNhTt3LCeVFkwJetc5Qb0jl4g/640?wx_fmt=jpeg "")  
  
****##   
##   
###   
###   
##   
# 内核对象  
  
# 3.1Bitmap  
1. 简介  
  
GDI（Windows Graphics Device Interface），是windows为应用程序提供图形、文字显示的 API 接口。  
  
Bitmap是GDI中的图形对象，用于创建、操作（缩放、滚动、旋转和绘制）并将图像作为文件存储在磁盘上，其实际上为一个二元数组，去存储像素、颜色、大小等信息。  
- Bitmap关键结构体及对象  
  
SURFACE对象（Bitmap在内核中的结构）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYfibr7yFEnLiaic0iaZ2aG7WSwml0sEsiaIbnwMj9ic2Cz80CtOjzHvvZfG6A/640?wx_fmt=jpeg "")  
  
BaseObject，内核 GDI 对象类的基类都是一个称作 _BASEOBJECT 的结构。对内核对象进行标记，用于描述最基础的对象信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYFBp3015KSIGzMs2icRTuXXibxI8HnJIjoExwPVq0zJAib3UrNLQjsgfSg/640?wx_fmt=jpeg "")  
  
SURFOBJ（Bitmap核心结构），用于控制位图的大小，像素等信息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYGDvJUX7Fr4oZSqIZiaFCLwP1cEUt1JuyMhnTIX9ib7V9HLiayBOW3KnDg/640?wx_fmt=jpeg "")  
- CreateBitmap相关  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYCA3JVLBXffVcnAYq8nHn0dESEUCiclLqyHCY2uyFzDBPa6E633yK8pw/640?wx_fmt=jpeg "")  
  
创建具有指定宽度，高度和颜色格式（颜色平面和位每像素）的位图，而前文中也提过bitmap在内核中关联的对象SURACE,由SURACE通过CreateBitamp的前4个参数去精确控制分配的内核内存块的大小。其调用链如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZY6hy9bLs11Y2nm14iabnuZZicCibMC1JhQEWONPrl8ZdKZY3icXj7ibZLDKg/640?wx_fmt=jpeg "")  
  
在GreCreateBitmap函数中，首先根据传入的 cPlanes 和 cBitsPerPel参数确定位图的像素位类型，然后创建一个DEVBITMAPINFO对象，通过CreateBitmap前四个参数去内存块中申请一片内存并且设置位图数据扫描线的长度。接着lpBits如果不为0，则通过GreSetBitmapBits去设置像素数据。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZY5rNjt9ezGUKNo5s7pKxFVKNWG0HmGAGpdcKLdJE0Qicot3rEmicpsaQQ/640?wx_fmt=jpeg "")  
  
DEVBITMAPINFO的结构：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYDx4qo87FOYSFksic4bHt7OxzV5LCyztBcziakBp2BKSJHuS1r21uHBPA/640?wx_fmt=jpeg "")  
- 扫描线  
  
在 Windows 内核中处理位图像素数据时，通常是以一行作为单位进行的，像素的一行被称为扫描线，而扫描线的长度就表示的是在位图数据中向下移动一行所需的字节数。  
  
位图数据扫描线的长度被存储在SURFACE+0x34 字节偏移的成员（即 SURFACE->so.lDelta 成员）中。这样一来，成员 pvScan0 将指向当前位图 SURFACE 对象的像素点数据缓冲区的起始位置。在后续对位图像素点进行读写访问时，系统位图解析模块将以该对象的 pvScan0 成员存储的地址作为像素点数据区域起始地址。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYhCrJib4zG59YoV6DZCWOIUmznwqVyxK4y5XKd0OS2B5BwoLeDPsu1rQ/640?wx_fmt=jpeg "")  
## 3.2Palette  
1. 简介  
  
调色板是一个数组，其中包含标识当前可以在输出设备上显示或绘制的颜色的颜色值。调色板由能够生成多种颜色但在任何给定时间只能显示或绘制这些颜色的子集的设备使用。  
1. Palette关键结构体及对象  
  
PALETTE对象  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYtuYwHdJOgSu9KzLcHrsBrKFpwwXWnZLqG1Oe4WRKVHa5XicjOujH2ibg/640?wx_fmt=jpeg "")  
  
PALETTE结构中，有三个成员是值得我们关注的分别是cEntries、pFirstColor、apalColors。cEntries指定当前调色板的项数，pFirstColor指向调色板列表起始表项（apalColors）的地址，apalColors是一个结构体数组存储调色板列表数据。  
  
PALETTEENTRY （调色板列表）  
  
结构体 PALETTEENTRY 大小为 4 字节，其各个成员用于定义调色板表项对应的 24 位 RGB 颜色值等信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYmHo31naSymTCM72uxtPzlaz0b1np1ITCLoPY4ib95oJAQQjnHQ0PUWw/640?wx_fmt=jpeg "")  
1. Createpalette相关  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYUdR9zloWRMVI7fqVvRqdJzsIUUMcAmib0uSibWkNV6AVnZBaqk8E8tXw/640?wx_fmt=jpeg "")  
  
Createpalette函数用来创建调色板对象，其只有一个参数lplgpl是指向LOFGPALETTE类型结构体对象的指针。定义如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYjrl36ibnHOMpmOkYGu5G62PwCjgPzTB9e9Miab8XYxONK08KCe40DVfw/640?wx_fmt=jpeg "")  
  
这里我们仅需要关注第二个和第三个参数，palPalEntry是可变长度的 PALETTEENTRY 结构体类型数组，而palNumEntries来决定PALETTEENTRY 的个数。也就是说palette对象的大小是由palNumEntries控制的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYU8jQdOpJeEFiamVJJqXhaVPWMmiadzad0H9ziaInEtcJJqpoziatib5GkUg/640?wx_fmt=jpeg "")  
  
显然，我们可以得出palette对象大小的计算方式：4 * cEntries + 0x90/PALETTE/  
## 3.3Wnd  
1. 简介  
  
Windows是对象，它们同时具有代码和数据，但它们不是C++ 类。相反，程序通过使用名为句柄 的值来引用窗口。句柄是不透明类型。实质上它只是操作系统用来标识对象的数字。可以想象Windows创建的所有窗口都有一个大表。它使用此表按其句柄查找窗口。(它内部的工作方式是否完全相同都很重要。) 窗口句柄的数据类型是 HWND， 这通常发音为"aitch-wind"。窗口句柄由创建窗口的函数返回 ：CreateWindow 和 CreateWindowEx。  
1. 关键结构体及对象  
  
这里只介绍tagWnd常用的字段,分别是tagwnd.cbwndextra和tagWND.ExtraBytes。当使用CreateWindowEx创建窗口时，可以在注册窗口类时通过WNDCLASSEXA结构体中的cbWndExtra字段直接在内存中的tagWND对象之后请求额外的内存字节。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYEiau4m5zRWiaoYWLVz7gcwLzib1VnxjAXYkjePg4OLQ0Z111EIr2BbrFg/640?wx_fmt=jpeg "")  
1. 关键函数分析  
  
   1.CreateWindowEx  
  
CreateWindowEx是用来创建窗口，在漏洞利用的世界中，Wnd地位是非常高的，可被用来进行堆spray，越界写的容器等等。此次我们仅介绍Wnd的pExtraByte字段，分析它在内核中生成的过程。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYq4IsTplHZVbQ5SgDT58YxBic4fVcYZnFxia8OACtzMn9IsWNnkLp11EQ/640?wx_fmt=jpeg "")  
  
上图时CreateWindowEx到内核真正调用xxxCreateWindowEx函数的过程，xxxCreateWindowEx中回到tagWND的cbWndExtra字段进行判断。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZY5KpvLg4hGiaEvbhZzPSdoYzICBvVC83yiaXEo37znPyTCtBKqzDShcoQ/640?wx_fmt=jpeg "")  
  
如果cbWndExtra不为0，则将其作为参数传入xxxClientAllocWindowClassExtraBytes，在xxxClientAllocWindowClassExtraBytes中通过KeUserModeCallback进入到R3，最后调用RtlAllocateHeap为其在用户层的桌面堆上申请一块内存。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYgn7003EmpJhWPv0uzLFVzZSP14yfJB5I6tIoSWpRp8Eu2PSsYzA0Kw/640?wx_fmt=jpeg "")  
1. SetWindowLongPtr  
  
对于SetWindowLongPtr函数，最重要的就是其对Wnd的修改能力，下图xxxSetWindowLongPtr函数的部分反汇编代码，可以看到当dwExtraFlag被设置为800后，可以直接对位于内核桌面堆的pExtraBytes+Index处的数据进行修改。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYnZa5z8rPlgx4vuUXdcIqGzAya6upfzibtXwB9C0ZZKfA6yMkvBFLNzg/640?wx_fmt=jpeg "")  
1. xxxSetWindowData  
  
xxxSetWindowData函数可以对Wnd的spMenu进行替换，这是我们能够利用Menu构造Read Primitive的先决条件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYHCrrWMAHmoZujHMlSgrXCxWzTEHjIPJjLHAl9V2n0C1YeE252doDQw/640?wx_fmt=jpeg "")  
1. 获取相邻Wnd  
  
相邻的窗口中相差的只是一个tagWNDk结构体的大小  
## 3.4Menu  
1. 简介  
  
菜单是为应用程序指定选项或选项组（子菜单）的项目列表。单击菜单项打开子菜单或使应用程序执行命令。菜单管理也是win32k中最复杂得组件之一，其整体依赖多种十分复杂的函数和结构体。  
1. Menu关键结构体及对象  
  
tagMENU，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZY8sicMldZ1IoJlV4UzaDtr6M759Wib5ITkFqmSgvsia9AQ5pYvnficmBiaVQ/640?wx_fmt=jpeg "")  
  
tagPOPUPMENU，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZY3a54ZeSbcDnjibuvh9D1Tap5ibicYQicst0SFb1nVtxabwpbZEA5n3pib8Q/640?wx_fmt=jpeg "")  
1. 信息泄露能力  
  
通过spMenu泄漏EPROCESS内核地址，用于寻找SYSTEM进程以及Token替换。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYWx5USwaYeqoZxMbzj33ibnGtTDibGicGmXHPLKT34GCA3oMyTc3kcQqZw/640?wx_fmt=jpeg "")  
  
****##   
##   
###   
###   
##   
# 攻防进化史  
  
  
漏洞只有能够被成功利用，才可以体现出它的价值。而对于win32k内核漏洞，最经典也是利用率最高的类型就是“任意地址任意写(WWW)”漏洞。本章节将围绕“ArbitraryOverwrite”，对win32k提权利用方式的进化史以及微软相应的缓解措施进行详细阐述。  
## 4.1Win7下的利用模式  
1. 缓解措施  
  
个人认为Win7是Win32k内核漏洞利用最理想的环境，因其具有以下几点特征：  
- Win32k.sys未分离  
  
- 信息泄露的方式最多（目前已知技术均兼容win7）  
  
- 0页内存机制未被缓解  
  
- Win32k 内核对象公开（成员偏移清晰）  
  
综上，可以更加确认一个win32k内核漏洞在win7的利用率是极高的。  
1. 利用思路  
  
我们以“Bitmap”为例，介绍内核提权漏洞在win7上的利用方式：  
  
前提：Arbitrary Memory Write漏洞  
- 创建两个bitmap对象分别为hManager、hWorker,通过GdiSharedHandleTable泄露内核地址。  
  
- 利用任意地址覆盖写漏洞，将hManager的pvScan0修改为指向hWorker成员pvScan0的地址。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYQ0Cia2BNYCnEBLHx5Mq6sxE2zcBHGzDIQsGjErWuYwDZWwznf2tBcYw/640?wx_fmt=jpeg "")  
- 构造对内核任意地址的RW原语（GetBitmapBits/SetBitmapBits）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYlkTEmXAatgXyJkgrkLT3NSSDUZVqdsicnj9qODs3iatEoYkqcYkCsYDg/640?wx_fmt=jpeg "")  
- 本地提权—令牌替换  
  
操作第一个 hManager，可以替换第二个 hWorker->pvScan0地址，再通过第二个 hWorker来将system进程的token写入当前进程。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZY4cxpX8PFtaNDbqsoPqP4DiaCwdejeDSicvNqdFRm71EONoLicE6IPP4qw/640?wx_fmt=jpeg "")  
## 4.2RS1 下的利用模式  
1. 缓解措施  
  
GdiSharedHandleTable泄露bitmap的方式被缓解，GdiSharedHandleTable的pKernelAddress 指向一块无意义的地址。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYLKE5QxXn9zXJibYBX9MF4ibicZJr8U0nw7ofX0zGWE3P1xVVc8DjFKtDQ/640?wx_fmt=jpeg "")  
1. 利用思路  
  
结合网上资料，Windows 中存在着 3 种类型的对象，分别为 User object、GDI object、Kernel object，一共有 40 多种对象。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYQyDlFPvVKpEJwPLpOFAOQ7Q5M5mk9DILM3IkuzIrlFAib1g7RVUJwQw/640?wx_fmt=jpeg "")  
  
而bitmap属于GDI object其存在于换页会话池中，由于GDI object泄露地址方式在RS1版本中被缓解，因此我们需要从另外两种类型对象中去寻找替代方案。此次我们使用的是Accelerator table其属于User object并且也存在于分页会话池中。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYor1MDNiaADlxeBic2xKVia6miaxQI0JO5S1eURT4SUSKTRKT0kdqVQ9lxA/640?wx_fmt=jpeg "")  
  
Tips:非分页池的虚拟地址被物理地址分配,而分页池对应的虚拟地址和物理地址不存在一一映射，只保证在当前执行会话有效，其余内核操作时，并不要求这些对象必须在内存中。  
- User Object地址获取  
  
在user32.dll中有一个全局变量gSharedInfo，其成员aheList为一个USER_HANDLE_ENTRY的句柄表。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZY6P8mhUibXBnTBFTG1cmLaicGPZF2tsFWedTfWYf0mKuET0IK10WFYVZQ/640?wx_fmt=jpeg "")  
  
该句柄表的具体结构如下所示，其第一个成员为pKernel作用GdiSharedHandleTable 中的 pKernel 一致，均指向object在内核中的位置（KernelAddress）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYyCd7qpy6Rga29iaCBXBH30bSw0JIxm2AYB3LOKibc7fS6NdiaibCgz44tA/640?wx_fmt=jpeg "")  
  
因此可通过USER_HANDLE_ENTRY去泄露Accelerator table的内核对象地址。  
  
KernelAddress= SHAREDINFO->USER_HANDLE_ENTRY->pKernel + handle&0xffff  
- Accelerator table 对象创建  
  
函数 CreateAcceleratorTable 用来在内核中创建快捷键对应表。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYibuovIoHibhrD7zvtZQgETOxIibg8iaqfibfB9d8xFict4DUvhqVBt5m5vlA/640?wx_fmt=jpeg "")  
  
该函数存在 LPACCEL lpaccl 和 int cAccel 两个参数。参数 lpaccl 作为指向 ACCEL 结构体类型数组的指针，cAccel 表示数组的元素个数。结构体 ACCEL (szie=6)的定义如下:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYeiaxqY3zicCS4hJ8Q73ajjibaPqKVhiaLLUL0QTs7IdAKVOib7SIL8qJ8fQ/640?wx_fmt=jpeg "")  
- 堆分水  
  
通过1)、2)我们肯定可以想到通过内存分水技术去泄露bitmap内核对象的地址，经笔者分析得出可以控制CreateAcceleratorTable 的参数，来控制其到内核所申请内存的大小。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYiawtggP2G1libPpCTS4CibKYvvkIPG3wCXweLxFk0KbibUIodLGiaia2fgmA/640?wx_fmt=jpeg "")  
  
现在，bitmap和AcceleratorTable内核对象的大小均可控，可以进行内存布局。过程如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYibTp7tFBQ0sCTlmo0svWZUAASyyy4kibCM8DFN8sp2fOb4vBvMfibaL2A/640?wx_fmt=jpeg "")  
  
至此，我们就可以成功泄露bitmap内核对象的地址啦！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYsnpjsJccExEAwpYjPE3PcBBb3zCaEcibl9TaMoHKKg2cJxPR5BST6gQ/640?wx_fmt=jpeg "")  
  
后续提权过程与win7一致。  
## 4.3RS2 下的利用模式  
1. 缓解措施  
  
在RS2中pKernel指向异常地址， AcceleratorTable + 池风水泄露pvScan0的方式失效  
1. 利用思路  
  
新的替代方案—桌面堆，更准确一点就在桌面堆上的lpszMenuName。lpszMenuName就是我们创建窗口时wndclass的成员，同bitmap一样它也存于换页内存池。  
  
另外，我们还需知道桌面堆是有两份分别存于用户态和内核态。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYU2iakPYWMriaH52KaZCFLG5U8jW9DkC55PQLTEHLib7BnDZsF7Qicicz4ag/640?wx_fmt=jpeg "")  
  
上图，在网上流传的比较火，应该是国外某位大神逆出来，再此稍稍瞻仰一下。有了这个我们就可以通过桌面堆来泄露bitmap的内核地址啦。  
- 获取lpszMenuName的地址.  
  
首先，我们要得到内核态桌面堆到用户态桌面堆的偏移值ulClientDelta。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYKM0sE5AVSz8RpQj5nuxBe96iaVUVecUmZ89IKiaLBib6ichibHZkhbFKanQ/640?wx_fmt=jpeg "")  
  
通过HMValidateHandle泄露Wnd的内核地址，然后通过用户态的tagCLS获取lpszMenuName（0x98）的地址。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYZiaFp3ziaib0p6HEpLLhMicMAZSzK2M2dibrCKVrPvbU9X91xmiaYrm3XPVw/640?wx_fmt=jpeg "")  
  
泄露结果如下所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYS4LMTHpQR3PaicxAjoavpyicX0lEWbbqMo1RMFhhC1lyLJfzPyRTTsIw/640?wx_fmt=jpeg "")  
- 堆风水  
  
到这，相信大家都知道可以通过桌面堆对象进行占坑，并控制lpszMenuName的大小与bitmap大小一致。即可成功泄露bitmap的内核地址。lpszMenuName申请内存过程堆栈如下，其大小为实际申请大小。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYLTBzDEP67ZHO8D559n0O10pwibaNUk3q5tETc7xmwhJiarTPGMwrxUjQ/640?wx_fmt=jpeg "")  
  
另外，BitMap的SurFace结构 在RS2上比RS1增大了10。  
  
内存布局如下，申请等大小的lpszMenuName和bitmap。利用UAF技术确保泄露lpszMenuName的地址稳定之后使用bitmap占坑。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYhqYOT3b7nvP3Omib3bwg4sJ5xCHCMrsDPjldrnMXGU9WtIiay8zpkZLA/640?wx_fmt=jpeg "")  
  
下图来自fuzzySecurity的blog,精确的展现出通过lpszMenuName进行UAF后泄露bitmap的过程。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYZv4JppEZtsuGQmvHZwhbt6Ff5opUrdWkPpkP6CGYVvUwPTSABl7bOw/640?wx_fmt=jpeg "")  
## 4.4RS3 下的利用模式  
1. 缓解措施  
  
微软引入了 TypeIsolation 功能将Bitmap header与Bitmap data分离，无法通过Bitmap header取得pvscan0指针的内核地址。  
1. 利用思路  
  
在第三章节介绍过另一个用于WWW漏洞利用的内核对象—Palette，它和bitmap有着异曲同工之妙，palette对象的0x90处是一个4字节的数组apalColors，相当于BitMap里的pixel data，pFirstColor是一个指针，指向apalColors，相当于BitMap里的pvScan0。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZY9AlpZI6zCux315DF3fU4KOKE4ticsOOK7vr8CfwElIo12VsoB8RU0Sw/640?wx_fmt=jpeg "")  
  
因此，我们完全可以按照在RS2中的利用思路，完成在RS3中的提权。  
- 创建两个palette对象分别为hManager、hWorker,并通过桌面堆泄露内核地址。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZY0cEkpIPnebia11TDicRicp47ruW9ObaNyvZZyUTjjXsM8G7p2vFuiaAvzQ/640?wx_fmt=jpeg "")  
  
泄露的方法还是采用池分水技术，利用lpszMenuName为palette占坑。  
  
Palette大小的计算方式：LOGPALETTE->palNumEntries进行控制的，具体如下：  
- 利用任意地址覆盖写漏洞，将hManager的pFirstColor修改为指向hWorker成员pFirstColor的地址。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYNwE6iafsHRiaQvQjhVVq6tAmCUdu9ibNwtDZvS5Kptyib5qq49yUiawPBkw/640?wx_fmt=jpeg "")  
- 构造对内核任意地址的RW原语（GetPaletteEntries/ SetPaletteEntries）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYLxurhib9kycicUWxCg5beBkWGqORYrrbgicWj1p4xcPzz3AEdLiav5FR0A/640?wx_fmt=jpeg "")  
- 提权-令牌替换（与bitmap方式一致）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYASLPJVLe5U2Z1yZChcIqgAw2R1WVCG74LRyC4J1ZFzGW1CMx5BXBRw/640?wx_fmt=jpeg "")  
## 4.5攻防现状  
1. 缓解措施  
  
RS4:  
  
HMValidateHandle泄露内核方法失效  
  
Palette同样被TypeIsolation进行header和body分离  
  
RS5:  
  
微软修改大量API，桌面堆泄露的方法被缓解 。  
  
2.新的思路  
  
到这，已有的所有泄露GDI对象的方法均以被缓解。但车到山前必有路，这也正体现了攻防对抗的魅力，直到2021年CVE-2021-1732的漏洞被爆出，不同于传统的内核漏洞，需借助“溢出”来完成漏洞利用，该漏洞是由于窗口类型混淆而导致的，通过spMenu的信息泄漏能力和借助GetMenuBarInfo/SetWindowLong函数构造读写原语（RW Primitive），最后通过纯数据攻击（DataOnlyAttack，特点不需要执行原语，只操纵操作系统使用的数据结构以实现提权）实现内核提权。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYsn330lXib7qmf3BLMmUdbrLTbLXRkibMFq6fTDfC4sGYCqhzibFxDusCQ/640?wx_fmt=jpeg "")  
  
****##   
##   
###   
###   
##   
# 附录  
  
## 5.1参考链接  
  
https://www.anquanke.com/post/id/235716#h3-4  
  
https://mp.weixi2n.qq.com/s/6mT0O9eur5-VEs0rbV0-mg  
  
https://github.com/gdabah/win32k-bugs/  
  
http://fuzzysecurity.com/tutorials/expDev/21.html  
  
https://www.wangan.com/p/7fygf309c52e2678  
## 5.2环境介绍  
1. 靶场  
  
HEVD的一个Windows Kernel Exploition训练项目--HackSysExtremeVulnerableDriver  
  
https://github.com/hacksysteam/HackSysExtremeVulnerableDriver  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/xkA3iaCzeYppFt6BnrofrTYFHeLfXqcZYKNHMYyUwJZnXXvh880fgWqd1IKrM9qm1IwuJoy75iaKdo2XCklicpvVw/640?wx_fmt=jpeg "")  
  
  
  
**往期推荐**  
  
  
  
[原创 |2023 阿里云CTF / AliyunCTF 部分WriteUp](http://mp.weixin.qq.com/s?__biz=MzI4Mzc0MTI0Mw==&mid=2247497401&idx=1&sn=5d1f0c5d3b2fde7c91cc70ac1203bf84&chksm=eb84abeddcf322fb2bcc48a90b56e3f0e64fd4b193726debfb6df645997a32423e82b82389b6&scene=21#wechat_redirect)  
  
  
[原创 |从Rome看二次反序列化](http://mp.weixin.qq.com/s?__biz=MzI4Mzc0MTI0Mw==&mid=2247497114&idx=1&sn=6948c0c8b8c578a751730c2dc574b532&chksm=eb84a8cedcf321d8100ac9bcf3b15b760f71075239aab3d542d15fd9ebb451b5a4004574bb8d&scene=21#wechat_redirect)  
  
  
[原创 | windows权限维持](http://mp.weixin.qq.com/s?__biz=MzI4Mzc0MTI0Mw==&mid=2247497332&idx=1&sn=5690210ecb4d02adf8a143d45f687372&chksm=eb84ab20dcf3223669900b661635030e91f1d461083ecf31e4d32d17e970877aa2d5f310f431&scene=21#wechat_redirect)  
  
  
  
  
  
