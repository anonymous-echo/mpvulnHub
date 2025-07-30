#  【复现】Chrome V8堆沙箱绕过分析   
启明星辰  ADLab   2025-04-30 07:27  
  
更多安全资讯和分析文章请关注启明星辰ADLab微信公众号及官方网站（adlab.venustech.com.cn）  
  
  
  
01  
  
  
**研究背景**  
  
  
  
V8是Google Chrome脚本语言（JavaScript）的解析引擎。多年来Google安全团队一直致力于提升V8的安全性，但V8漏洞仍层出不穷。除了经典的内存破坏、运行时问题，V8优化编译器的逻辑问题转化为内存破坏是V8漏洞中的典型。如果编译器本身就是攻击面，生成有漏洞的代码在所难免。通过采取内存安全的编程语言或者硬件安全不能缓解这种问题。在这种情况下，Google安全提出V8沙箱，将V8堆保存在1TB的沙箱内，将利用V8漏洞造成的破坏限制在沙箱内。攻击者为了能进一步构造任意内存读写，必须找到能绕过V8沙箱的漏洞。  
  
理想情况下，V8沙箱使得浏览器即使运行不安全的代码也不会造成攻击威胁。 然而事实并非如此。在pwn2own2024比赛中，Manfred Paul利用了一个V8中的类型混淆漏洞（CVE-2024-2887）控制沙箱内的内存，同时也披露了一种绕过V8沙箱的方法。启明星辰ADLab研究人员着重分析复现了该V8沙箱的绕过方法，并提醒Google Chrome用户及时更新浏览器，避免受到NDay威胁。  
  
  
02  
  
  
**V8沙箱**  
  
  
  
V8沙箱的出现，将进程地址空间分为V8沙箱内存和V8沙箱外内存，为了防止任意内存读写，禁止使用危险的原始指针。沙箱内的对象通过对沙箱基地址的偏移引用。如下面的ArrayBuffer的内存布局，后端存储数据的原始指针（紫色部分）由沙箱基址偏移取代：  
  
  
  
V8外部对象（如Blink对象）通过外部索引表引用。为了控制流完整性，代码和它的元数据等危险对象也要移到沙箱外，由代码索引表以及信任表引用。信任表用于对不包含原始指针的V8对象（如Bytecode 、Code metadata）的索引，这些对象虽然不包含指针，但利用这些对象仍可能打破沙箱。V8沙箱整体的设计图如下：  
  
  
V8沙箱的出现增加了利用链的长度，一定程度上减少了V8漏洞对浏览器安全带来的攻击威胁。攻防相生相克，在pwn2own2024比赛中，Manfred Paul就利用一个整数溢出漏洞绕过了V8沙箱。  
  
  
03  
  
  
**漏洞分析**  
  
#   
  
在沙箱出现前，通过  
ArrayBuffer  
以及其对应的  
TypedArray  
后端存储可有效控制任意内存读写。从上面的  
ArrayBuffer  
的内存布局可知，现在后端存储指针被替换为沙箱指针，而且长度被限制在  
235   
，有效阻止了利用这种方法任意读写。  
  
随着Resizable ArrayBuffer  
的出现，对  
ArrayBuffer  
和  
SharedArrayBuffer  
以及他们的  
Type View  
的访问变得更加复杂。具体来讲对于  
ArrayBuffer  
和  
SharedArrayBuffer  
的构造函数添加了  
maximum length，ArrayBuffer  
能够随时增加和缩减缓存大小，而  
SharedArraybuffer  
能够随时增加缓存大小。在对象创建后缓存的动态变化，致使每次访问后端缓存都要重新计算缓存的长度。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/VuRGkncX57OmfmOLH4UAVu0nC2Giaaa4R5JVlNMapmUyTr0mfWsl9Xyd1FoA44oeggSV2WvB6pfZBA36C81WY5g/640?wx_fmt=png&from=appmsg "")  
  
对于类型数组的长度计算应该采取（  
byte_length - byte_offset  
）  
/element_size ,   
下面是对  
RAB  
长度计算：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/VuRGkncX57OmfmOLH4UAVu0nC2Giaaa4Ru6Sj66P52hrZriaekZPG0LWRrtq3p28MHgAjE1c9iaCmoY7C3aPjyQFQ/640?wx_fmt=png&from=appmsg "")  
  
相较于  
RAB  
对于  
byte_length  
和  
byte_offset  
的溢出检查，  
GSAB  
缺少整数溢出检查，在拥有沙箱内内存破坏的能力下，这两个值完全可控，当  
byte_offset  
大于  
byte_length,   
其后端存储后的整个地址空间可控，完全突破  
V8  
沙箱，达到沙箱外内存读写。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/VuRGkncX57OmfmOLH4UAVu0nC2Giaaa4RxicsMfIFGdibQdrib8EF6awxY3IQy5IicuNV0qszNHC13Y1y9o6SGIBXxg/640?wx_fmt=png&from=appmsg "")  
  
  
04  
  
  
**漏洞复现**  
  
#   
  
创建  
GSAB (ab)  
对象，  
length  
为  
0x3000  
，  
maxByteLength  
为  
0x6000  
；创建类型数组  
Uint8Array (dv)  
，偏移值为  
0x2000   
；优化  
func  
函数根据提供的索引（  
i  
）给类型数组元素（  
dv[i]  
）赋值（  
0x88  
）。  
  
打印类型数组对象（  
dv  
）以便于查看其后端存储指针，使用沙箱内写函数修改类型数组（  
dv  
）的偏移为  
0x8000  
（由于内存存储整数值为实际值的  
2  
倍，所以实际偏移为  
0x4000   
）。偏移值（  
0x4000  
）大于长度  
(0x3000) ,  
导致整数溢出，当使用超大的索引（  
0x10000000000  
）越界访问后端缓存时，计算的索引小于长度值，导致越界写。  
  
可以看到类型数组（  
dv  
）的后端存储指针为  
0x316600002000  
：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/VuRGkncX57OmfmOLH4UAVu0nC2Giaaa4RPusqRahicy88U62wNvwJvjnJt0ibODEFPuR21UMlAObMGe9PYrqKEBqg/640?wx_fmt=png&from=appmsg "")  
  
V8  
沙箱的内存范围是在  
1TB  
的地址空间，程序在对  
0x326600002000  
沙箱外的不可写内存赋值（  
0x88  
）时出现崩溃：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/VuRGkncX57OmfmOLH4UAVu0nC2Giaaa4RxY0QbSuOY85VSiavBbqAjqg2esVDg1ibCWjP0OFXx0qdNn90xEEeNIOA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/VuRGkncX57OmfmOLH4UAVu0nC2Giaaa4RhjYxxmxiagbCich1LCUetetn0F5yIXkAZXbhVtL9CgfL6gVAdXlickqiaQ/640?wx_fmt=png&from=appmsg "")  
  
  
05  
  
  
**漏洞修复**  
  
#   
# 在BuidLength函数长度计算之前，添加了对byte_offset和byte_length的比较，避免出现整数溢出：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/VuRGkncX57OmfmOLH4UAVu0nC2Giaaa4RIKSp0CwRUaImHgssBTasx3CapicSzhMK2Bbglpy8uHibicaAnCc0WDtxg/640?wx_fmt=png&from=appmsg "")  
  
  
06  
  
  
**漏洞影响**  
  
#   
# Chrome before 123.0.6312.86  
#   
#   
  
**参考链接：**  
  
[1]  
https://docs.google.com/document/d/1FM4fQmIhEqPG8uGp5o9A-mnPB5BOeScZYpkHjo0KKA8/edit?tab=t.0  
  
[2]  
https://www.zerodayinitiative.com/blog/2024/5/2/cve-2024-2887-a-pwn2own-winning-bug-in-google-chrome  
  
[3]  
https://github.com/tc39/proposal-resizablearraybuffer  
  
[4]  
https://chromium-review.googlesource.com/c/v8/v8/+/5385329/4/src/compiler/graph-assembler.cc  
  
  
  
  
  
启明星辰积极防御实验室（ADLab）  
  
  
  
  
  
ADLab成立于1999年，是中国安全行业最早成立的攻防技术研究实验室之一，微软MAPP计划核心成员，  
“黑雀攻击”概  
念首推者。截至目前，ADLab已通过 CNVD/CNNVD/NVDB/CVE累计发布安全漏洞6500余个，持续保持国际网络安全领域一流水准。实验室研究方向涵盖基础安全研究、数据安全研究、5G安全研究、AI+安全研究、卫星安全研究、运营商基础设施安全研究、移动安全研究、物联网安全研究、车联网安全研究、工控安全研究、信创安全研究、云安全研究、无线安全研究、高级威胁研究、攻防对抗技术研究。研究成果应用于产品核心技术研究、国家重点科技项目攻关、专业安全服务等  
。  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/VuRGkncX57ONOtW3DSPMEXiaLPqrs8a20KxsFg78IaJzyEf51AIjLGNkDG5tsCH76Qo7PoVz74JGQqKJbCh5PdQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
