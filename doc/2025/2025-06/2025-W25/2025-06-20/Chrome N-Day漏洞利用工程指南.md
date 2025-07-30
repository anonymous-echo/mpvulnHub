> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI1MDA1MjcxMw==&mid=2649908325&idx=2&sn=06326aff0db92eb3b0cf94102cdbec84

#  Chrome N-Day漏洞利用工程指南  
原创 rayh4c  赛博攻防悟道   2025-06-19 23:39  
  
## 前言：N-Day漏洞利用的工程化趋势  
  
在BSides Luxembourg 2025安全会议上，Arnaud（@Petitoto）的演讲“在2025年，一个现代浏览器的漏洞利用需要什么？”引发了广泛关注。  
  
  
其核心并非展示0-Day漏洞，而是通过串联三个已公开的N-Day漏洞，完整演示了针对最新版（130）Chrome浏览器的全链攻击。  
  
其开源的 
```
chromium-exploit-dev
```

  
 工具包，提供了一个剖析现代浏览器攻击的绝佳样本。它揭示出一个重要趋势：浏览器攻击的挑战正从发现单个高危漏洞，转向如何通过精巧的工程化手段，将多个独立的、威力有限的漏洞串联成稳定、可靠的攻击链。  
  
本文将结合 
```
chromium-exploit-dev
```

  
 的源代码，对这条攻击链进行客观、深入的技术拆解，为相关研究提供一份详尽的分析指南。  
## ⛓️ 攻击链总览：从渲染器到计算器  
  
该攻击链遵循了经典的浏览器攻击范式，其目标是通过三个阶段的漏洞利用，最终在Windows系统上弹出 
```
calc.exe
```

  
，实现从浏览器渲染进程到完全控制系统的跨越。  
  
阶段一  
 V8内存损坏 → V8沙箱内任意读写  
  
**漏洞:**  
 
```
CVE-2025-0291
```

  
 - V8 Turboshaft WASM编译器中的一个类型混淆漏洞。  
  
**🎯 目标:**  
 在V8的沙箱（V8 Sandbox/Cage）内部，获得稳定的、不受限制的内存读写能力。  
  
  
阶段二  
 V8沙箱逃逸 → 渲染进程任意读写  
  
**漏洞:**  
 
```
Issue 379140430
```

  
 - V8 WASM中的一个签名类型混淆漏洞。  
  
**🎯 目标:**  
 突破V8沙箱的限制，获得在整个渲染进程（Renderer Process）内存空间内的任意读写能力。  
  
  
阶段三  
 渲染进程RCE → 浏览器沙箱逃逸  
  
**漏洞:**  
 
```
CVE-2024-11114
```

  
 - Mojo IPC接口中的一个逻辑漏洞。  
  
**🎯 目标:**  
 将渲染进程的内存读写能力转化为任意代码执行（RCE），并利用Mojo漏洞模拟用户交互，最终通过DLL劫持实现浏览器主沙箱逃逸。  
  
以下将深入代码，剖析每个阶段的技术细节和实现意图。  
## 🛡️ 第一阶段：攻破V8的第一道防线  
  
攻击的起点是获取最初的内存控制权。  
### 入口点 (vulns/memcor/CVE-2025-0291.js):  
  
此脚本是攻击链的基石，利用V8的WASM JIT编译器Turboshaft中的类型混淆漏洞。通过精心构造的WASM模块，使编译器错误地处理循环中的对象类型，最终创造出两个最基础的利用原语：  
- 
```
addrOf(object)
```

  
给定一个JS对象，返回其在内存中的地址。  
  
- 
```
fakeObj(address)
```

  
给定一个内存地址，伪造一个指向该地址的JS对象。  
  
  
这两个原语虽然强大，但通常不稳定且易崩溃，因为它们直接依赖于JIT编译器的特定错误行为。  
### 稳定化与“上帝视角” (v8/cage.js):  
  
这部分代码体现了其“利用开发框架”的定位。它并未满足于 
```
addrOf
```

  
 / 
```
fakeObj
```

  
，而是利用这两个不稳定的原语，构建了一个极其稳定的V8沙箱内存操纵工具。  
1. **伪造ArrayBuffer:**  
 脚本首先伪造一个 
```
ArrayBuffer
```

  
 对象。  
  
1. **修改元数据:**  
 接着，用 
```
addrOf
```

  
 和 
```
fakeObj
```

  
 修改这个伪造 
```
ArrayBuffer
```

  
 的内部元数据，将其 
```
backing_store
```

  
 指针指向V8沙箱的基地址（
```
0x0
```

  
），并将其 
```
byte_length
```

  
 设置为沙箱的最大尺寸。  
  
1. **创建DataView:**  
 最后，在这个被篡改的 
```
ArrayBuffer
```

  
 之上创建一个 
```
DataView
```

  
 实例，命名为 
```
sbxMemory
```

  
。  
  
  
至此，攻击方获得了一个“上帝视角”的DataView，可以通过简单的 
```
sbxMemory.getBigUint64()
```

  
 和 
```
sbxMemory.setBigUint64()
```

  
，在V8沙箱的任何地址上进行稳定、可靠的读写。这一步将一个不稳定的内存损坏漏洞，工程化成了一个可靠的内存控制API。  
  
// 伪代码: v8/cage.js 的核心逻辑  
  
function  
getSbxMemory  
(  
addrOf  
,  
fakeObj  
) {  
  
      
// 1. 创建一个正常的ArrayBuffer作为模板  
  
      
let  
a =  
new  
ArrayBuffer  
(  
8  
);  
  
  
      
// 2. 获取其内存地址  
  
      
let  
a_addr =  
addrOf  
(a);  
  
  
      
// 3. 伪造一个JSArrayBuffer对象，并修改其元数据  
  
      
// (需要精确计算Map、backing_store等字段的偏移量)  
  
      
let  
fake_ab_addr = a_addr +  
0x40n  
;  
  
      
write64  
(fake_ab_addr +  
0x00n  
,  
addrOf  
(a) +  
0x0n  
);  
// 复制Map指针  
  
      
write64  
(fake_ab_addr +  
0x18n  
,  
0x4000000000n  
);  
// byte_length  
  
      
write64  
(fake_ab_addr +  
0x20n  
,  
0n  
);  
// backing_store  
  
    ...  
  
  
      
// 4. 将伪造的地址转换为JS对象  
  
      
let  
fake_ab =  
fakeObj  
(fake_ab_addr);  
  
  
      
// 5. 在这个被完全控制的ArrayBuffer上创建DataView  
  
      
let  
sbxMemory =  
new  
DataView  
(fake_ab);  
  
      
return  
sbxMemory;  
  
}  
## 🚀 第二阶段：冲出V8的牢笼  
  
在V8沙箱内获得控制权后，下一步是突破这层束缚，染指整个渲染进程。  
### 逃逸原语 (vulns/v8sbx/379140430.js):  
  
此漏洞同样发生在WASM中，利用函数签名在JIT编译（Tier-up）过程中的类型混淆，允许以错误的参数类型调用一个函数。通过这个漏洞，脚本实现了两个关键目标：  
- **泄露Trusted Cage指针:**  
 泄露出一个指向V8沙箱外部“可信空间”（Trusted Cage）的指针，作为通往渲染进程广阔内存空间的第一把钥匙。  
  
- **构建任意读写原语:**  
 基于泄露的指针，构建出 
```
arbRead()
```

  
 和 
```
arbWrite()
```

  
 函数，其能力范围不再局限于V8沙箱，而是整个渲染进程的地址空间。  
  
### 寻找可执行内存 (RCE) 的基石 (rwx/helpers/trusted-rwx.js):  
  
获得了渲染进程的任意读写能力后，执行原生代码（Shellcode）的关键一步是找到一块同时具备读、写、执行（RWX）权限的内存页。该脚本的实现方法如下：  
- **Egg Hunting（猎蛋）:**  
 创建大量的WASM实例，并在每个实例的JIT代码段中嵌入一个独特的魔术数字（"Egg"）。  
  
- **内存扫描:**  
 利用上一步获得的 
```
arbRead()
```

  
，从泄露的Trusted Cage指针开始，在内存中扫描这个"Egg"。  
  
- **定位RWX页:**  
 一旦找到"Egg"，就意味着找到了WASM代码所在的内存页。由于JIT编译的需求，这些页面通常被标记为RWX。脚本通过 
```
getRWX()
```

  
 函数返回这个RWX内存页的地址。  
  
  
// 伪代码: trusted-rwx.js 的核心逻辑  
  
const  
EGG =  
0xdeadbeefdeadbeefn  
;  
// 定义一个独特的“蛋”  
  
  
// 1. 创建多个WASM实例，每个实例的代码中都包含EGG  
  
for  
(  
let  
i =  
0  
; i <  
100  
; i++) { ... }  
  
  
// 2. 从已知的trusted_space_ptr开始，扫描内存  
  
let  
rwx_page =  
0n  
;  
  
for  
(  
let  
i =  
0n  
; i <  
0x10000000n  
; i +=  
8n  
) {  
  
      
if  
(  
arbRead  
(trusted_space_ptr + i) === EGG) {  
  
          
// 找到了！将地址对齐到页边界  
  
        rwx_page = (trusted_space_ptr + i) & ~  
0xfffn  
;  
  
          
log  
(  
`[+] Found RWX page at   
${  
hex  
(rwx_page)  
}  
`  
);  
  
          
break  
;  
  
    }  
  
}  
### 执行原生代码 (rwx/shellcodes.js & rwx/src/*.asm):  
  
拥有RWX内存页和任意读写能力后，即可执行原生代码。
```
shellcodes.js
```

  
 提供了一系列JS函数，用于将预先编译好的汇编代码（来自 
```
rwx/src/
```

  
 目录）写入RWX页并执行。  
## 💻 终极越狱  
  
最后一步是从渲染进程的沙箱中逃逸，获得系统权限。  
### Mojo逻辑漏洞与“物理”点击 (vulns/sbx/CVE-2024-11114.js):  
  
此漏洞利用了Chrome内部IPC框架Mojo的一个逻辑缺陷，该缺陷允许渲染进程无限制地调用 
```
StartDragging
```

  
 函数来控制鼠标。  
  
关键技术细节：模拟鼠标拖拽  
  
利用已获得的RCE能力，可以直接在内存中构建参数并调用 
```
chrome.dll
```

  
 中未导出的 
```
StartDragging
```

  
 函数。通过连续调用此函数，并不断改变目标屏幕坐标，即可模拟出平滑的鼠标移动轨迹，实现对UI的精准“物理”点击。  
### DLL劫持与最终Payload (static/.../calc.cpp):  
  
当被模拟的鼠标点击下载并运行一个旧版的 
```
putty.exe
```

  
 后，它会尝试加载系统合法的 
```
winspool.drv
```

  
。然而，由于Windows的DLL搜索顺序，它会优先加载位于同一目录（即下载目录）下的恶意 
```
winspool.drv
```

  
。  
  
关键技术细节：Windows DLL搜索顺序  
  
DLL劫持利用了Windows加载动态链接库时的固定搜索路径。通过将恶意的 
```
winspool.drv
```

  
 与 
```
putty.exe
```

  
 放在同一目录下，可以确保系统优先加载它，而不是System32下的合法版本，从而触发代码执行。  
## 💡 设计思想与工程化特点  
  

```
chromium-exploit-dev
```

  
 项目的代码实现，体现了清晰的工程化和模块化设计思想。  
- **关注点分离 :**  
架构上严格区分漏洞利用代码和辅助工具，实现“即插即用”，极大提高研究效率。  
  
- **自动化与工具链 :**  
Python脚本可自动下载PDB文件、解析函数地址，解决了硬编码偏移量更新的繁琐问题，将移植成本降到最低。  
  
- **对稳定性与可靠性的追求:**  
代码多处实现都体现了对可靠利用的追求，目标是构建可用的利用链，而非学术性的PoC。  
  
## 结论与启示  
  
Arnaud (@Petitoto) 的工作描绘了一幅现代浏览器攻击的清晰蓝图。它证明了：  
  
**对于攻击方:**  
 0-Day已非必需品。通过对已修复漏洞的快速分析和强大的工程化工具，完全可以快速构建针对最新版本浏览器的有效攻击链。  
  
**对于防御方:**  
 仅仅修复单个漏洞是远远不够的。防御体系必须是纵深的。需要在V8沙箱、进程隔离、IPC通信等每一个环节都部署有效的缓解措施。  
  
总而言之，
```
chromium-exploit-dev
```

  
 展示了当精巧的漏洞利用技术与卓越的软件工程思想相结合时所能产生的威力，对攻防双方都具有极高的参考价值。  
  
  
