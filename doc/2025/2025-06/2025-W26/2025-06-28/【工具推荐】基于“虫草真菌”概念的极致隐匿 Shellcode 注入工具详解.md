> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg4NzgzMjUzOA==&mid=2247485864&idx=1&sn=e4257ed5a2181965abea4ee03bb97df9

#  【工具推荐】基于“虫草真菌”概念的极致隐匿 Shellcode 注入工具详解  
原创 visionsec  安全视安   2025-06-27 23:00  
  
**声明**  
**：该公众号分享的安全工具和项目均来源于网络，仅供安全研究与学习之用，如用于其他用途，由使用者承担全部法律及连带责任，与工具作者和本公众号无关。**  
##   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Pf9NC3AaQF6kTFpicOjFTQ2YqlY0V0ibKHZ95xhCAZv7bCe52KwRCGLRkxiakASgsFclp9toNj5riaJ7N4Y23k9Ymg/640?wx_fmt=png&from=appmsg "")  
## 前言  
  
在现实世界中，有一种令人毛骨悚然的寄生真菌——  
**Ophiocordyceps camponoti-balzani（虫草真菌）**  
，它能够精准操控蚂蚁行为，让其主动爬到利于孢子传播的位置，然后悄无声息地夺取宿主生命。  
  
而在网络攻防世界，有一个灵感来自这种“虫草机制”的攻击工具，也正在悄然蔓延。  
## 🧬 工具介绍  
  
它是一个极其隐匿的   
**Shellcode 加载器**  
，它能够将恶意 Payload（如 CobaltStrike Beacon）注入到正常的可执行文件（.exe 或 .dll）中，并在不破坏原有文件结构的前提下，实现完整的恶意代码执行。  
  
整个加载器像“虫草”一样隐藏在宿主体内，伪装成毫无异样的正常文件。静态分析工具很难发现其踪迹，而行为检测系统（EDR/AV）则会被其多种反检测机制所欺骗。  
## 🛡️ 核心特性  
- ✅   
**XOR 加密 Payload**  
，防止明文暴露  
  
- ✅   
**环境感知（Guardrail）执行**  
，只在特定环境中解密运行  
  
- ✅   
**反仿真（Anti-Emulation）机制**  
，绕过沙箱与 AV 仿真引擎  
  
- ✅   
**EDR 混淆与去激活技术**  
，降低内存扫描命中率  
  
- ✅   
**保留原始 PE 文件结构与元数据**  
，对抗静态特征分析  
  
- ✅   
**函数入口劫持（Entrypoint Hijack）**  
实现代码执行  
  
- ✅   
**无需 PEB Walk，直接复用 Import Table 实现 API 调用**  
（Cordyceps 技术核心）  
  
## 🔧 使用方式一览  
  
此工具提供两种使用方式：Web UI 和命令行（推荐后者用于批量自动化）。  
### 基础准备：  
- 安装 [Visual Studio 2022]，包含   

```
cl.exe
```

  
 与   

```
ml64.exe
```

  
 编译环境  
  
- 配置 Python 环境：  

```
pip install -r requirements.txt
```

  
### 命令行注入示例：  
  
假设你有一个   

```
calc64.bin
```

  
 Shellcode 和   

```
7z.exe
```

  
 可执行文件，执行如下：  

```
python supermega.py \
  --shellcode calc64.bin \
  --inject 7z.exe \
  --carrier alloc_rw_rx \
  --decoder xor_2 \
  --antiemulation sirallocalot \
  --carrier_invoke backdoor
```

  
即可输出一个已经注入 Shellcode 的恶意   

```
7z.exe
```

  
 文件。  
## ⚙️ 可配置模块说明  
  
<table><thead><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;"><th style="box-sizing: border-box;padding: 6px 13px;font-weight: bold;border-width: 1px 1px 0px;border-style: solid solid none;border-color: rgb(223, 226, 229) rgb(223, 226, 229) currentcolor;border-image: none;margin: 0px;"><span cid="n106" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 296.53125px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">参数</span></span></span></th><th style="box-sizing: border-box;padding: 6px 13px;font-weight: bold;border-width: 1px 1px 0px;border-style: solid solid none;border-color: rgb(223, 226, 229) rgb(223, 226, 229) currentcolor;border-image: none;margin: 0px;"><span cid="n107" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 612.484375px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">描述</span></span></span></th></tr></thead><tbody><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n109" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 296.53125px;min-height: 10px;"><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;font-family: var(--monospace);text-align: left;vertical-align: initial;border: 1px solid rgb(231, 234, 237);background-color: rgb(243, 244, 244);border-radius: 3px;padding: 0px 2px;font-size: 0.9em;"><span leaf="">--shellcode</span></code></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n110" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 612.484375px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">需要注入的 Payload Shellcode（x64）</span></span></span></td></tr><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;background-color: rgb(248, 248, 248);"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n112" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 296.53125px;min-height: 10px;"><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;font-family: var(--monospace);text-align: left;vertical-align: initial;border: 1px solid rgb(231, 234, 237);background-color: rgb(243, 244, 244);border-radius: 3px;padding: 0px 2px;font-size: 0.9em;"><span leaf="">--inject</span></code></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n113" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 612.484375px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">宿主 PE 文件，可为 exe 或 dll</span></span></span></td></tr><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n115" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 296.53125px;min-height: 10px;"><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;font-family: var(--monospace);text-align: left;vertical-align: initial;border: 1px solid rgb(231, 234, 237);background-color: rgb(243, 244, 244);border-radius: 3px;padding: 0px 2px;font-size: 0.9em;"><span leaf="">--carrier</span></code></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n116" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 612.484375px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">执行 Shellcode 的加载模块，如 alloc_rw_rx</span></span></span></td></tr><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;background-color: rgb(248, 248, 248);"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n118" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 296.53125px;min-height: 10px;"><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;font-family: var(--monospace);text-align: left;vertical-align: initial;border: 1px solid rgb(231, 234, 237);background-color: rgb(243, 244, 244);border-radius: 3px;padding: 0px 2px;font-size: 0.9em;"><span leaf="">--decoder</span></code></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n119" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 612.484375px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">解密模块，支持 XOR、XOR2 等</span></span></span></td></tr><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n121" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 296.53125px;min-height: 10px;"><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;font-family: var(--monospace);text-align: left;vertical-align: initial;border: 1px solid rgb(231, 234, 237);background-color: rgb(243, 244, 244);border-radius: 3px;padding: 0px 2px;font-size: 0.9em;"><span leaf="">--antiemulation</span></code></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n122" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 612.484375px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">反仿真模块，如 timeraw, sirallocalot</span></span></span></td></tr><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;background-color: rgb(248, 248, 248);"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n124" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 296.53125px;min-height: 10px;"><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;font-family: var(--monospace);text-align: left;vertical-align: initial;border: 1px solid rgb(231, 234, 237);background-color: rgb(243, 244, 244);border-radius: 3px;padding: 0px 2px;font-size: 0.9em;"><span leaf="">--guardrail</span></code></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n125" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 612.484375px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">限制在哪些环境中执行，如检查环境变量</span></span></span></td></tr><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n127" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 296.53125px;min-height: 10px;"><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;font-family: var(--monospace);text-align: left;vertical-align: initial;border: 1px solid rgb(231, 234, 237);background-color: rgb(243, 244, 244);border-radius: 3px;padding: 0px 2px;font-size: 0.9em;"><span leaf="">--carrier_invoke</span></code></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n128" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 612.484375px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">指定入口点劫持方式，如 overwrite 或 backdoor</span></span></span></td></tr><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;background-color: rgb(248, 248, 248);"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n130" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 296.53125px;min-height: 10px;"><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;font-family: var(--monospace);text-align: left;vertical-align: initial;border: 1px solid rgb(231, 234, 237);background-color: rgb(243, 244, 244);border-radius: 3px;padding: 0px 2px;font-size: 0.9em;"><span leaf="">--payload_location</span></code></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n131" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 612.484375px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">Payload 注入位置：.text 或 .rdata</span></span></span></td></tr></tbody></table>## 🧙  技术细节亮点  
  
在设计上最大程度避免了引入异常行为，例如：  
- **不走 PEB 结构链**  
，避免被行为分析引擎标记  
  
- **使用现有 IAT 表完成函数调用**  
，减少 API Hook 暴露  
  
- **支持导出函数劫持（DLL 模式）**  
  
- **可选关闭自动修复 IAT**  
 以维持 PE 结构原貌，增强 OPSEC 隐蔽性  
  
## 🚫 OPSEC 注意事项  
  
虽然提供了一系列反检测机制，但你仍需手动配置执行限制（如   

```
--guardrail
```

  
），确保其不会在分析平台或沙箱中自动触发执行。  
  
例如：  

```
--guardrail env --guardrail-key VCINSTALLDIR --guardrail-value Community
```

  
上述设置确保只有装有 Visual Studio 2022 的系统上才会执行，极大提高对抗动态沙箱的能力。  
## 💭 总结与推荐  
  
它是近年来在 shellcode 隐匿与加载领域的一款杰作，其设计理念极度贴合现代红队需求：  
- 对抗现代 EDR  
  
- 最小化静态特征  
  
- 扩展性强，支持自定义 Carrier、Decoder、Anti-Emu 模块  
  
- UI & CLI 双支持，适合自动化部署与演示  
  
# 免费网络安全资料PDF大合集  
  
**链接：https://pan.quark.cn/s/41b02efa09e6**  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/Pf9NC3AaQF5xOsytm8HnicSzbLxpd8ftiayzOUDHO0ThH4c5u1nj0xL95BmAMgOfsc1d426a81FwEcpMYiazDBNRQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**后台回复：0051**  
  
**获得项目地址**  
  
  
  
