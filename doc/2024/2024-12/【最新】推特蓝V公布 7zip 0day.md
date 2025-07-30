#  【最新】推特蓝V公布 7zip 0day   
原创 visionsec  安全视安   2024-12-30 12:38  
  
**声明**  
**：该公众号分享的安全工具和项目均来源于网络，仅供安全研究与学习之用，如用于其他用途，由使用者承担全部法律及连带责任，与工具作者和本公众号无关。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Pf9NC3AaQF5UKOQAYlyDrbUHjlH0xItMyuf71pGUJ9PwmzhHkgOGcibzws6RlbLg6fFYs2sIhiaQ40ic7xn5yBEnw/640?wx_fmt=png&from=appmsg "")  
  
地址：https://x.com/NSA_Employee39/status/1873644808998367272  
1. // 此漏洞利用针对 7-Zip 软件的 LZMA 解码器中的漏洞。它使用带有格式错误的 LZMA 流的精心设计的 .7z 存档来触发 RC_NORM 函数中的缓冲区溢出条件。通过对齐偏移量和有效载荷，漏洞利用操纵内部缓冲区指针来执行 shellcode，从而导致任意代码执行。当受害者使用易受攻击的 7-Zip 版本（当前版本）打开/提取存档时，漏洞利用就会触发，执行启动 calc.exe 的有效载荷（您可以更改这一点）。  
  
1. // 偏移量可能需要调整!!!  
  
```
```  
  
  
