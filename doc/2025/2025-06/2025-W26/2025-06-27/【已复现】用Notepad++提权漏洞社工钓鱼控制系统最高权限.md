> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI5NTQ5MTAzMA==&mid=2247484481&idx=1&sn=12f6a7fef44109a965c102f35130580b

#  【已复现】用Notepad++提权漏洞社工钓鱼控制系统最高权限  
 天黑说嘿话   2025-06-27 01:05  
  
   
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2K9ohfEv3JP2mYJZmoFqadibP2NXm4ndPJ4BsaJLtbVvtsl3EYw8feSrIAFDTC9v6MaWm7MfNzJExg/640?wx_fmt=png&from=appmsg "")  
  
  
CVE-2025-49144 是 Notepad++ v8.8.1 安装程序中存在一个权限提升漏洞，该漏洞允许非特权用户通过不安全的可执行文件搜索路径获取 SYSTEM 级权限，只需极少的用户交互即可利用此漏洞  
### 先看成果  
  
我测试了 8.8.1 和 8.7.9 两个版本均可以无感获得系统最高权限  
  
### 漏洞原因  
  
安装程序在当前工作目录中搜索可执行文件依赖项而不进行验证，从而允许攻击者放置恶意可执行文件，这些可执行文件将在安装期间以 SYSTEM 权限加载  
### 攻击方法  
1. 1. 准备： 将恶意可执行文件放置在目录中  
  
1. 2. 触发方式： 引导用户下载并运行 Notepad++ 安装程序  
  
1. 3. 执行： 安装程序以 SYSTEM 权限从当前目录加载恶意可执行文件  
  
1. 4. 结果： 攻击者获得完全系统控制权  
  
### 影响版本  
  
8.8.1及之前的版本  
### 修复建议  
##### 方式一  
  
如必须使用，尽快更新到 8.8.2 版本  
##### 方式二  
  
直接卸载notepad++，这老外作者是出了名的T独Z独分子，多次发表分裂中国的Z治言论，有太多优秀的开源编辑器可以替代它  
🤡  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/5HsgFkdwV2JBajs0kBDQBO1B5iaz7CF2a4qN5pDOOJnDVC0fd9Kab629XdDo3Xwtib0IUthQmYTvMxTFvbf6It4A/640?wx_fmt=gif&from=appmsg "")  
  
漏洞复现可关注本公众号后回复：  
进群  
  
欢迎关注   
红队安全圈  
  
  
给个一键四连吧  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/5HsgFkdwV2J3Ykl5xDepRoqkSBlQKAEIEx0DHiaQHx6sBYGNDAI6Eia2ZnZLLsHzD8yxEGEVbrzzTL4Shrf7iaWWw/640?wx_fmt=gif&from=appmsg "")  
  
  
   
  
