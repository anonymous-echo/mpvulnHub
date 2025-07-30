#  从webpack开始发现的漏洞大礼包   
aoteman  白帽子左一   2024-01-21 12:00  
  
## 前言  
  
**信息收集贯穿渗透测试的全过程**  
## webpack发现后台地址  
  
日常SRC发现一个比较偏僻的域名，很有可能存在漏洞。git搜域名没找到源码。顺手翻了下js，发现webpack打包的源码，然后赶紧去搜了搜这个怎么利用，发现主要是用来找里面的接口，尝试未授权的思路。这个站点的webpack没有发现什么能未授权的接口，但是发现了config.js文件。这个肯定得进去看看，里面发现了3个地址，都是后台应该有两个是测试阶段的站点，另一个是生产环境。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGb3pyTP91icT9icnEsnQZXMOWCOMl7dsX6QYsjb2r22nOiaHn6Z8ApalXxLGicmIIKibvODcbiaRzD3Rqg/640?wx_fmt=png&from=appmsg "")  
## 后台常规的信息收集和初步测试  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGb3pyTP91icT9icnEsnQZXMOHwViaA6JkiasjMnwQpwCGZQYalbIX6WSs9B62JsExOMS7s8Tglc44veQ/640?wx_fmt=png&from=appmsg "")  
  
常规登录框测试手段，简单测口令，然后验证码能不能绕过开始爆破，扫目录什么的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGb3pyTP91icT9icnEsnQZXMORMVx8fkAiaYHqmmyOcJeZUumtjCHUGb53Blb76SVucMibkBnOV9u27Bw/640?wx_fmt=png&from=appmsg "")  
  
thinkphp3.2.3然后就是已知漏洞测试，再加上有位师傅提过的日志泄露，都测试了一遍，无果  
## github泄露源码  
  
过了好几天想起来这个站点，不甘心在后台晃悠，想起来有位师傅提起过，可以把页面上的东西都扔到github搜一下，前面已经在github上搜过域名了不好使。然后看到后台底下有个技术支持qq号码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGb3pyTP91icT9icnEsnQZXMOQGhK5R7tENQTIpBwJ124DT6AgFibwLkia30o0xan4UWHnKYPll3F2tmw/640?wx_fmt=png&from=appmsg "")  
  
反正没有入手点，就把qq号码扔到github上面搜索发现源码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGb3pyTP91icT9icnEsnQZXMOR4NFiaiaYssE8iaAXsMWPU6GOoCxxAphbPhjCbHhWcRf5ic2Z6ZMFLFhbw/640?wx_fmt=png&from=appmsg "")  
  
这里发现了两个入手点，一个是ueditor,一个是swfupload。ueditor php版本已知的应该是1.4.3 ssrf漏洞，但是是云服务器，危害不大，重心放在swfupload上面  
  
进去swfupload文件夹里面结构是下面这样子的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGb3pyTP91icT9icnEsnQZXMOYuA5Qic4DnZtlpYdYic4Q7B7amySQIP53pKFicIDSJsy3EUghIEXnc5mg/640?wx_fmt=png&from=appmsg "")  
## 任意文件删除  
  
第一个就看到任意文件删除  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGb3pyTP91icT9icnEsnQZXMOvPn2MLib9TMVKA8uwqeJ6aVGApmScDfRXNuukaaCBgp7lAalvhR4OcQ/640?wx_fmt=png&from=appmsg "")  
## 任意文件上传  
  
upload.php太长了，最快的方法就是码云直接找个swfupload的源码，扔phpstudy，直接上传php，抓包复制过来，然后重新上传。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGb3pyTP91icT9icnEsnQZXMOHFxNLstTEZ8799bC0xtymg9iaof2frSs5TmTUAs1GNMufldicdfQc7LA/640?wx_fmt=png&from=appmsg "")  
  
访问代码执行成功。  
```
文章来源：https://xz.aliyun.com/t/8547
文章作者：aoteman
```  
  
声明：⽂中所涉及的技术、思路和⼯具仅供以安全为⽬的的学习交流使⽤，任何⼈不得将其⽤于⾮法⽤途以及盈利等⽬的，否则后果⾃⾏承担。**所有渗透都需获取授权**  
！  
  
@  
  
**学习更多渗透技能！体验靶场实战练习**  
```
```  
  
