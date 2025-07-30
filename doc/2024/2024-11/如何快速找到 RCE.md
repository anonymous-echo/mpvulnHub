#  如何快速找到 RCE   
 迪哥讲事   2024-11-19 21:00  
  
<table><tbody><tr><td width="557" valign="top" style="word-break: break-all;"><h1 data-selectable-paragraph="" style="white-space: normal;outline: 0px;max-width: 100%;font-family: -apple-system, system-ui, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;"><strong style="outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="color: rgb(255, 0, 0);"><strong><span style="font-size: 15px;">声明：</span></strong></span><span style="font-size: 15px;"></span></span></strong><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="font-size: 15px;">文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由用户承担全部法律及连带责任，文章作者不承担任何法律及连带责任。</span></span></h1></td></tr></tbody></table>#   
  
  
# 背景介绍  
  
本文将分享国外白帽子在‘侦察’阶段如何快速发现 RCE 漏洞的经历。以Apache ActiveMQ 的 CVE-2023–46604 为特例，重点介绍如何发现类似此类的漏洞，让我们开始吧。  
# 快速发现过程  
  
在‘侦察’阶段，白帽小哥会保持每周更新一次目标站点的子域列表，并每三天扫描一次开放端口。  
  
对于子域枚举，白帽小哥习惯使用 Subfinder 和 Amass 等工具，使用方法：  
```
subfinder -dL domains.txt -o subdomains.txt
#then subdomains of subdomains 
subfinder -dL subdomains.txt -o more-subdomains.txt

#using amass
amass enum -passive -norecursive -noalts -df domains.txt -o subs.txt
#then subdomains of subdomains
amass enum -passive -norecursive -noalts -df subs.txt -o more-subs.txt
```  
  
然后使用下面的命令进行子域去重：  
```
cat more-subdomains.txt subdomains.txt subs.txt more-subs.txt | sort -u > targets.txt
```  
  
之后就是端口扫描，通过制作简单的脚本来使用 DNSx 检查子域并将它们分成 15 个分组，然后使用 nohup 运行 Naabu 保持在后台运行。  
  
脚本如下：  
```
#!/bin/bash

if [ $# -eq 0 ]; then
    echo "Usage: $0 <file>"
    exit 1
fi

cat $1 | dnsx -o $1_ok.txt

split -l 15 $1_ok.txt 15_file_

for file in 15_file_*; do
    nohup naabu -list "$file" -p - -o "${file}.out"&
done
```  
  
然后对端口进行去重：  
  
cat 15*out | sort -u > ports.out  
  
这样可以过滤掉一些疑似蜜罐的主机，但 Naabu 的结果有时也不是很可靠。  
  
其中一个bamboo.target.com的主机，白帽小哥注意到它有一个特殊的开放端口 54663。  
  
使用Nmap的 -sSCV 进行扫描时，会发现运行的是 Apache ActiveMQ，显示可能存在 CVE-2023–46604 漏洞。  
  
通过PoC进行测试后，确定可被成功利用。于是白帽小哥第一时间提交漏洞报告，很快便获得了厂商的确认。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnOKicuicWyfeBczI2Ld9WGbLHuJqqAsxLrb3ggthnuib1aW6rtLYPl6PurIjibJhcaBfWeSP22NibZtIA/640?wx_fmt=png&from=appmsg "")  
  
顺利获得赏金奖励。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnOKicuicWyfeBczI2Ld9WGbLo1AoicQTJOicKKnguO3Hx1Ys7KCcV6POD8ZiaGngVEiaicAr1DNfF0ibrrbQ/640?wx_fmt=png&from=appmsg "")  
  
读后感:其实这篇文章我们学习的是其中的思路:在搜集好资产以后，需要进行批量指纹识别，识别出出相对应的组件以后，迅速查看一下组件有没历史漏洞，如果有，那么大概率就是去捡钱了，那么在这个过程中我们需要学习和积累的能力是如何去写指纹和POC,尤其是灯塔和nuclei这些比较知名的一些工具  
  
如果你是一个长期主义者，欢迎加入我的知识星球，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5jYW8icFkojHqg2WTWTjAnvcuF7qGrj3JLz1VgSFDDMOx0DbKjsia5ibMpeISsibYJ0ib1d2glMk2hySA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 往期回顾  
  
[一款bp神器](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247495880&idx=1&sn=65d42fbff5e198509e55072674ac5283&chksm=e8a5faabdfd273bd55df8f7db3d644d3102d7382020234741e37ca29e963eace13dd17fcabdd&scene=21#wechat_redirect)  
  
  
[ssrf绕过新思路](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247495841&idx=1&sn=bbf477afa30391b8072d23469645d026&chksm=e8a5fac2dfd273d42344f18c7c6f0f7a158cca94041c4c4db330c3adf2d1f77f062dcaf6c5e0&scene=21#wechat_redirect)  
  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
  
##   
  
  
