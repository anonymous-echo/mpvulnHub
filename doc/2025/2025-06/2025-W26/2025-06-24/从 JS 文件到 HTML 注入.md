> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5Mzc4MzUzMQ==&mid=2650261344&idx=1&sn=d7948723d5d49662eea50943ae3fc4e4

#  从 JS 文件到 HTML 注入  
骨哥说事  骨哥说事   2025-06-24 07:15  
  
<table><tbody><tr><td data-colwidth="557" width="557" valign="top" style="word-break: break-all;"><h1 data-selectable-paragraph="" style="white-space: normal;outline: 0px;max-width: 100%;font-family: -apple-system, system-ui, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;"><strong style="outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="color: rgb(255, 0, 0);"><strong><span style="font-size: 15px;"><span leaf="">声明：</span></span></strong></span><span style="font-size: 15px;"></span></span></strong><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="font-size: 15px;"><span leaf="">文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由用户承担全部法律及连带责任，文章作者不承担任何法律及连带责任。</span></span></span></h1></td></tr></tbody></table>#   
  
#   
  
****# 防走失：https://gugesay.com/archives/4480  
  
******不想错过任何消息？设置星标****↓ ↓ ↓**  
****  
#   
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlbXyV4tJfwXpicwdZ2gTB6XtwoqRvbaCy3UgU1Upgn094oibelRBGyMs5GgicFKNkW1f62QPCwGwKxA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jkZVRPuQ3tozkTmSlHgKAEpEvGGp1k4iaqZZicdHW7icf8Q8QWPgibLIFyibFO2fnxvtO5fDvqQ1vOKuUg/640?wx_fmt=png&from=appmsg "")  
# 前言  
  
目标网站是一家使用AI，机器学习和数据工具来帮助企业解决问题的公司。  
  
他们通过云平台提供智能解决方案来与医疗保健，金融和零售等行业合作。  
# 漏洞挖掘  
  
像往常一样，白帽小哥使用了多种工具进行子域枚举，并将结果保存在一个文件中。  
  
然后使用HTTPX过滤出 200响应状态的子域，当手动检查每个子域时，小哥遇到了一个子域，该子域显示了一个注册页，上面有一条消息显示注册当前已关闭。  
  
于是小哥利用Javascript 代码编写的“超酷书签”对该子域进行了 JS文件侦察：  

```
javascript:(function(){var scripts=document.getElementsByTagName(&#34;script&#34;),regex=/(?%3C=(\%22|\%27|\`))\/[a-zA-Z0-9_?&=\/\-\#\.]*(?=(\%22|\'|\%60))/g;const%20results=new%20Set;for(var%20i=0;i%3Cscripts.length;i++){var%20t=scripts[i].src;%22%22!=t&&fetch(t).then(function(t){return%20t.text()}).then(function(t){var%20e=t.matchAll(regex);for(let%20r%20of%20e)results.add(r[0])}).catch(function(t){console.log(%22An%20error%20occurred:%20%22,t)})}var%20pageContent=document.documentElement.outerHTML,matches=pageContent.matchAll(regex);for(const%20match%20of%20matches)results.add(match[0]);function%20writeResults(){results.forEach(function(t){document.write(t+%22%3Cbr%3E%22)})}setTimeout(writeResults,3e3);})();

```

  
很快，便发现了**main.js**  
 文件，通过阅读里面的一些代码后，一段特定代码片段成功引起了小哥的注意。  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jkZVRPuQ3tozkTmSlHgKAEpMFOz00VgP3141sGEU0N3lSGEfXaTepK9cS35wSFdwYoU1UCiaPZyfdw/640?wx_fmt=png&from=appmsg "")  
  
  
这段代码包含了注册用户时所有变量的完整 API 路径。快速复制整个代码，然后发出 curl 请求：  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jkZVRPuQ3tozkTmSlHgKAEpy3Xcyib22T0hBa8YBvTpQLibzWnHaZRGSdlqBM9eK8avl4vB7Kib6gsRg/640?wx_fmt=png&from=appmsg "")  
  
成功注册，并实现 HTML 代码注入！  
  
原文：https://medium.com/legionhunters/js-recon-to-html-injection-4cdca8fd88cf  
  
- END -  
  
**加入星球，随时交流：**  
  
**********（会员统一定价）：128元/年（0.35元/天）******  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/hZj512NN8jnMJtHJnShkTnh3vR3fmaqicPicANic6OEsobrpRjx5vG6mMTib1icuPmuG74h2bxC4eP6nMMzbs5QaSlw/640?wx_fmt=jpeg&from=appmsg "")  
  
**感谢阅读，如果觉得还不错的话，欢迎分享给更多喜爱的朋友～**  
  
