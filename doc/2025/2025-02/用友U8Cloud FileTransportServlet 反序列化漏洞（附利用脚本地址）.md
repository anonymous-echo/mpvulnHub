#  用友U8Cloud FileTransportServlet 反序列化漏洞（附利用脚本地址）   
原创 chobits02  Code4th安全团队   2025-02-10 14:14  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/EXTCGqBpVJQGQG6ibYpsQ9hibUNQ9JogaBM4ETcLDdyuTknYvxjLbGCEQFKUEwbwpummEIZzqUcA3Mhaj6yJqd9Q/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
  
用友U8cloud  
是用友推出的新一代云ERP，主要聚焦成长型、创新型企业，提供企业级云ERP整体解决方案，全面支持多组织业务协同、营销创新、智能财务、人力服务，构建产业链制造平台，融合用友云服务，实现企业互联网资源连接、共享、协同，赋能中国成长型企业高速发展、云化创新。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRbTKOmKs1vTxcmcrVl8dqicN5bD1BftK1oiblCOlXM79wgwExpibvaRLmFoCDIzJX64PWF1Kd3ib4v5Q/640?wx_fmt=png&from=appmsg "")  
  
   
  
用友U8Cloud在全版本中存在反序列化漏洞。未经授权的攻击者可以通过访问FileTransportServlet类时构造恶意请求包，当传递的恶意序列化数据被系统反序列化后，将会导致远程代码执行，从而使得服务器被控制。  
  
网上有用友漏洞官方预警，但是没有公开利用poc  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRbTKOmKs1vTxcmcrVl8dqicJUEm3ka9EwH0YP3DngfI3ibsZ90SNqTz1UTO5G2nuS3DT7lMkG7L9Jg/640?wx_fmt=png&from=appmsg "")  
  
但是方法名称为  
FileTransportServlet，可以审计代码得出poc  
  
漏洞的关键代码如下，doAction方法中调用了  
performTask方法  
```
  public void performTask(HttpServletRequest request, HttpServletResponse response) throws Exception {
    GZIPInputStream input = new GZIPInputStream((InputStream)request.getInputStream());
    GZIPOutputStream output = new GZIPOutputStream((OutputStream)response.getOutputStream());
    ObjectOutputStream objOut = new ObjectOutputStream(output);
    ObjectInputStream objInput = new ObjectInputStream(input);
    FileTransportVO transVO = (FileTransportVO)objInput.readObject();
    UnitInfoVO unitInfo = IUFOUICacheManager.getSingleton().getUnitCache().getUnitInfoByCode(transVO.getUnitCode());
    if (unitInfo != null) {
      String strUnitID = unitInfo.getPK();
      ImportFileUtil.importFileByUnit(request.getSession().getId(), transVO.getContent(), strUnitID, transVO.getLangCode());
      objOut.writeObject(null);
    } else {
      objOut.writeObject(new UfoException("miufoexpnew00034", new String[] { transVO.getUnitCode() }));
    } 
    objInput.close();
    objOut.close();
    input.close();
    output.close();
  }
```  
  
performTask方法中对前端传参进行了gzip解压后，进行了  
readObject反序列化造成了漏洞  
  
使用  
ysoserial-all.jar生成cc6的利用链文件，  
使用脚本读取内容构造请求dnslog验证漏洞，如下图  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRbTKOmKs1vTxcmcrVl8dqicphUsy2V62v1QMUKNSjqicwPiaMlpJe1ib2Hb2w7nDicCXY2ES4F7hPnRjQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRbTKOmKs1vTxcmcrVl8dqictpibcIffxvQNAnDtQKEPA2t7UAF3czYX4RJkr8OvkwVAicbSWsOJRlag/640?wx_fmt=png&from=appmsg "")  
  
  
漏洞利用脚本附在团队  
Freebuf知识大陆中了，地址如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRbTKOmKs1vTxcmcrVl8dqictYJ9LckMr7Dpw1uEdADFmibNricDVbBhrkvxkA6fk0GnPa0DiaFepyGEg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRbTKOmKs1vTxcmcrVl8dqicibPUHBRefqN8lNmaIiaGEGVXtj5o08tPIdovcTCTm7wxb7MiaiaHc8BJ7Q/640?wx_fmt=png&from=appmsg "")  
  
  
**往期漏洞利用文档即工具一览**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRbTKOmKs1vTxcmcrVl8dqicvBFytPGxMVUcSMcUwNg5XapE16ENd8pLmCvQmCKFzk0UTFKHBUMShw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRbTKOmKs1vTxcmcrVl8dqicr5TMfxMbDgznZKUEClSp241PLenxJ3fk0sHgArNmyibma09M2cmkbPQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRbTKOmKs1vTxcmcrVl8dqicFc1uiaeeAOMQWLVA1D5qOSIsicFHMGEbu0fm3oWWBl7cza0HSlpkWdhg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRbTKOmKs1vTxcmcrVl8dqic3qCLDWHtXgibzFELBicuSX0TJTiaTLYQVDLKpdUPDn68KagYL2M7zbRLg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRbTKOmKs1vTxcmcrVl8dqicNLg4yjnSW5qJakdJkciceNcDKiaick4zjQZkGhlAKsMgfCLOODhW9jR8Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRbTKOmKs1vTxcmcrVl8dqicib0ribiaCCzCoVEiaVLfahB4tq8thpX9ZtzK3ibPSoGHZ9sb8XWibCM46Trw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRbTKOmKs1vTxcmcrVl8dqicuqYPibtQe7N3giach9J1MaXQmiaqBkib2hlpibbxESuQ8Y5elhiaULmut0cQ/640?wx_fmt=png&from=appmsg "")  
  
更多资源移步知识大陆  
  
  
  
**SRC漏洞挖掘出洞课程**  
，是由团队内部师傅根据实际挖洞经历整合的适合挖掘漏洞但是缺乏思路、刚接触学习漏洞挖掘不出漏洞的师傅们的漏洞挖掘教程。  
  
第一期课程价格  
199  
，这价格还要什么自行车？课程正在持续更新中~  
  
[](http://mp.weixin.qq.com/s?__biz=MzkzMzE5OTQzMA==&mid=2247485154&idx=1&sn=90f1bce91e53a5bf538bdef11fe15b2d&chksm=c2516dcbf526e4dd6d75254b70743d30902a7f0288d001148a41cc05e2d0b9fb09702d2ea03e&scene=21#wechat_redirect)  
  
  
# 寻找网络安全的守护者，C4安全团队纳新中。我们是一群对网络安全充满热情的年轻探险者，团队名为 Code4th安全团队（简称 C4安全）。我们正式成立于2024年7月，致力于深入挖掘国内外SRC平台的漏洞，以守护网络世界的安全。  
  
[](https://mp.weixin.qq.com/s?__biz=MzkzMzE5OTQzMA==&mid=2247485257&idx=1&sn=1d36719418ef7fc0715d7cf81508c140&scene=21#wechat_redirect)  
  
  
  
  
  
END  
  
  
  
关注Cod  
e4th安全团队  
  
了解更多安全相关内容~  
  
  
  
  
