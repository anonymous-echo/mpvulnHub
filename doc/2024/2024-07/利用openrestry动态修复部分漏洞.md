#  利用openrestry动态修复部分漏洞   
原创 帅气的Jumbo  中国白客联盟   2024-06-30 19:18  
  
**背景**  
  
安全风险频出，在甲方如何在不影响业务的情况下修复安全漏洞是一个经常苦扰的问题，因为业务优先，业务在跑，安全没太大的权利责令业务停机修复漏洞，当然及其严重的漏洞除外。本文将尝试通过openrestry来动态解决点击劫持漏洞。  
  
**点击劫持漏洞介绍**  
  
点击劫持漏洞简单讲就是自己构造一个网页，然后用iframe嵌了其他网页，伪造的网页引诱用户点击，当用户点击时实际上是点击到了前面的iframe的网页。找了张网上的图来说明下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dnicaoDibZzp3fH37IPqRFqr2wOZiaWiaulg2ygfjsT7oB3pGDoGD80ibG8ibYaiaJMF3dsoIibNiazB642DUGibn1Ugc1icg/640?wx_fmt=png&from=appmsg "")  
  
                     
  
可以拿以下html来测试：  
  
```
<!DOCTYPE html>
<html>
<head>
   <meta charset="UTF-8">
     <title>点击劫持</title>
<style>
  iframe {
    /*窗口的大小*/
    width: 2500px;
    height: 1600px;
    
  
    /*定位绝对位置*/
    position: absolute;
    top: -195px;
    left: -740px;
    z-index: 2;
    
    /* 从视图上隐藏 */
    -moz-opacity: 0.5;
    opacity: 0.5;
    filter: alpha(opacity=0);
    
    }
    
    /*按钮的位置*/
    button{
      position: absolute;
      top: 120px;
      left: 730px;
      z-index: 1;
      width: 100px;
  }
</style>
</head>

     <body>
          <button>test</button>
          <iframe src="https://www.baidu.com"></iframe>
     </body>
</html>
```  
  
  
       
                
  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dnicaoDibZzp3fH37IPqRFqr2wOZiaWiaulgAm5MoDiaXUXjrwT8UYcDXZLrTbJBQvXGhFpjXJLNEmIdibZk0QJpLRxg/640?wx_fmt=png&from=appmsg "")  
  
              修复方案的话也比较简单，通过设置响应header，添加  
X-Frame-Options  
解决。  
  
**openrestry安装**  
  
安装也很简单，根据官方文档来就行，就不多赘述了：               
https://openresty.org/en/installation.html  
  
**新增lua规则**  
  
现在大家多使用openrestry而不纯使用nginx的目的是因为openrestry支持lua脚本，可以自定义很多东西。在针对漏洞修复的情况，也可以  
依托于openrestry的lua脚本做到“热更新”。  
                
本文中针对点击劫持漏洞，当然也可以通过lua脚本完成，通过lua脚本可以设置给所有经过openrestry的网站都自动添加  
X-Frame-Options  
头，而不用让业务各个都改代码。  
              lua脚本文件内容如下：  
```
ngx.header["X-Frame-Options"] = "DENY"
```  
  
  
openrestry配置如下：  
  
```
lua_code_cache off; # 保证lua脚本修改后无需重启openrestry也可以实时生效              
header_filter_by_lua_file /usr/local/openresty/lua/set_headers.lua; # 设置在响应头过滤阶段执行脚本
```  
  
  
这时候再尝试iframe目标网站，发现已经拒绝嵌入了：               
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dnicaoDibZzp3fH37IPqRFqr2wOZiaWiaulg10Qj9TRbIQx7fd3iahhVueM6xqib45Q8aeye1ORk9Iu5csXtuMZveVmg/640?wx_fmt=png&from=appmsg "")  
  
  
curl也可以看到新增的header头：               
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/dnicaoDibZzp3fH37IPqRFqr2wOZiaWiaulgMG9E0969icVyKNaHUevFUzcnremaV8ibQEoklmjTyBt6xLRRT6VJ9Syg/640?wx_fmt=jpeg "")  
  
      
  
**总结**  
  
本文通过openrestry来动态修复了点击劫持漏洞，一些前端漏洞都可以通过此类方法解决，从而解决“业务不配合”的问题，做到“热更新”修复漏洞。      
  
