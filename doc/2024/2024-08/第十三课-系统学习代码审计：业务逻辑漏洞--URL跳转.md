#  第十三课-系统学习代码审计：业务逻辑漏洞--URL跳转   
原创 开发小鸡娃  安全随心录   2024-08-13 21:55  
  
    收费是因为我如果把群二维码放出来，会有些广告自动进群发广告，本篇只有群号需要付费。  
  
视频地址：  
  
https://space.bilibili.com/482887446/channel/collectiondetail?sid=3340840&ctype=0  
主要内容：1、URL跳转漏洞原理2、转发和重定向的区别3、浏览器解析URL的格式规则4、URL跳转的绕过方式5、几个关于URL跳转绕过的CVEURL跳转漏洞漏洞原理    URL 跳转漏洞也叫作 URL 重定向漏洞，由于服务端未对传入的跳转地址进行检查和控制，从而导致攻击者可以构造任意一个恶意地址，诱导用户跳转至恶意站点。因为是从用户可信站点跳转出去的，用户会比较信任该站点，所以URL跳转漏洞常用于钓鱼攻击，通过转到攻击者精心构造的恶意网站来欺骗用户输入信息，从而盗取用户的账号和密码等敏感信息，更甚者会欺骗用户进行金钱交易。浏览器解析URL的格式scheme://userinfo@host:port/path?query#fragmentScheme:协议 userinfo: 认证信息 Host: 实际访问的域名 Path：访问路径 如下面网址，实际访问的是www.eval.com     http://www.baidu.com.com[@www.eval.com/tou 在业务场景中，在实际浏览器解析访问时中反斜线 \ 会被纠正为正斜线 /。也就是说类似 www.baidu.com\asd 浏览器会自动纠正为：www.baidu.com/asd可能产生漏洞的函数redirectredirect_toredirect_urlurljumpjump_totargettolinklinktodomain转发和重定向    具体区别见：day2JavaWeb基础讲解1.url常见跳转参数：redirect domain  link  to target  targets  jump  jump_to  redirect_urlnuclei中的绕过技巧：http://xxx.xxx.xxx/%0a/baidu.com http://xxx.xxx.xxx/%5C%5Cbaidu.com/%252e%252e%252f其它url跳转绕过技巧：http://xxx.xxx.xxx/redirect.php?url=/www.baidu.comhttp://xxx.xxx.xxx/redirect.php?url=//www.baidu.com http://xxx.xxx.xxx/redirect.php?url=///www.baidu.com http://xxx.xxx.xxx/redirect.php?url=http://www.baidu.comhttp://xxx.xxx.xxx/redirect.php?url=http://www.baidu.com\www.evil.com http://xxx.xxx.xxx/redirect.php?url=http://www.baidu.com http://xxx.xxx.xxx/redirect.php?url=.evil.com(可能会跳到evil.com) http://xxx.xxx.xxx/redirect.php?url=.evil(可能会跳到www.evil.com.evil)期望跳转到www.baidu.comhttp://www.test.com[@www.baidu.com/tou http://@www.realsee.com[@www.baidu.com/tou http://baidu.com\test.com绕过URL跳转https://www.cnblogs.com/-meditation-/articles/16243218.htmljava代码审计漏洞-URL跳转https://www.cnblogs.com/-meditation-/articles/16243853.html搜索关键字redirect:setStatussetHeadersendRedirectModelAndView(url);CVE-2024-22243https://forum.butian.net/share/2781CVE-2024-22259https://forum.butian.net/share/2810CVE-2024-22262https://forum.butian.net/share/2932  
  
