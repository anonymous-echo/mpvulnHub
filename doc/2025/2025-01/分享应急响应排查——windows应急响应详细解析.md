#  分享应急响应排查——windows应急响应详细解析   
原创 神农Sec  神农Sec   2025-01-01 02:00  
  
#   
  
扫码加圈子  
  
获内部资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，学习文档，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。  
#   
  
  
             
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x1 前言**  
  
<table><tbody><tr><td data-colwidth="100" width="100" valign="top" style="width:75.0pt;background:#F5F5F5;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf=""><span textstyle="" style="font-size: 16px;">题序</span></span></span></p></td><td data-colwidth="366" width="366" valign="top" style="width:274.5pt;background:#F5F5F5;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf=""><span textstyle="" style="font-size: 16px;">题目</span></span></span></p></td><td data-colwidth="356" width="356" valign="top" style="width:267.0pt;background:#F5F5F5;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf=""><span textstyle="" style="font-size: 16px;">答案</span></span></span></p></td></tr><tr><td data-colwidth="100" width="100" valign="top" style="width:75.0pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf=""><span textstyle="" style="font-size: 16px;">1</span></span></span></p></td><td data-colwidth="366" width="366" valign="top" style="width:274.5pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf=""><span textstyle="" style="font-size: 16px;">1.请提交攻击者攻击成功的第一时间，格式：YY:MM:DD hh:mm:ss</span></span></span></p></td><td data-colwidth="356" width="356" valign="top" style="width:267.0pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf=""><span textstyle="" style="font-size: 16px;">2023:22:45:23</span></span></span></p></td></tr><tr><td data-colwidth="100" width="100" valign="top" style="width:75.0pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf=""><span textstyle="" style="font-size: 16px;">2</span></span></span></p></td><td data-colwidth="366" width="366" valign="top" style="width:274.5pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf=""><span textstyle="" style="font-size: 16px;">2.请提交攻击者的浏览器版本                  </span></span><span leaf=""><br/></span><span leaf=""><span textstyle="" style="font-size: 16px;">                    </span></span><span leaf=""><br/></span></span></p></td><td data-colwidth="356" width="356" valign="top" style="width:267.0pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf=""><span textstyle="" style="font-size: 16px;">Firefox/110.0</span></span></span></p></td></tr><tr><td data-colwidth="100" width="100" valign="top" style="width:75.0pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf=""><span textstyle="" style="font-size: 16px;">3</span></span></span></p></td><td data-colwidth="366" width="366" valign="top" style="width:274.5pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf=""><span textstyle="" style="font-size: 16px;">3.请提交攻击者目录扫描所使用的工具名称</span></span></span></p></td><td data-colwidth="356" width="356" valign="top" style="width:267.0pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf=""><span textstyle="" style="font-size: 16px;">Fuzz Faster U Fool</span></span></span></p></td></tr><tr><td data-colwidth="100" width="100" valign="top" style="width:75.0pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf=""><span textstyle="" style="font-size: 16px;">4</span></span></span></p></td><td data-colwidth="366" width="366" valign="top" style="width:274.5pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf=""><span textstyle="" style="font-size: 16px;">4.找到攻击者写入的恶意后门文件，提交文件名（完整路径）</span></span></span></p></td><td data-colwidth="356" width="356" valign="top" style="width:267.0pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf=""><span textstyle="" style="font-size: 16px;">C:\phpstudy_pro\WWW\x.php</span></span></span></p></td></tr><tr><td data-colwidth="100" width="100" valign="top" style="width:75.0pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf=""><span textstyle="" style="font-size: 16px;">5</span></span></span></p></td><td data-colwidth="366" width="366" valign="top" style="width:274.5pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf=""><span textstyle="" style="font-size: 16px;">5.找到攻击者隐藏在正常web应用代码中的恶意代码，提交该文件名（完整路径）</span></span></span></p></td><td data-colwidth="356" width="356" valign="top" style="width:267.0pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf=""><span textstyle="" style="font-size: 16px;">C:\phpstudy_pro\WWW\usr\themes\default\post.php</span></span></span></p></td></tr><tr><td data-colwidth="100" width="100" valign="top" style="width:75.0pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf=""><span textstyle="" style="font-size: 16px;">6</span></span></span></p></td><td data-colwidth="366" width="366" valign="top" style="width:274.5pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf=""><span textstyle="" style="font-size: 16px;">6.请提交内存中可疑进程的PID</span></span></span></p></td><td data-colwidth="356" width="356" valign="top" style="width:267.0pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf=""><span textstyle="" style="font-size: 16px;">2176</span></span></span></p></td></tr><tr><td data-colwidth="100" width="100" valign="top" style="width:75.0pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf=""><span textstyle="" style="font-size: 16px;">7</span></span></span></p></td><td data-colwidth="366" width="366" valign="top" style="width:274.5pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf=""><span textstyle="" style="font-size: 16px;">请提交攻击者执行过几次修改文件访问权限的命令</span></span></span></p></td><td data-colwidth="356" width="356" valign="top" style="width:267.0pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf=""><span textstyle="" style="font-size: 16px;">2</span></span></span></p></td></tr><tr><td data-colwidth="100" width="100" valign="top" style="width:75.0pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf=""><span textstyle="" style="font-size: 16px;">8</span></span></span></p></td><td data-colwidth="366" width="366" valign="top" style="width:274.5pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf=""><span textstyle="" style="font-size: 16px;">8.请指出可疑进程采用的自动启动的方式</span></span></span></p></td><td data-colwidth="356" width="356" valign="top" style="width:267.0pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf=""><span textstyle="" style="font-size: 16px;">.bat</span></span></span></p></td></tr></tbody></table>  
             
  
            
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x2 windows应急响应日志分析参考文章**  
  
1. https://blog.csdn.net/qq_38205354/article/details/122454417  
  
1. https://www.cnblogs.com/v1vvwv/p/Windows-Emergency-Response.html  
  
日志分析工具   
-  
  
Log  
  
Parser  
            
  
            
  
1  
、登录成功的所有事件  
            
  
LogParser  
.  
exe  
  
-  
i  
:  
EVT  
 –  
o  
:  
DATAGRID  
    
"SELECT *  
    
FROM c:\Security.evtx where EventID=4624"  
            
  
            
  
2  
、指定登录时间范围的事件：  
            
  
LogParser  
.  
exe  
  
-  
i  
:  
EVT  
 –  
o  
:  
DATAGRID  
    
"SELECT *  
    
FROM c:\Security.evtx where TimeGenerated>'2018-06-19 23:32:11' and TimeGenerated<'2018-06-20 23:34:00' and EventID=4624"  
            
  
            
  
3  
、提取登录成功的用户名和  
IP  
：  
            
  
LogParser  
.  
exe  
  
-  
i  
:  
EVT  
    
–  
o  
:  
DATAGRID  
    
"SELECT EXTRACT_TOKEN(Message,13,' ') as EventType,TimeGenerated as LoginTime,EXTRACT_TOKEN(Strings,5,'|') as Username,EXTRACT_TOKEN(Message,38,' ') as Loginip FROM c:\Security.evtx where EventID=4624"  
            
  
            
  
4  
、登录失败的所有事件：  
            
  
LogParser  
.  
exe  
  
-  
i  
:  
EVT  
 –  
o  
:  
DATAGRID  
    
"SELECT *  
    
FROM c:\Security.evtx where EventID=4625"  
            
  
            
  
5  
、提取登录失败用户名进行聚合统计：  
            
  
LogParser  
.  
exe  
    
-  
i  
:  
EVT  
  
"SELECT  
    
EXTRACT_TOKEN(Message,13,' ')  
    
as EventType,EXTRACT_TOKEN(Message,19,' ') as user,count(EXTRACT_TOKEN(Message,19,' ')) as Times,EXTRACT_TOKEN(Message,39,' ') as Loginip FROM c:\Security.evtx where EventID=4625 GROUP BY Message"  
            
  
LogParser  
.  
exe  
  
-  
i  
:  
EVT  
 –  
o  
:  
DATAGRID  
    
"SELECT TimeGenerated,EventID,Message FROM c:\System.evtx where EventID=6005 or EventID=6006"  
            
  
  
             
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x3 题目详情**  
  
### 1.请提交攻击者攻击成功的第一时间，格式：YY:MM:DD hh:mm:ss      
  
2023:22:45:23  
  
在  
Windows  
  
Server  
  
2012  
中，事件日志文件通常存储在以下目录下：  
            
  
C  
盘的  
windows  
\  
System32  
\  
Winevt  
\  
Logs  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVjtw20CBcc4wQKxuhf6M4oCk47FJJIAkSyCWOAicyrvQD6JOxogt398MtJZQpwJ1ecia140DNqVZwA/640?wx_fmt=png "")  
  
  
也可以利用cmd然后输入  
eventvwr.msc  
查看日志内容，  
  
里面可以进行日志的筛选、日志查找、日志保存、日志详细信息查看等操作。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVjtw20CBcc4wQKxuhf6M4oibYkYENQwlT6wFXGVSvyvzvveaUywb8egQdhIhx5XpccF09iaiaoE8VUA/640?wx_fmt=png "")  
  
  
这条日志是POST请求并且请求的登入响应的是302然后接下来就到了manage所以这条是成功登入的  
  
管理员的请求也是首次攻击成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVjtw20CBcc4wQKxuhf6M4oC3A271TqIWWkCLwl9UTstd3A9VyQm2mIibibGdg1DsDK4qOttahiatxzQ/640?wx_fmt=png "")  
  
             
### 2.请提交攻击者的浏览器版本      
  
Firefox/110.0  
  
查看日志的ua头能得到  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVjtw20CBcc4wQKxuhf6M4ozF6CAuTb9V8ToVPfDMKk9NiahY5q8DyHyFuouOssL7MM9WNKWyy4XzQ/640?wx_fmt=png "")  
  
### 3.请提交攻击者目录扫描所使用的工具名称      
  
Fuzz Faster U Fool  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVjtw20CBcc4wQKxuhf6M4ooiaoQEPkMBmhoyafFU47Qf3goCdO7YkM2iaBJia5r73M8jHy2SACDnrKw/640?wx_fmt=png "")  
  
             
  
             
### 4.找到攻击者写入的恶意后门文件，提交文件名（完整路径）      
  
C:\phpstudy_pro\WWW\x.php  
  
因为一般上传恶意后门文件大多后缀都是.php，所以直接在C盘本地查找.php，然后再挨个查看  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVjtw20CBcc4wQKxuhf6M4o0XMUzicgS2iaHMXSDSFE96nbh01IoduZRIcor5o5jkumibCOPvcq4ibQXw/640?wx_fmt=png "")  
  
  
后来在C:\phpstudy_pro\WWW目录下的x.php文件中，发现了恶意木马  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVjtw20CBcc4wQKxuhf6M4oxWepj2C7A2hpZOodewiap2byOl7a4JEPdMiab3tOPs1MHVfre3mGUSUA/640?wx_fmt=png "")  
  
    
### 5.找到攻击者隐藏在正常web应用代码中的恶意代码，提交该文件名（完整路径）      
  
C:\phpstudy_pro\WWW\usr\themes\default\post.php  
  
这里题目说的是web应用代码中的恶意代码，那么我们就在C:\phpstudy_pro\WWW下找，  
  
就只有几个文件，那么我们就挨个看  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVjtw20CBcc4wQKxuhf6M4oxLmiaHuQsgjLPFQiaVjVic9UicWlbxpupqRjzGM5DaVaTGk9Dtys3K1P9A/640?wx_fmt=png "")  
  
  
发现post.php文件里面有个base64编码的内容，解码发现就是x.php的木马内容  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVjtw20CBcc4wQKxuhf6M4oKgRozIODfEScLgWTGymaNJmd0JXRSMz3CTBfzyB5FgrznpWXgicIctA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVjtw20CBcc4wQKxuhf6M4oe4YmIIWKHMIz57DvaYAPyiaUDwHhUCxFOibFKM31RcjXmWOZOWiaXlVWw/640?wx_fmt=png "")  
  
### 6.请提交内存中可疑进程的PID      
  
2176  
  
win标直接右击，然后点击任务管理器：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVjtw20CBcc4wQKxuhf6M4olHWRAqU2d73b3wibLuU7iaqdeYsgI45u0ibFxZDSvDBnxzPTX9o0p2wYg/640?wx_fmt=png "")  
  
通过任务管理器发现一个360.exe PID为 2176  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVjtw20CBcc4wQKxuhf6M4oGWAftJhWDH1ibvsX22JYxLJmDWr3yJG28QTbHp2pHtky87ibpLyTkHZA/640?wx_fmt=png "")  
  
通过资源检测器发现在对外进行连接  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVjtw20CBcc4wQKxuhf6M4oLHuXPl5BIVl9ovrewb9bQT9SzkwekhibfbatQar1ptPibo6I4tUy6h6g/640?wx_fmt=png "")  
  
### 7.请提交攻击者执行过几次修改文件访问权限的命令      
  
2  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVjtw20CBcc4wQKxuhf6M4osgiaaJ4sKQuxiajibLdOYz4ssGrezRzOGickHE77hepgE64iaUkdYOE2eEA/640?wx_fmt=png "")  
  
### 8.请指出可疑进程采用的自动启动的方式      
  
.bat  
  
在策略组->计算机配置->Windows设置->脚本(启动/关闭)->启动->属性 发现自启动了一个bat脚本  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVjtw20CBcc4wQKxuhf6M4obwjPSibGKwowwXhdwGsL2DqCGLJqKal9zU4iaVVQeAoFE6yVfZDK3GEw/640?wx_fmt=png "")  
  
             
  
我们是神农安全，  
**点赞 + 在看**  
 铁铁们点起来，最后祝大家都能心想事成、发大财、行大运。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mngWTkJEOYJDOsevNTXW8ERI6DU2dZSH3Wd1AqGpw29ibCuYsmdMhUraS4MsYwyjuoB8eIFIicvoVuazwCV79t8A/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap086iau0Y0jfCXicYKq3CCX9qSib3Xlb2CWzYLOn4icaWruKmYMvqSgk1I0Aw/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**内部圈子介绍**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap08Z60FsVfKEBeQVmcSg1YS1uop1o9V1uibicy1tXCD6tMvzTjeGt34qr3g/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
圈子专注于更新src相关：  
  
```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、分享src优质视频课程
3、分享src挖掘技巧tips
4、微信小群一起挖洞
5、不定期有众测、渗透测试项目
6、需要职业技能大赛环境dd我
```  
  
  
  
  
  
  
```
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWBeNFS2WNPd2FJ1SmqGkcf3s0DkMZicbriaUEuXagWt2eqxBWkUXRyQabIczmNAT5nTxc9tvaBzlww/640?wx_fmt=png&from=appmsg "")  
  
  
**欢迎加入星球一起交流，券后价仅40元！！！ 即将满200人涨价**  
  
**长期更新，更多的0day/1day漏洞POC/EXP**  
  
    
  
  
  
