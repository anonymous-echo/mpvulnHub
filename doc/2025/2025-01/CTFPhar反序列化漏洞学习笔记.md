#  CTF:Phar反序列化漏洞学习笔记   
 sec0nd安全   2025-01-22 13:00  
  
使用phar://伪协议读取文件时，文件会被解析成phar对象，phar对象内的以反序列化形式存储的用户自定义元数据信息会被反序列化。  
  
影响函数  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0LTz7Lex94WW1djaoXnQU2vDC6B8YKicn26SnkCDxiaRB2rkW5dgwxcfUBuG1neQ2dqoTGy3D9sQEwxI3XOq3ngg/640?wx_fmt=png&from=appmsg "")  
  
pha  
r结构  
  
phar  
由四部分组成，分别是  
  
1.stub是一个文件标志，格式为 ：xxx<?php xxx;__HALT_COMPILER();?>。可理解为phar文件头。  
  
2.manifest是被压缩的文件的属性等放在这里，这部分是以序列化存储的，是主要的攻击点，因为这里以序列化的形式存储了用户自定义的Meta-data。  
  
3.contents是被压缩的内容，在没有特殊要求的情况下，这个被压缩的文件内容可以随便写。  
  
4.signature签名，放在文件末尾。  
  
利用条件  
  
1.phar文件能上传至服务器。  
  
2.存在受影响函数，存在可以利用的魔术方法。  
  
3.phar和:和/没被过滤。  
  
4.自己电脑能生成phar文件。  
  
生成phar文件  
  
生成phar文件需要修改php.ini中的配置文件，将phar.readonly设置为off  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0LTz7Lex94WW1djaoXnQU2vDC6B8YKicnAzUe8IJwFbrHkpeVZutkL6Kdz1BsdC6nEjicbFnx5giaFy5OaPcXic2Rg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0LTz7Lex94WW1djaoXnQU2vDC6B8YKicny0M7Ux2J3x2WZY1rVO516a2xNtU8RpBUVPAia4UuRV89BetojJ2wveg/640?wx_fmt=png&from=appmsg "")  
  
生成后的phar文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0LTz7Lex94WW1djaoXnQU2vDC6B8YKicnXTj98btPzt7pIhqe87Dt3KibUcBWDomvHXKNyicwp4CAxt7h1JrhBVRg/640?wx_fmt=png&from=appmsg "")  
  
使用方法  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0LTz7Lex94WW1djaoXnQU2vDC6B8YKicnfWfa6vQp9uAPR39C2UwLAM1icxUjQTjckosjJiavy5UciaEUgZeKthichQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0LTz7Lex94WW1djaoXnQU2vDC6B8YKicniaxG1ILma9SZMd7OYYrmJAH2nuBdE0UicyH4HS6hXR5L5IFica43z3HpA/640?wx_fmt=png&from=appmsg "")  
  
在做文件上传的时候先考虑上传PHP文件，可以先尝试双写绕过等绕过姿势，如果不行就考虑上传phar文件  
  
漏洞修复 可以进行简单的过滤  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0LTz7Lex94WW1djaoXnQU2vDC6B8YKicnjJ6RlibRHvVkx4GvjXIOw5icsicfuwQHZMvWib6xMFJRbiaA69cZRTj0SwQ/640?wx_fmt=png&from=appmsg "")  
  
CTF题目练习  
  
[HNCTF 2022 WEEK3]ez_phar  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/0LTz7Lex94WW1djaoXnQU2vDC6B8YKicnT5NXKEEibeIgEYaNIVGWL3SyLVDicB5VfdRyLrpf7aLtfeWaYIsYodLA/640?wx_fmt=jpeg "")  
  
查看源码可以看到没有反序列化函数，因此考虑用phar。  
  
生成phar文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0LTz7Lex94WW1djaoXnQU2vDC6B8YKicnEDRLocQx8U3eg6iaSDW2sIWI8PoWNPd67hxlquFEicSocu4SKp2cbJ9A/640?wx_fmt=png&from=appmsg "")  
  
进行文件上传，只允许上传jpg\png\jpeg格式，将phar文件更改后缀为.jpg  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0LTz7Lex94WW1djaoXnQU2vDC6B8YKicnIMmTGvw0aQFTPic5SQacWQJkXcjeR7Jtws8MWQ1MbkDHef9h1wLBtgQ/640?wx_fmt=png&from=appmsg "")  
  
上传访问即可获得flag  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0LTz7Lex94WW1djaoXnQU2vDC6B8YKicncIjwIrsEwNFF6Lt1zlwTrHORs39Ill07mJscsr2aNnI0Kykfwia6umg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0LTz7Lex94WW1djaoXnQU2vDC6B8YKicnHd4fs1tbmzicGM7P4lVP3ibYzRDVwroOFdDUrU0Rdf1dTnCz5Cg4daiaA/640?wx_fmt=png&from=appmsg "")  
  
