> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg2NTk4MTE1MQ==&mid=2247487497&idx=1&sn=56addf0384cd792e5f5a6fa3c00ec142

#  Langflow应用程序存在远程代码执行 (RCE)  
 TtTeam   2025-06-21 02:14  
  
mitsec - CVE-2025-3248 Langflow RCE 漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0HlywncJbB1BWA2iaJfo4q3h3ib35ndnzFwpVejlyiaf7iaYRZuzEKCl9vzHPEXaDoSO5B2TtC6xdNJffHOjWricickA/640?wx_fmt=png&from=appmsg "")  
- 远程和未经身份验证的 RCE  
- 无需身份验证  
- Python3 单行脚本  
- 彩色终端输出  

```
python3 mitsec.py -u http://target:7860 -c &#34;id&#34;
```

  
- **CVE编号**：CVE-2025-3248  
- **类型**：远程代码执行（RCE）  
- **组件**：Langflow 后端  
- **条件**
```
exec()
```

：用户控制的代码路径中动态的滥用  
