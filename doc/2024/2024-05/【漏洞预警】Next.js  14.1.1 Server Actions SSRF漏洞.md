#  【漏洞预警】Next.js < 14.1.1 Server Actions SSRF漏洞   
cexlife  飓风网络安全   2024-05-11 20:15  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu03Fo6cqzsptEVqhBQkZdq5vib39Gic7cD3OiahNcVYOmibL2SaArRsrApeZVSicJz90myuyRWdcCzUCpmg/640?wx_fmt=png&from=appmsg "")  
  
**漏洞描述:**  
  
Next.js是Node.js生态中基于React的开源Web框架,其通过Server Actions功能提供了后端开发能力,在受影响版本中,当使用Server Actions服务端试图执行基于相对路径的重定向时,如果 Host 头被篡改,会错误地将重定向的基地址设置为攻击者指定的地址进行请求,可能导致内网信息泄露,修复版本中,通过环境变量__NEXT_PRIVATE_HOST来确定服务器的内部主机名和端口号,不再依赖于请求中的Host头,修复该漏洞。**影响范围:**next[13.4.0, 14.1.1)**修复方案:**将组件next升级至14.1.1及以上版本**参考链接:**https://www.assetnote.io/resources/research/digging-for-ssrf-in-nextjs-apps  
  
