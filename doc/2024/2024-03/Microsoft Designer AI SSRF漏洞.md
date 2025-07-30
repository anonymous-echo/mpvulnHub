#  Microsoft Designer AI SSRF漏洞   
安全路人A  军机故阁   2024-03-09 15:01  
  
近期   
5h3rl0ck 老哥发现并成功利用了 Microsoft 的一款 AI 产品的  
SSRF（服务器端请求伪造）漏洞，产品为Microsoft Designer。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ESFRPeynAv4LY0OybtK56qNwefkfkn3nHIuPpzNeIjQZQ0zQ9n1wYicDgQNkkzwibfxgN2dcLojVr4A9zsib7gjoA/640?wx_fmt=png&from=appmsg "")  
  
Microsoft Designer 是一款基于 AI 的图形设计应用，可帮助快速创建的社交媒体帖子、邀请函、数字明信片、图形等。  
  
当尝试在应用程序上找到一些 IDOR 时，遇到了一个节点，这节点是用一些参数（包括名为 nextlink 的参数）并从中检索图像，然后它从中生成缩略图并将其托管在 Onedrive 上，看到这触发了 spidey SSRF 的意义并触发 burp 回显，但报了 500 响应错误，其中有一个显示解析错误的小标头，如下所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ESFRPeynAv4LY0OybtK56qNwefkfkn3nbNxZXia1jTrKMqPDxw3oDn6pFzWZdvbD1AaSSqql9906HahZvcTvs2Q/640?wx_fmt=png&from=appmsg "")  
  
  
在多次尝试重现URL SSRF 失败之后，就转向检查下一个 URL 的原始值的输出。它似乎是一个代表驱动对象的 JSON 对象，该 JSON 类似于以下结构：  
```
{
    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users('elhabtiesoufiane%40gmail.com')/drive/special('approot')/children",
    "@odata.count": 33,
    "@odata.nextLink": "https://graph.microsoft.com/v1.0/me/drive/special/approot:/My%20stuff:/children?expand=thumbnails(select%3dmedium)&top=9&orderby=lastModifiedDateTime+desc&select=id%2cname%2ccreatedDateTime%2clastModifiedDateTime%2cthumbnails%2cfile%2cimage%2c%40microsoft.graph.downloadUrl&$skiptoken=Mjg",
    "value": [{
        "@microsoft.graph.downloadUrl": "https://public.am.files.1drv.com/y4mKouM8V3c8qPmNuxA6Xuar9ZLAjp5mc_nmElgmPbykqyEx6fA2fIOqOt9JmGK9T7wrPrpGIFl6thL91UYUXJeYAjkoJ29DLcrxIJtjk3XjCK8XSi2rkNL_MN9gSl8jgukYpYIR7H2tPIbSWswzXmxbxgo6dOg3q5FfTbPFAMvlvzNuUzfyIp8aVBL0e4PkG5Z7NXkOJ3S0_3wzzvo2UBH90XlTf5n97OBLcTNLz5fTjo",
        "id": null,
        "name": "check 9.jpg",
        "createdDateTime": "2023-08-29T17:44:24.92Z",
        "lastModifiedDateTime": "2023-08-29T18:07:58.943Z",
        "file": {
            "mimeType": "image/jpeg",
            "hashes": {
                "quickXorHash": "htg9DiY+4UVg4Utg7VVVLudD968=",
                "sha1Hash": "77C14952BFA9BBC809B6267C88385B6C428EFABA",
                "sha256Hash": "7225D72CBB652B45E5883BEB794BC5BB3F7B024CF5E6BAED24F243EEAB988918"
            }
        },
        "image": {
            "height": 800,
            "width": 800
        },
        "thumbnails@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users('elhabtiesoufiane%40gmail.com')/drive/special('approot')/children('FE1AD29AF25F99C0%2119434')/thumbnails",
        "thumbnails": [{
            "medium": {
                "height": 176,
                "url": "SOME ONEDRIVE URL"

            }
        }]
    }
]
}
```  
  
  
通过一些调试，我们了解到后端会解析thumbnails.medium.url的值，我所做的就是在我自己的服务器上托管一个类似的json对象，让目标后端向它发送请求，因此我们构建了漏洞语句并发送请求，但没报错误，只有一个空响应，如下所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ESFRPeynAv4LY0OybtK56qNwefkfkn3nReEWobRYVlSCLLtFtYiabhmKsfs7XiapdG3MhVnwQE9eQg3R1Ciap76Ew/640?wx_fmt=png&from=appmsg "")  
  
但好的一面是，我在 burp 接到了来自 microsoft IP 的回显：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ESFRPeynAv4LY0OybtK56qNwefkfkn3nKkV2EtetZ798Sqs1WECv45nAibC2kGM2QxVSk9DluYAEjia2TfL6BUqg/640?wx_fmt=png&from=appmsg "")  
  
这位置似乎只能使用检索图片的缩略图的点才行，直到我注意到一个名为 Responsetype 的请求标头，它最初设置为 json，因此我们尝试将其设置为 html，就得到了 burp 完整响应:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ESFRPeynAv4LY0OybtK56qNwefkfkn3nUNnGC0L0mrgjNPVmMicLL7icwNyBtTTzjfA1ePkZydiagsD122oyY0VCg/640?wx_fmt=png&from=appmsg "")  
  
最后我们测试这个ssrf demo，通过内部 IP 访问了   
Microsoft Desi  
gner的本地图像内容，并且还从元数据 url 请求服务器实例信息：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ESFRPeynAv4LY0OybtK56qNwefkfkn3nk3MkvZtibibsN5NH7cHhZ3GjXJCecLtROUMR7icC8ial3Cn4N5OwHRjGzQ/640?wx_fmt=png&from=appmsg "")  
  
  
