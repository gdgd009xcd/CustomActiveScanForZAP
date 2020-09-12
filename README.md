## CustomActiveScanForZAP

A OWASP ZAP AddOn ActiveScan for detecting SQL injections.
Real Web application page has dynamic contents such as special sale products list or CSRF token, which is not affected by input parameters.
The web application vulnerability scanner manipulates input parameters to detect vulnerabilities by affecting page content. 
The scanner may fail to detect vulnerabilities if the dynamic content of the web page has contents which is unaffected by the input parameters. 
Therefore, this CustomActiveScan uses LCS (Longest Common Sequece) algorithm to remove these unnecessarily dynamic content.
Due to this method, this scanner has a superior vulnerability detection capability.

### how to remove these dynamic contents which is not affected input parameters.

LCS(Longest Common Sequence) algorighm extracts the content that is common to two array elements.
For example, you have a web page that contains a CSRF token. The CSRF token has a unique value for each http request.
To erase this token, this addon sends two identical http requests and computes the response LCS of the two requests.
LCS remove the different token values ​​from the two responses as follows:
 
<PRE>
[response1]
&lt;form action="add.php" method="POST"&gt;
&lt;input type="hidden" name="token" value="<font color="red">dbc8ee88f64bf794505ef74e41d6e5a4</font>"&gt;
&lt;input type="submit"  value="Complete"&gt;
&lt;/form&gt;

[response2]
&lt;form action="add.php" method="POST"&gt;
&lt;input type="hidden" name="token" value="bcb138585064356efa927ab196cbf8ec"&gt;
&lt;input type="submit"  value="Complete"&gt;
&lt;/form&gt;

[LCS]
&lt;form action="add.php" method="POST"&gt;
&lt;input type="hidden" name="token" value="&gt;
&lt;input type="submit"  value="Complete"&gt;
&lt;/form&gt;
</PRE>
* Before calculating the LCS, this addon splits the response content by whitespace/JSON/HTML delimiters or characters and stores it in an array.

##  SQL injection test some results.

Test Environment: OWASP Juice Shop <A HREF="https://hub.docker.com/r/bkimminich/juice-shop">Docker Image</A>  
ZAPROXY Version:  2.10.0-SNAPSHOT  
ZAPROXY Mode: Standard mode  

<TABLE>
 <TR><TH>URL</TH><TH>parameter</TH><TH>ascanrules release <BR>ver 36.0.0</TH><TH>ascanrules beta <BR>ver 31.0.0</TH><TH>Advanced SQLInjection Scanner <BR>Ver13 beta</TH><TH>CustomActiveScan <BR>ver0.0.1 alpha</TH></TR>
 <TR><TD>http://localhost:3000/rest/products/search?q=</TD><TD>q</TD><TD>NO</TD><TD>NO</TD><TD>DETECTED</TD><TD>DETECTED</TD></TR>
 <TR><TD>http://localhost:3000/rest/user/login</TD><TD>email</TD><TD>NO</TD><TD>NO</TD><TD>DETECTED</TD><TD>DETECTED</TD></TR>
</TABLE> 

## Download & Building

The add-on is built with [Gradle]: https://gradle.org/  

To download & build this addon, simply run:  

$ git clone https://github.com/gdgd009xcd/CustomActiveScanForZAP.git  
$ cd CustomActiveScanForZAP  
$ ./gradlew build  

The add-on will be placed in the directory `CustomActiveScanForZAP/addOns/customactivescan/build/zapAddOn/bin`

$ cd addOns/customactivescan/build/zapAddOn/bin  
$ ls  
customactivescan-alpha-0.0.2.zap  
$  

* Gradle builds may fail due to network connection timeouts for downloading dependencies. If you have such problems, please retry the gradlew command each time. or you can download addon file from [release page](https://github.com/gdgd009xcd/CustomActiveScanForZAP/releases)

## Install

Start ZAPROXY in your PC's Desktop.  
Install add-on customactivescan-alpha-N.N.N.zap file according to the ZAP add-on installation method (example: File menu "Load add-on file").<BR>
![AddonInstall](https://raw.githubusercontent.com/gdgd009xcd/RELEASES/master/IMG/ZAP/addoninst.png)
