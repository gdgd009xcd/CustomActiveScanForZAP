## CustomActiveScanForZAP

[***Questionnaire](https://docs.google.com/forms/d/e/1FAIpQLScwRM5w5wXzkgEbOlItzKPCu3ZJjxTac7dGo2lOtEWLCsPlhw/viewform?hl=en): Please answer the questionnaire if you like.

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
<table>
 <TR><TH ROWSPAN="2">SQL injection Detection rate<BR>(Detected/Total)</TH><TH>CustomActiveScan<BR>ForZAP <BR>0.5.1</TH><TH>Active Scanner Rules(alpha)<BR>32.0.0</TH><TH>Active Scanner Rules(beta)<BR>37.0.0</TH><TH>Active Scanner Rules<BR>41.0.0</TH><TH>Advanced SQLInjection Scanner<BR>15.0.0</TH></TR>
 <TR><TH>100%<BR>(12/12)</TH><TH>0%<BR>(0/12)</TH><TH>0%<BR>(0/12)</TH><TH>17%<BR>(2/12)</TH><TH>50%<BR>(6/12)</TH></TR>
 </table>
  
[See Details](https://github.com/gdgd009xcd/CustomActiveScanForZAP/wiki/99.1.-SQL-injection-detection-test-results-with-ActiveScan)


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

1）Start ZAPROXY in your PC's Desktop.  
2）Install add-on customactivescan-alpha-N.N.N.zap file according to the ZAP add-on installation method (example: File menu "Load add-on file").<BR>
![AddonInstall](https://raw.githubusercontent.com/gdgd009xcd/RELEASES/master/IMG/ZAP/addoninst.png)<BR>    
3）restart zap(sorry, currently this addon does not work unless restart zap after install it.)
