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

## OWASP Juice Shop: SQL injection test some results.

Version: ZAPROXY 2.10.0-SNAPSHOT  
Mode: Standard mode  

<TABLE>
 <TR><TH>URL</TH><TH>parameter</TH><TH>ascanrules release <BR>ver 36.0.0</TH><TH>ascanrules beta <BR>ver 31.0.0</TH><TH>Advanced SQLInjection Scanner <BR>Ver13 beta</TH><TH>CustomActiveScan <BR>ver0.0.1 alpha</TH></TR>
 <TR><TD>http://localhost:3000/rest/products/search?q=</TD><TD>q</TD><TD>NO</TD><TD>NO</TD><TD>DETECTED</TD><TD>DETECTED</TD></TR>
 <TR><TD>http://localhost:3000/rest/user/login</TD><TD>email</TD><TD>NO</TD><TD>NO</TD><TD>DETECTED</TD><TD>DETECTED</TD></TR>
</TABLE> 

## Building

The add-ons are built with [Gradle], each add-on has its own project which is located under the `addOns` project/directory.

To build all add-ons, simply run:

    ./gradlew build

in the main directory of the project, the add-ons will be placed in the directory `build/zapAddOn/bin/` of each project.

To build an add-on individually run:

    ./gradlew :addOns:<name>:build

replacing `<name>` with the name of the add-on (e.g. `reveal`).

[Gradle]: https://gradle.org/
