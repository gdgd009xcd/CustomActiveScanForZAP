## CustomActiveScanForZAP

A OWASP AddOn ActiveScan for detecting SQL injections.
Real Web application page has dynamic contents such as special sale products list or CSRF token, which is not affected by input parameters.
Web application vulnerability scanner detects problems by input parameter affected page contents. 
The scanner may fail to detect vulnerabilities if the dynamic content of the web page is configured to be unaffected by the input parameters.
Therefore, this CustomActiveScan uses LCS (Longest Common Sequece) algorithm to erase these unnecessarily dynamic content.

### how to erase these dynamic contents which is not affected input parameters.

LCS(Longest Common Sequence) algorighm extracts the content that is common to two array elements.
For example, you have a web page that contains a CSRF token. The CSRF token has a unique value for each http request.
To erase this token, this addon sends two identical http requests and computes the response LCS of the two requests.
LCS clears the different token values ​​from the two responses as follows:
 
<PRE>
[response1]
...
&lt;input type="hidden" name="token" value="dbc8ee88f64bf794505ef74e41d6e5a4"&gt;
...
[response2]
...
&lt;input type="hidden" name="token" value="dbc8ee88f64bf794505ef74e41d6e5a4"&gt;
...
[LCS]
...
&lt;input type="hidden" name="token"
... 
</PRE>



## Building

The add-ons are built with [Gradle], each add-on has its own project which is located under the `addOns` project/directory.

To build all add-ons, simply run:

    ./gradlew build

in the main directory of the project, the add-ons will be placed in the directory `build/zapAddOn/bin/` of each project.

To build an add-on individually run:

    ./gradlew :addOns:<name>:build

replacing `<name>` with the name of the add-on (e.g. `reveal`).

[Gradle]: https://gradle.org/
