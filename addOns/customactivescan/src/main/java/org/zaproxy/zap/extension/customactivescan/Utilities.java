package org.zaproxy.zap.extension.customactivescan;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.core.scanner.PluginFactory;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.extension.pscan.ExtensionPassiveScan;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Utilities {
    enum CharMODE {
        NUMBER,
        ALPHALOWER,
        ALPHAUPPER,
        OTHER,
        SPACE,
        PLUS,
        SLASH,
        EQUAL,
        HYPHEN,
        UNDERBAR,
        QUESTION,
        AMBERSAND,
        DOT,
        SEMICOLON,
        PERCENT,
        DEFAULT
    };

    enum TokenType {
        BASE64,
        BASE64URL,
        BASE64WITHSYMBOL,
        BASE64URLWITHSYMBOL,
        URLENCODE,
        LENGTHGT16,
        HASSLASH,
        HASDOT3,
        HASQUESTION,
        HASAMBERSAND,
        HASEQUAL,
        HASSEMICOLON,
        UNKNOWNTOKEN,
        DONE,
    };

    static private String queryMarkRegex = "[\\?;]";
    static private Pattern queryMarkPattern;
    static private String pathDivRegex = "[\\\\/]+";
    static private Pattern pathDivPattern;
    static private String queryParamRegex = "([^&=]+)=([^&=]+)";
    static private Pattern queryParamPattern;
    static private String alphaNumRegex = "[a-zA-Z0-9]+";
    static private Pattern alphaNumPattern;

    static {
        pathDivPattern = Pattern.compile(pathDivRegex);
        queryParamPattern = Pattern.compile(queryParamRegex);
        queryMarkPattern = Pattern.compile(queryMarkRegex);
        alphaNumPattern = Pattern.compile(alphaNumRegex);
    }

    /**
     * parse and analyze token
     * @param tkn
     * @return
     */
    private static List<TokenType> parseTokenValue(String tkn) {
        List<TokenType> results = new ArrayList<>();
        boolean isUrlEncodedChar = false;
        boolean onlyUrlEncodedCharacters = true;
        boolean onlyBase64Characters = true;
        boolean onlyBase64UrlCharacters = true;
        boolean hasPlusSymbol = false;
        boolean hasEqualSymbol = false;
        boolean hasSlashSymbol = false;
        boolean hasHyphenSymbol = false;
        boolean hasUnderBarSymbol = false;
        boolean hasQuestionSymbol = false;
        boolean hasSemicolonSymbol = false;
        boolean hasAmbersandSymbol = false;
        int charCount = 0;
        int urlEncode3Modulus = 0;
        int base64PaddingCount = 0;
        int dot3Count = 0;
        char[] base64Multi4 = new char[4];
        int base64Multi4Count = 0;
        if (tkn == null || tkn.isEmpty()) return null;

        if (tkn.length() >= 16) {
            results.add(TokenType.LENGTHGT16);
        }

        CharMODE current = CharMODE.DEFAULT;
        int ncnt = 0;
        int lowercnt = 0;
        int uppercnt = 0;
        char[] charArray = tkn.toCharArray();
        for (char ch : charArray) {
            urlEncode3Modulus = charCount++ % 3;
            isUrlEncodedChar = false;
            switch (ch) {
                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                case '8':
                case '9': // 数値
                    switch (current) {
                        case NUMBER:
                            break;
                        case EQUAL:
                            onlyBase64Characters = false;
                            ncnt++;
                            break;
                        default:
                            ncnt++;
                            break;
                    }
                    if (urlEncode3Modulus != 0) {
                        isUrlEncodedChar = true;
                    }
                    current = CharMODE.NUMBER;
                    break;
                case 'a':
                case 'b':
                case 'c':
                case 'd':
                case 'e':
                case 'f':
                    if (urlEncode3Modulus != 0) {
                        isUrlEncodedChar = true;
                    }
                    switch (current) {
                        case ALPHALOWER:
                            break;
                        case EQUAL:
                            onlyBase64Characters = false;
                            lowercnt++;
                            break;
                        default:
                            lowercnt++;
                            break;
                    }
                    current = CharMODE.ALPHALOWER;
                    break;
                case 'g':
                case 'h':
                case 'i':
                case 'j':
                case 'k':
                case 'l':
                case 'm':
                case 'n':
                case 'o':
                case 'p':
                case 'q':
                case 'r':
                case 's':
                case 't':
                case 'u':
                case 'v':
                case 'w':
                case 'x':
                case 'y':
                case 'z':
                    switch (current) {
                        case ALPHALOWER:
                            break;
                        case EQUAL:
                            onlyBase64Characters = false;
                            lowercnt++;
                            break;
                        default:
                            lowercnt++;
                            break;
                    }
                    current = CharMODE.ALPHALOWER;
                    break;
                case 'A':
                case 'B':
                case 'C':
                case 'D':
                case 'E':
                case 'F':
                    if (urlEncode3Modulus != 0) {
                        isUrlEncodedChar = true;
                    }
                    switch (current) {
                        case ALPHAUPPER:
                            break;
                        case EQUAL:
                            onlyBase64Characters = false;
                            uppercnt++;
                            break;
                        default:
                            uppercnt++;
                            break;
                    }
                    current = CharMODE.ALPHAUPPER;
                    break;
                case 'G':
                case 'H':
                case 'I':
                case 'J':
                case 'K':
                case 'L':
                case 'M':
                case 'N':
                case 'O':
                case 'P':
                case 'Q':
                case 'R':
                case 'S':
                case 'T':
                case 'U':
                case 'V':
                case 'W':
                case 'X':
                case 'Y':
                case 'Z':
                    switch (current) {
                        case ALPHAUPPER:
                            break;
                        case EQUAL:
                            onlyBase64Characters = false;
                            uppercnt++;
                            break;
                        default:
                            uppercnt++;
                            break;
                    }
                    current = CharMODE.ALPHAUPPER;
                    break;
                case ' ':
                case '\t':
                case '\r':
                case '\n':
                    current = CharMODE.SPACE;
                    break;
                case '+':
                    hasPlusSymbol = true;
                    if (current == CharMODE.EQUAL) {
                        onlyBase64Characters = false;
                    }
                    current = CharMODE.PLUS;
                    break;
                case '/':
                    hasSlashSymbol = true;
                    if (current == CharMODE.EQUAL) {
                        onlyBase64Characters = false;
                    }
                    current = CharMODE.SLASH;
                    break;
                case '=':
                    hasEqualSymbol = true;
                    current = CharMODE.EQUAL;
                    base64PaddingCount++;
                    break;
                case '-':
                    hasHyphenSymbol = true;
                    current = CharMODE.HYPHEN;
                    break;
                case '_':
                    hasUnderBarSymbol = true;
                    current = CharMODE.UNDERBAR;
                    break;
                case '?':
                    hasQuestionSymbol = true;
                    current = CharMODE.QUESTION;
                    break;
                case '&':
                    hasAmbersandSymbol = true;
                    current = CharMODE.AMBERSAND;
                    break;
                case '.':
                    dot3Count++;
                    current = CharMODE.DOT;
                    break;
                case ';':
                    hasSemicolonSymbol = true;
                    current = CharMODE.SEMICOLON;
                    break;
                case '%':
                    if (urlEncode3Modulus == 0) {
                        isUrlEncodedChar = true;
                    }
                    current = CharMODE.PERCENT;
                    break;
                default:
                    current = CharMODE.OTHER;
                    break;
            }
            if (!isUrlEncodedChar) {
                onlyUrlEncodedCharacters = false;
            }
            switch(current) {
                case NUMBER:
                case ALPHALOWER:
                case ALPHAUPPER:
                case PLUS:
                case SLASH:
                case EQUAL:
                case HYPHEN:
                case UNDERBAR:
                    if (current == CharMODE.PLUS ||
                    current == CharMODE.EQUAL ||
                    current == CharMODE.SLASH) {
                        onlyBase64UrlCharacters = false;
                    }
                    if (current == CharMODE.HYPHEN ||
                    current == CharMODE.UNDERBAR) {
                        onlyBase64Characters = false;
                    }
                    if (base64Multi4Count > 3) {
                        base64Multi4Count = 0;
                    }
                    base64Multi4[base64Multi4Count++] = ch;
                    break;
                case SPACE:
                    return null;
                default:
                    base64Multi4Count = 0;
                    onlyBase64Characters = false;
                    onlyBase64UrlCharacters = false;
                    base64PaddingCount = 0;
                    break;
            }
        }
        // jWT: contains 3 dots?
        if (dot3Count == 3) {
            results.add(TokenType.HASDOT3);
        }

        if (hasSlashSymbol) {
            results.add(TokenType.HASSLASH);
        }

        if (hasQuestionSymbol) {
            results.add(TokenType.HASQUESTION);
        }

        if (hasAmbersandSymbol) {
            results.add(TokenType.HASAMBERSAND);
        }

        if (hasSemicolonSymbol) {
            results.add(TokenType.HASSEMICOLON);
        }

        if (hasEqualSymbol) {
            results.add(TokenType.HASEQUAL);
        }

        if (onlyUrlEncodedCharacters) {
            results.add(TokenType.URLENCODE);
        }

        // is Base64?
        if (base64Multi4Count == 4 && onlyBase64Characters && base64PaddingCount < 4) {
            int base64CharLen = tkn.length() - base64PaddingCount;
            int bitPadding = (base64CharLen * 6) % 8;
            if (bitPadding < 6) {
                results.add(TokenType.BASE64);
                if (hasPlusSymbol || hasSlashSymbol || hasEqualSymbol) {
                    results.add(TokenType.BASE64WITHSYMBOL);
                }
            }
        }
        // is Base64url ?
        if (onlyBase64UrlCharacters) {
            int base64CharLen = tkn.length();
            int bitPadding = (base64CharLen * 6) % 8;
            if (bitPadding < 6) {
                results.add(TokenType.BASE64URL);
                if (hasHyphenSymbol || hasUnderBarSymbol) {
                    results.add(TokenType.BASE64URLWITHSYMBOL);
                }
            }
        }
        // System.out.println("number/lower/upper=" + ncnt + "/" +lowercnt + "/" + uppercnt);
        if (ncnt >= 4 || (lowercnt >= 4 && uppercnt >= 4) && tkn.length() >= 16) {
            results.add(TokenType.UNKNOWNTOKEN);
        }
        return results;
    }

    /**
     * get Asterisk Masked value
     *
     * @param value
     * @return
     */
    private static String getAsteriskMaskedValue(String value) {
        String maskedValue = "";
        int valueLength = value != null ? value.length() : 0;
        for(int i = 0; i < valueLength; i++) {
            maskedValue += "*";
        }
        return maskedValue;
    }

    /**
     * converts token parts of value to asterisks
     *
     * @param value
     * @return
     */
    public static String convTokenPart2Asterisk(String value) {
        String result = "";

        // convert character references to "&"
        value = replaceCharRef2Amb(value);
        List<TokenType> results = parseTokenValue(value);

        if (results != null) {
            result = convIfValueHasToken2Asterisk(results, value);

            if (!results.contains(TokenType.DONE)) {
                // has query mark "?" or ";"
                if ((results.contains(TokenType.HASQUESTION)
                        || results.contains(TokenType.HASSEMICOLON))
                        && results.contains(TokenType.HASEQUAL)) {
                    Matcher queryMarkMatcher = queryMarkPattern.matcher(value);
                    if (queryMarkMatcher.find()) {
                        int qmarkend = queryMarkMatcher.end();
                        result = value.substring(0, qmarkend);
                        String queryparts = value.substring(qmarkend);
                        Matcher queryMatcher = queryParamPattern.matcher(queryparts);
                        int lastpos = 0;
                        while (queryMatcher.find()) {
                            int vstart = queryMatcher.start(2);
                            int vend = queryMatcher.end(2);
                            result += queryparts.substring(lastpos, vstart);
                            result += convIfValueHasToken2Asterisk(null,
                                    queryparts.substring(vstart, vend));
                            lastpos = vend;
                        }
                        int querypartlen = queryparts.length();
                        if (lastpos < querypartlen) {
                            result += queryparts.substring(lastpos);
                        }
                        results.add(TokenType.DONE);
                        return result;
                    }
                }
                // UNKOWNTOKEN and !HASSLASH(isn't path)
                if (results.contains(TokenType.UNKNOWNTOKEN) && !results.contains(TokenType.HASSLASH)) {
                    // System.out.println("UNKNOWNTOKEN![" + value + "]");
                    return getAsteriskMaskedValue(value);
                }
            }
        } else {
            result = value;
        }

        return result;
    }

    /**
     * determine value is something token such as base64/JWT/URlencode and if value has such types then convert it with asterisk.
     *
     * @param value
     * @return
     */
    private static String convIfValueHasToken2Asterisk(List<TokenType> results, String value) {
        String result = "";

        boolean unknownTokenConvert = false;
        if (results==null) {
            unknownTokenConvert = true;
            results = parseTokenValue(value);
        }

        if (results == null) return value;
        boolean hasSlash = false;
        if (results.contains(TokenType.HASSLASH)) {
            hasSlash = true;
        }

        // is URLencoded?
        if (results.contains(TokenType.URLENCODE)) {
            // System.out.println("URLENCODED!");
            results.add(TokenType.DONE);
            return getAsteriskMaskedValue(value);
        }
        // is JWT(JSON Web Token) ?
        if (!hasSlash && results.contains(TokenType.HASDOT3)) {
            String[] part = value.split(".");
            if (part != null && part.length == 3) {
                boolean isJWT = true;
                for (String v: part) {
                    List<TokenType> partResults = parseTokenValue(v);
                    if (partResults != null) {
                        if (!partResults.contains(TokenType.BASE64URL)) {
                            isJWT = false;
                            break;
                        }
                    } else {
                        isJWT = false;
                        break;
                    }
                }
                if (isJWT) {
                    // System.out.println("JWT!");
                    results.add(TokenType.DONE);
                    return getAsteriskMaskedValue(value);
                }
            }
        }

        // is Maybe BASE64 encoding
        if ((results.contains(TokenType.BASE64) && results.contains(TokenType.UNKNOWNTOKEN))
                || (results.contains(TokenType.BASE64WITHSYMBOL) && results.contains(TokenType.LENGTHGT16))) {
            // System.out.println("BASE64!");
            results.add(TokenType.DONE);
            return getAsteriskMaskedValue(value);
        }

        // is Maybe BASE64URL encoding
        if ((results.contains(TokenType.BASE64URL) && results.contains(TokenType.UNKNOWNTOKEN))
                || (results.contains(TokenType.BASE64URLWITHSYMBOL) && results.contains(TokenType.LENGTHGT16))) {
            // System.out.println("BASE64URL!");
            results.add(TokenType.DONE);
            return getAsteriskMaskedValue(value);
        }

        if (unknownTokenConvert) {
            if(results.contains(TokenType.UNKNOWNTOKEN) && !results.contains(TokenType.HASSLASH)) {
                // System.out.println("UNKNOWNTOKEN![" + value + "]");
                return getAsteriskMaskedValue(value);
            }
        }
        return value;
    }

    /**
     * replace character references of value with "&"
     *
     * @param value
     */
    private static String replaceCharRef2Amb(String value) {
        value = value.replaceAll("&([a-z]+|#[0-9]+|#x[0-9a-fA-F]+);", "&");
        return value;
    }

    public static String replaceCtrlCodesToStringRep(String value) {
        return value.replaceAll("\n", "<LF>").replaceAll("\r", "<CR>");
    }

    /**
     * escape regex special characters below:
     *  ., +, *, ?, ^, $, (, ), [, ], {, }, |, \
     * @param originalRegex
     * @return
     */
    public static String escapeRegexChars(String originalRegex) {
        return originalRegex.replaceAll("([\\\\|+{}\\[\\]()*.<>?^$])", "\\\\$1");
    }

    public static boolean hasAlphaNumberChars(String data) {
        if (data == null) return false;
        Matcher m = alphaNumPattern.matcher(data);
        if (m.find()) {
            return true;
        }
        return false;
    }
    public static String getInputVectorName(Alert alert) {
        String inputVector = alert.getInputVector();
        if (inputVector.isEmpty()) {
            return "";
        }
        String key = "variant.shortname." + inputVector;
        if (Constant.messages.containsKey(key)) {
            return Constant.messages.getString(key);
        }
        return inputVector;
    }

    public static String getSourceData(Alert alert) {
        String source = Constant.messages.getString(alert.getSource().getI18nKey());
        if (alert.getPluginId() == -1) {
            return source;
        }

        StringBuilder strBuilder = new StringBuilder(source);
        strBuilder.append(" (").append(alert.getPluginId());
        if (alert.getSource() == Alert.Source.ACTIVE) {
            Plugin plugin = PluginFactory.getLoadedPlugin(alert.getPluginId());
            if (plugin != null) {
                strBuilder.append(" - ").append(plugin.getName());
            }
        } else if (alert.getSource() == Alert.Source.PASSIVE) {
            ExtensionPassiveScan ext =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionPassiveScan.class);
            if (ext != null) {
                PluginPassiveScanner scanner = ext.getPluginPassiveScanner(alert.getPluginId());
                if (scanner != null) {
                    strBuilder.append(" - ").append(scanner.getName());
                }
            }
        }
        strBuilder.append(')');
        return strBuilder.toString();
    }

    public static String normlizedId(int id) {
        return id != -1 ? Integer.toString(id) : "";
    }

    public static String PartialURLDecodeISO8859_1(String value) {
        String regex = "%[0-9a-fA-F][0-9a-fA-F]";
        Pattern pattern = Pattern.compile(regex);
        StringBuffer buffer = new StringBuffer(value);
        StringBuffer output = new StringBuffer();
        int valueLen = buffer.length();
        int startIndex = 0;
        int endIndex = -1;

        for(endIndex = 3; endIndex <= valueLen; endIndex += 3) {
            String digit3String = buffer.substring(startIndex, endIndex);
            Matcher matcher = pattern.matcher(digit3String);
            if (matcher.find()) {
                try {
                    String decodedValue = URLDecoder.decode(digit3String, StandardCharsets.ISO_8859_1);
                    output.append(decodedValue);
                } catch (Exception ex) {
                    output.append(digit3String);
                }
            } else {
                output.append(digit3String);
            }
            startIndex = endIndex;
        }
        if(startIndex < valueLen) {
            output.append(buffer.substring(startIndex, valueLen));
        }
        return output.toString();
    }

    public static String partialURLencodeUTF8(String value) {
        String regex = "%[0-9a-fA-F][0-9a-fA-F]";
        Pattern pattern = Pattern.compile(regex);
        StringBuffer buffer = new StringBuffer(value);
        StringBuffer output = new StringBuffer();
        int valueLen = buffer.length();
        int startIndex = 0;
        int endIndex = -1;

        for(endIndex = 3; endIndex <= valueLen; endIndex += 3) {
            String digit3String = buffer.substring(startIndex, endIndex);
            Matcher matcher = pattern.matcher(digit3String);
            if (matcher.find()) {
                output.append(digit3String);
            } else {
                String encodedValue = URLEncoder.encode(digit3String, StandardCharsets.UTF_8);
                output.append(encodedValue);
            }
            startIndex = endIndex;
        }
        if(startIndex < valueLen) {
            String encodedValue = URLEncoder.encode(buffer.substring(startIndex, valueLen), StandardCharsets.UTF_8);
            output.append(encodedValue);
        }
        return output.toString();
    }

    public static String encodeURL(String value, Encode enc) {
        return URLEncoder.encode(value, enc.getIANACharset());
    }

    public static String encodeBase64(String value, Encode enc) {
        return new String(Base64.getEncoder().encode(value.getBytes(enc.getIANACharset())));
    }

    /**
     * get whole request string from HttpMessage
     * @param httpMessage
     * @return request string
     */
    public static String getWholeMessageString(HttpMessage httpMessage) {
        HttpRequestHeader requestHeader = httpMessage.getRequestHeader();
        String CRLF = HttpHeader.CRLF;
        String primeHeaderWithOutCrLf = requestHeader.getPrimeHeader();
        String requestHeaderStrings = requestHeader.getHeadersAsString();
        String headerPartString = primeHeaderWithOutCrLf + CRLF + requestHeaderStrings + CRLF;
        String originalMessageString = headerPartString + httpMessage.getRequestBody().toString();
        return originalMessageString;
    }

    // since java version 19, getId will be deprecated. use threadId instead.
    @SuppressWarnings("deprecation")
    public static long getThreadId(Thread th) {
        if (th != null) {
            return th.getId();
        }
        return 0;
    }
}
