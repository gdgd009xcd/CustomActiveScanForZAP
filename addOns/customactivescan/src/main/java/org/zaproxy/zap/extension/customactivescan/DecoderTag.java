package org.zaproxy.zap.extension.customactivescan;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DecoderTag {
    private static final String SECTION_SIGN = "§";
    private static final String PILCROW_MARK = "¶";

    public static final String DECODE_PREFIX_URL_STRING = SECTION_SIGN + "U" + PILCROW_MARK;
    public static final String DECODE_SUFFIX_URL_STRING = PILCROW_MARK + "U" + SECTION_SIGN;
    public static final String DECODE_PREFIX_BASE64_STRING = SECTION_SIGN + "B" + PILCROW_MARK;
    public static final String DECODE_SUFFIX_BASE64_STRING = PILCROW_MARK + "B" + SECTION_SIGN;
    private static final String DECODEREGEX = "((?:§[BU]¶)+)((?:.|[\\r\\n\\t ])*?)(?<!¶[BU]§)((?:¶[BU]§)+)";
    private static final String DECODE_REMOVE_REGEX = "(§[BU]¶)|(¶[BU]§)";
    private static Pattern pattern = Pattern.compile(DECODEREGEX, Pattern.MULTILINE);

    public static List<StartEndPosition> getDecodeTagList(String value) {
        Matcher m = pattern.matcher(value);
        List<StartEndPosition> results = new ArrayList<>();;
        while (m.find()) {
            int gcount = m.groupCount();
            if (gcount == 3) {
                results.add(getStartEndPositionFromMatcherGroup(m, 1));
                results.add(getStartEndPositionFromMatcherGroup(m, 3));
            }
        }
        return results;
    }

    public static List<StartEndPosition> getDecodedStringList(String value) {
        Matcher m = pattern.matcher(value);
        List<StartEndPosition> results = new ArrayList<>();;
        while (m.find()) {
            int gcount = m.groupCount();
            if (gcount == 3) {
                results.add(getStartEndPositionFromMatcherGroup(m, 2));
            }
        }
        return results;
    }

    /**
     * whether is value consist of valid CustomEncoded value
     * @param value
     * @return true - value is valid CustomEncoded value | false - not valid value
     */
    public static boolean isDecodedTaggedString(String value) {
        Matcher m = pattern.matcher(value);
        boolean totalResult = false;
        while (m.find()) {
            int gcount = m.groupCount();
            if (gcount != 3) {
                return false;
            } else {
                String prefixTag = m.group(1);
                String content = m.group(2);
                String suffixTag = m.group(3);
                if (prefixTag.length() != suffixTag.length()) {
                    return false;
                } else if (prefixTag.length() % 3 != 0) {
                    return false;
                } else {
                    int maxTagLabelIndex = prefixTag.length() - 2;
                    for (int i = 1, j = maxTagLabelIndex; i <= maxTagLabelIndex; i += 3, j -= 3) {
                        if (!prefixTag.substring(i, i + 1).equals(suffixTag.substring(j, j + 1))) {
                            return false;
                        }
                    }
                    totalResult = true;
                }
            }
        }
        return totalResult;
    }

    public static String getOriginalEncodedString(String value, Encode enc) {
        Matcher m = pattern.matcher(value);
        StringBuffer resultEncodedString =  new StringBuffer();
        int start = 0;
        Deque<String> stacker = new ArrayDeque<>();
        while (m.find()) {
            int gcount = m.groupCount();
            boolean failed = false;
            String content = "";
            stacker.clear();
            if (gcount == 3) {
                String prefixTag = m.group(1);
                content = m.group(2);
                String suffixTag = m.group(3);
                if (prefixTag.length() != suffixTag.length()) {
                    failed = true;
                } else if (prefixTag.length() % 3 != 0) {
                    failed = true;
                } else {

                    int maxTagLabelIndex = prefixTag.length() - 2;

                    for (int i = 1, j = maxTagLabelIndex; i <= maxTagLabelIndex; i += 3, j -= 3) {
                        if (!prefixTag.substring(i, i + 1).equals(suffixTag.substring(j, j + 1))) {
                            failed = true;
                            break;
                        } else {
                            stacker.push(prefixTag.substring(i, i + 1));
                        }
                    }
                }
            } else {
                failed = true;
            }
            if (failed) {
                resultEncodedString.append(value.substring(start, m.end()));
            } else {
                resultEncodedString.append(value.substring(start, m.start()));
                String encodeCommand;
                while((encodeCommand = stacker.pollFirst())!= null) {
                    switch(encodeCommand) {
                        case "U":
                            content = Utilities.encodeURL(content, enc);
                            break;
                        case "B":
                            content = Utilities.encodeBase64(content, enc);
                            break;
                    }
                }
                resultEncodedString.append(content);
            }
            start = m.end();
        }
        if (start < value.length()) {
            resultEncodedString.append(value.substring(start, value.length()));
        }
        return resultEncodedString.toString();
    }

    public static StartEndPosition getStartEndPositionFromMatcherGroup(Matcher m, int i) {
        int gStart = m.start(i);
        int gEnd = m.end(i);
        String groupString = m.group(i);
        return new StartEndPosition(gStart, gEnd, groupString);
    }

    public static String removeDecodeTag(String value) {
        if (value != null) {
            return value.replaceAll(DECODE_REMOVE_REGEX, "");
        }
        return null;
    }
}
