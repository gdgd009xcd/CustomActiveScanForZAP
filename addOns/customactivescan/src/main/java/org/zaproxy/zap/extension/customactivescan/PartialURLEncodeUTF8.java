package org.zaproxy.zap.extension.customactivescan;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PartialURLEncodeUTF8 extends ManipulateAction<String> {
    SequenceManipulator<String> sequenceManipulator;

    /**
     * encode the inputData to the URL encoding<BR>
     *     except the part of percent encoding(%XX) in the inputData.<BR>
     *         the charset of encoding is UTF-8.
     * @param inputData
     */
    public PartialURLEncodeUTF8(String inputData) {
        final int Len = inputData!=null?inputData.length():0;
        final Pattern pattern = Pattern.compile("%[0-9a-zA-Z][0-9a-zA-Z]");
        final StringBuffer outputData = new StringBuffer();
        final Matcher matcher = pattern.matcher(inputData);

        sequenceManipulator = new SequenceManipulator<>() {
            @Override
            public int length() {
                return Len;
            }

            @Override
            public StartEndPosition foundKeyNext(int pos) {
                if (matcher.find()) {
                    int startPos = matcher.start();
                    int endPos = matcher.end();
                    return new StartEndPosition(startPos, endPos);
                }
                return null;
            }

            @Override
            public String getSubSequence(int startPos, int endPos) {
                return URLEncoder.encode(inputData.substring(startPos, endPos), StandardCharsets.UTF_8);
            }

            @Override
            public String manipulate(int startPos, int endPos) {
                return inputData.substring(startPos, endPos);
            }

            @Override
            public void addToResultData(String data) {
                outputData.append(data);
            }

            @Override
            public String getResultData() {
                return outputData.toString();
            }
        };
    }


    public String action() {
        return manipulateAction(sequenceManipulator);
    }
}
