package org.zaproxy.zap.extension.customactivescan;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PartialURLDecodeISO8859_1 extends ManipulateAction<String> {
    SequenceManipulator<String> sequenceManipulator;

    /**
     * decode the part of the percent encoding(%XX) within the inputData<BR>
     *     the charset of decoding is ISO8859_1
     * @param inputData
     */
    public PartialURLDecodeISO8859_1(String inputData) {
        sequenceManipulator = new SequenceManipulator<>() {
            final int totalLen = inputData!=null?inputData.length():0;
            final Pattern pattern = Pattern.compile("%[0-9a-zA-Z][0-9a-zA-Z]");
            final StringBuffer outputData = new StringBuffer();
            final Matcher matcher = pattern.matcher(inputData);


            @Override
            public int length() {
                return totalLen;
            }

            @Override
            public StartEndPosition foundKeyNext(int pos) {
                if(matcher.find()) {
                    int startPos = matcher.start();
                    int endPos = matcher.end();
                    return new StartEndPosition(startPos, endPos);
                }
                return null;
            }

            @Override
            public String getSubSequence(int startPos, int endPos) {
                return inputData.substring(startPos, endPos);
            }

            @Override
            public String manipulate(int startPos, int endPos) {
                return URLDecoder.decode(inputData.substring(startPos, endPos), StandardCharsets.ISO_8859_1);
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

    String action() {
        return manipulateAction(sequenceManipulator);
    }
}
