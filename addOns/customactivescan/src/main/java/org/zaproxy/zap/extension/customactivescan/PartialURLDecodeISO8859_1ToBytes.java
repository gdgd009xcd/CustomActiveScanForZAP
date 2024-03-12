package org.zaproxy.zap.extension.customactivescan;

import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PartialURLDecodeISO8859_1ToBytes extends ManipulateAction<byte[]> {
    SequenceManipulator<byte[]> sequenceManipulator;

    /**
     * decode the part of the percent encoding(%XX) within the inputData<BR>
     *     and Convert it to byte array.
     * the charset of URL decoding is ISO8859_1
     * the charset of other part of string is the parameter named charset
     *
     * @param inputData
     * @param charset encoding for converting string to byte array.
     */
    public PartialURLDecodeISO8859_1ToBytes(String inputData, Charset charset) {
        sequenceManipulator = new SequenceManipulator<>() {
            final int totalLen = inputData!=null?inputData.length():0;
            final Pattern pattern = Pattern.compile("%[0-9a-zA-Z][0-9a-zA-Z]");
            final ParmGenBinUtil outputBytes = new ParmGenBinUtil();
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
            public byte[] getSubSequence(int startPos, int endPos) {
                return inputData.substring(startPos, endPos).getBytes(charset);
            }

            @Override
            public byte[] manipulate(int startPos, int endPos) {
                return URLDecoder.decode(
                        inputData.substring(startPos, endPos),
                        StandardCharsets.ISO_8859_1
                ).getBytes(StandardCharsets.ISO_8859_1);
            }

            @Override
            public void addToResultData(byte[] data) {
                outputBytes.concat(data);
            }

            @Override
            public byte[] getResultData() {
                return outputBytes.getBytes();
            }
        };
    }

    byte[] action() {
        return manipulateAction(sequenceManipulator);
    }
}
