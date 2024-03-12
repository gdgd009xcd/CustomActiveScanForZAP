package org.zaproxy.zap.extension.customactivescan;

public class ReplaceStringSequence extends ManipulateAction<String> {

    private SequenceManipulator<String> sequenceManipulator;
    public ReplaceStringSequence(String sequence, String key, String replaceValue) {
        sequenceManipulator = new SequenceManipulator<String>() {
            final int seqLen = sequence != null ? sequence.length() : 0;
            final StringBuffer seqBuffer = new StringBuffer(sequence);
            final String keyString = key != null ? key : "";
            final StringBuffer outputBuffer = new StringBuffer();

            @Override
            public int length() {
                return seqLen;
            }

            @Override
            public StartEndPosition foundKeyNext(int pos) {
                int startPos;
                if ((startPos = seqBuffer.indexOf(keyString, pos)) != -1){
                    return new StartEndPosition(startPos, startPos + keyString.length());
                }
                return null;
            }

            @Override
            public String getSubSequence(int startPos, int endPos) {
                return seqBuffer.substring(startPos, endPos);
            }

            @Override
            public String manipulate(int startPos, int endPos) {
                return replaceValue;
            }

            @Override
            public void addToResultData(String data) {
                outputBuffer.append(data);
            }

            @Override
            public String getResultData() {
                return outputBuffer.toString();
            }
        };
    }

    public String action(int untilFoundCount) {
        return manipulateActionUntil(sequenceManipulator, untilFoundCount);
    }
}
