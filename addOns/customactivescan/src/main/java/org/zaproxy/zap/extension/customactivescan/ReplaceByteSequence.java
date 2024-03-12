package org.zaproxy.zap.extension.customactivescan;

public class ReplaceByteSequence extends ManipulateAction<byte[]> {
    SequenceManipulator<byte[]> sequenceManipulator;

    /**
     * Replaces each occurrence of the keyBytes in the seqBytes with the replaceBytes.
     * @param seqBytes
     * @param keyBytes
     * @param replaceBytes
     */
    public ReplaceByteSequence(byte[] seqBytes, byte[] keyBytes, byte[] replaceBytes) {
        sequenceManipulator=new SequenceManipulator<byte[]>() {
            final int seqLen = seqBytes != null ? seqBytes.length : 0;
            final int keyLen = keyBytes != null ? keyBytes.length : 0;
            final ParmGenBinUtil seqBin = new ParmGenBinUtil(seqBytes);
            final ParmGenBinUtil outputBin = new ParmGenBinUtil();

            @Override
            public int length() {
                return seqLen;
            }

            @Override
            public StartEndPosition foundKeyNext(int pos) {
                int startPos = seqBin.indexOf(keyBytes, pos);
                if (startPos != -1) {
                    return new StartEndPosition(startPos, startPos + keyLen);
                }
                return null;
            }

            @Override
            public byte[] getSubSequence(int startPos, int endPos) {
                return seqBin.subBytes(startPos, endPos);
            }

            @Override
            public byte[] manipulate(int startPos, int endPos) {
                return replaceBytes;
            }

            @Override
            public void addToResultData(byte[] data) {
                outputBin.concat(data);
            }

            @Override
            public byte[] getResultData() {
                return outputBin.getBytes();
            }
        };
    }

    public byte[] action(int untilFountCount) {
        return this.manipulateActionUntil(sequenceManipulator, untilFountCount);
    }
}
