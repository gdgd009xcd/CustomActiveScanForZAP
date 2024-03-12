package org.zaproxy.zap.extension.customactivescan;

public interface SequenceManipulator<T> {
    /**
     * get length of the Sequence
     * @return
     */
    public int length();

    /**
     * get index of the Key within the Sequence
     * @param pos
     * @return
     */
    public StartEndPosition foundKeyNext(int pos);

    /**
     * get the subsequence of the Sequence.
     * @param startPos
     * @param endPos
     * @return
     */
    public T getSubSequence(int startPos, int endPos);

    /**
     * manipulate the specified part of the Sequence with the Value
     * @param startPos
     * @param endPos
     * @return
     */
    public T manipulate(int startPos, int endPos);

    /**
     * add a data to the Output
     * @param data
     */
    public void addToResultData(T data);

    /**
     * get result of the manipulation
     * @return
     */
    public T getResultData();
}
