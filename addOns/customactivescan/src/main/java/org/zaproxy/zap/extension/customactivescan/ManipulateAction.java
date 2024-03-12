package org.zaproxy.zap.extension.customactivescan;

public class ManipulateAction<T> {

    /**
     * Elements:<BR>
     *  the Sequence : the target sequence of manipulation<BR>
     *  the Key : the value for searching within the Sequence<BR>
     *  the Value(of Manipulation): the value for replacing the key within sequence<BR>
     *  the Output: the buffer for storing result of manipulation.<BR>
     * Objective:<BR>
     *  search the Key within the Sequence and replace it with the Value.<BR>
     * Steps:<BR>
     * 1) get index of the Key within the Sequence by the foundKeyNext method.<BR>
     * 2) replace the part of the Key in the Sequence with the Value by the manipulate method.<BR>
     * 3) copy these results of manipulation in the Sequence to the Output.
     *
     * @param manipulator
     * @return
     */
    protected T manipulateAction(SequenceManipulator<T> manipulator) {
        int startPos = 0;
        int endPos = -1;
        StartEndPosition position;
        while((position = manipulator.foundKeyNext(startPos)) != null){
            endPos = position.start;
            if (startPos < endPos) {
                T inputData = manipulator.getSubSequence(startPos, endPos);
                manipulator.addToResultData(inputData);
            }
            manipulator.addToResultData(manipulator.manipulate(position.start, position.end));
            startPos = position.end;
        }
        if (startPos < manipulator.length()) {
            manipulator.addToResultData(manipulator.getSubSequence(startPos, manipulator.length()));
        }
        return manipulator.getResultData();
    }

    protected T manipulateActionUntil(SequenceManipulator<T> manipulator, int untilFoundCount) {
        if (untilFoundCount<1) return manipulateAction(manipulator);
        int startPos = 0;
        int endPos = -1;
        StartEndPosition position;
        while((position = manipulator.foundKeyNext(startPos)) != null){
            endPos = position.start;
            if (startPos < endPos) {
                T inputData = manipulator.getSubSequence(startPos, endPos);
                manipulator.addToResultData(inputData);
            }
            manipulator.addToResultData(manipulator.manipulate(position.start, position.end));
            startPos = position.end;
            if(--untilFoundCount <= 0)break;
        }
        if (startPos < manipulator.length()) {
            manipulator.addToResultData(manipulator.getSubSequence(startPos, manipulator.length()));
        }
        return manipulator.getResultData();
    }
}
