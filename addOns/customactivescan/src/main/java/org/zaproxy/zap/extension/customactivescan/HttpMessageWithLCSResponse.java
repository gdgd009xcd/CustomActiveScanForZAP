package org.zaproxy.zap.extension.customactivescan;

import org.parosproxy.paros.network.HttpMessage;
import java.util.List;

public class HttpMessageWithLCSResponse extends HttpMessage {
    private String lcsResponse;
    private int originalAverageResponseSize;
    private int worstResponseStatus;
    private int messageIndexInScanLogPanel; //  index of message in ScanLogPanel.resultMessageList
    private List<StartEndPosition> lcsCharacterIndexOfLcsResponse = null;

    HttpMessageWithLCSResponse(HttpMessage htmsg, String lcsResponse, int worstResponseStatus, int originalAverageResponseSize) {
        super(htmsg);
        messageIndexInScanLogPanel = -1;
        this.lcsResponse = lcsResponse;
        this.worstResponseStatus = worstResponseStatus;
        this.originalAverageResponseSize = originalAverageResponseSize;
    }

    HttpMessageWithLCSResponse(HttpMessage resultMessage) {
        super(resultMessage);
        messageIndexInScanLogPanel = -1;
        String entireResponseString = resultMessage.getResponseHeader().toString() + resultMessage.getResponseBody().toString();
        this.lcsResponse = entireResponseString;
        this.worstResponseStatus = resultMessage.getResponseHeader().getStatusCode();
        this.originalAverageResponseSize = entireResponseString.length();
    }

    /**
     *  set index of message in ScanLogPanel.resultMessageList
     * @param index
     */
    public void setMessageIndexInScanLogPanel(int index) {
        this.messageIndexInScanLogPanel = index;
    }

    /**
     *  get index of message in ScanLogPanel.resultMessageList
     * @return index of messageList
     */
    public int getMessageIndexInScanLogPanel() {
        return this.messageIndexInScanLogPanel;
    }

    public void updateLcsResponse(String lcs) {
        this.lcsResponse = lcs;
    }

    public void setLcsCharacterIndexOfLcsResponse(List<StartEndPosition> listIndex) {
        this.lcsCharacterIndexOfLcsResponse = listIndex;
    }

    public boolean hasLCS() {
        return (this.lcsCharacterIndexOfLcsResponse != null && !this.lcsCharacterIndexOfLcsResponse.isEmpty());
    }

    public List<StartEndPosition> getLcsCharacterIndexOfLcsResponse() {
        return this.lcsCharacterIndexOfLcsResponse;
    }

    /**
     * get LCS response. LCS response consists of response header and Response body.
     * @return
     */
    public String getLCSResponse() {
        return this.lcsResponse;
    }

    /**
     * get Original Average Size from 2 Responses
     * @return
     */
    public int getOriginalAverageResponseSize() {
        return this.originalAverageResponseSize;
    }

    /**
     * get response's 3digit status using worst(most largest) 3digit status in 2 responses.
     * @return
     */
    public int getWorstResponseStatus() { return this.worstResponseStatus; }

}
