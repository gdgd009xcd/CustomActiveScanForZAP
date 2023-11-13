package org.zaproxy.zap.extension.customactivescan;

import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.customactivescan.model.AttackTitleType;
import org.zaproxy.zap.extension.customactivescan.view.InterfacePopUpAction;

import java.awt.*;
import java.util.List;

public class HttpMessageWithLCSResponse extends HttpMessage implements InterfacePopUpAction {
    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();
    private String lcsResponse = null;
    private int originalAverageResponseSize = -1;
    private int worstResponseStatus = -1;
    private int messageIndexInScanLogPanel; //  index of message in ScanLogPanel.resultMessageList
    private List<StartEndPosition> lcsCharacterIndexOfLcsResponse = null;
    private List<StartEndPosition> lcsCharacterIndexOfLcsRequest = null;
    private String attackTitleString = null;
    private String percentString = "";
    private int injectionPatternGroupIndex = -1;
    private Alert alert = null;
    private AttackTitleType attackTitleType = null;
    private Component popUpInvokerComponent = null;
    private ParmGenMacroTraceParams pmtParams = null;

    HttpMessageWithLCSResponse(
            HttpMessage htmsg,
            String lcsResponse,
            int worstResponseStatus,
            int originalAverageResponseSize,
            AttackTitleType attackTitleType,
            String attackTitleString) {
        super(htmsg);
        messageIndexInScanLogPanel = -1;
        this.lcsResponse = lcsResponse;
        this.worstResponseStatus = worstResponseStatus;
        this.originalAverageResponseSize = originalAverageResponseSize;
        this.attackTitleType = attackTitleType;
        this.attackTitleString = attackTitleString;
    }

    HttpMessageWithLCSResponse(HttpMessage resultMessage, AttackTitleType attackTitleType) {
        super(resultMessage);
        messageIndexInScanLogPanel = -1;
        String entireResponseString = resultMessage.getResponseHeader().toString() + resultMessage.getResponseBody().toString();
        this.lcsResponse = entireResponseString;
        this.worstResponseStatus = resultMessage.getResponseHeader().getStatusCode();
        this.originalAverageResponseSize = entireResponseString.length();
        this.attackTitleType = attackTitleType;
        this.attackTitleString = attackTitleType.name();
    }

    private HttpMessageWithLCSResponse(HttpMessageWithLCSResponse message) {
        super(message);
    }

    private void copyMembersToDest(HttpMessageWithLCSResponse dest) {
        dest.lcsResponse = this.lcsResponse;
        dest.originalAverageResponseSize = this.originalAverageResponseSize;
        dest.worstResponseStatus = this.worstResponseStatus;
        dest.messageIndexInScanLogPanel = this.messageIndexInScanLogPanel;
        dest.lcsCharacterIndexOfLcsResponse = this.lcsCharacterIndexOfLcsResponse;
        dest.lcsCharacterIndexOfLcsRequest = this.lcsCharacterIndexOfLcsRequest;
        dest.attackTitleString = this.attackTitleString;
        dest.percentString = this.percentString;
        dest.injectionPatternGroupIndex = this.injectionPatternGroupIndex;
        dest.alert = this.alert;
        dest.attackTitleType = this.attackTitleType;
        dest.popUpInvokerComponent = this.popUpInvokerComponent;
        dest.pmtParams = this.pmtParams;
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

    public void setLcsCharacterIndexOfLcsRequest(List<StartEndPosition> listIndex) {
        this.lcsCharacterIndexOfLcsRequest = listIndex;
    }

    public boolean hasResponseLCS() {
        return (this.lcsCharacterIndexOfLcsResponse != null && !this.lcsCharacterIndexOfLcsResponse.isEmpty());
    }

    public boolean hasRequestLCS() {
        return (this.lcsCharacterIndexOfLcsRequest !=null && !this.lcsCharacterIndexOfLcsRequest.isEmpty());
    }
    public List<StartEndPosition> getLcsCharacterIndexOfLcsResponse() {
        return this.lcsCharacterIndexOfLcsResponse;
    }

    public List<StartEndPosition> getLcsCharacterIndexOfLcsRequest() {
        return this.lcsCharacterIndexOfLcsRequest;
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

    public String getAttackTitleString() {
        return attackTitleString;
    }

    public void setPercentString(String percent){
        this.percentString = percent;
    }

    public String getPercentString() {
        return this.percentString;
    }
    public AttackTitleType getAttackTitleType() {
        return this.attackTitleType;
    }

    public void setAlert(Alert alert) {
        this.alert = alert;
    }

    public Alert getAlert() {
        return this.alert;
    }

    public void setPopUpInvokerComponent(Component component) {
        this.popUpInvokerComponent = component;
    }
    @Override
    public void popUpActionPerformed(HttpMessage message) {
        if (this.popUpInvokerComponent != null) {
            if (InterfacePopUpAction.class.isAssignableFrom(this.popUpInvokerComponent.getClass())){
                InterfacePopUpAction action = (InterfacePopUpAction) this.popUpInvokerComponent;
                action.popUpActionPerformed(message);
            }
        }
    }


    @Override
    public HttpMessageWithLCSResponse cloneRequest() {
        HttpMessageWithLCSResponse newMessage = new HttpMessageWithLCSResponse(this);
        if (newMessage != null) {
            copyMembersToDest(newMessage);
        }
        return newMessage;
    }

    public void hello(String data, Integer i) {

        LOGGER4J.info("hello from customactive data:" + data + " i=" + i.toString());
    }

    public void setPmtParams(ParmGenMacroTraceParams pmtParams) {
        this.pmtParams = pmtParams;
    }

    public Integer[] getPmtParamsArray() {
        if (this.pmtParams != null) {
            return new Integer[] {
                    this.pmtParams.scannerId,
                    this.pmtParams.getSelectedRequestNo(),
                    this.pmtParams.getLastStepNo(),
                    this.pmtParams.getTabIndex()
            };
        }
        return null;
    }

}
