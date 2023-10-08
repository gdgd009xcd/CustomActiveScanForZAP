package org.zaproxy.zap.extension.customactivescan;

import org.parosproxy.paros.network.HttpMessage;

public class HttpMessageWithLCSResponse extends HttpMessage {
    String lcsResponse;
    int originalAverageResponseSize;
    int worstResponseStatus;

    HttpMessageWithLCSResponse(HttpMessage htmsg, String lcsResponse, int worstResponseStatus, int originalAverageResponseSize) {
        super(htmsg);
        this.lcsResponse = lcsResponse;
        this.worstResponseStatus = worstResponseStatus;
        this.originalAverageResponseSize = originalAverageResponseSize;
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
