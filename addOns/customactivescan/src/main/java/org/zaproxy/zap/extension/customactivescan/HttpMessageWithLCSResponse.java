package org.zaproxy.zap.extension.customactivescan;

import org.parosproxy.paros.network.HttpMessage;

public class HttpMessageWithLCSResponse extends HttpMessage {
    String lcsResponse;
    int originalAverageResponseSize;

    HttpMessageWithLCSResponse(HttpMessage htmsg, String lcsResponse, int originalAverageResponseSize) {
        super(htmsg);
        this.lcsResponse = lcsResponse;
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

}
