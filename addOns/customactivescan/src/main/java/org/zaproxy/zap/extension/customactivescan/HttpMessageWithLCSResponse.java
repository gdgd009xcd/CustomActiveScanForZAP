package org.zaproxy.zap.extension.customactivescan;

import org.parosproxy.paros.network.HttpMessage;

public class HttpMessageWithLCSResponse extends HttpMessage {
    String lcsResponse;

    HttpMessageWithLCSResponse(HttpMessage htmsg, String lcsResponse) {
        super(htmsg);
        this.lcsResponse = lcsResponse;
    }

    /**
     * get LCS response. LCS response consists of response header and Response body.
     * @return
     */
    public String getLCSResponse() {
        return this.lcsResponse;
    }

}
