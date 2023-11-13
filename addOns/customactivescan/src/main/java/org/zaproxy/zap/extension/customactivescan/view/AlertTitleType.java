package org.zaproxy.zap.extension.customactivescan.view;

public enum AlertTitleType {

    URL("URL:"),
    RISK("Risk:"),
    CONFIDENCE("Confidence:"),
    PARAMETER("Parameter:"),
    ATTACK("Attack:"),
    EVIDENCE("Evidence:"),
    CWE("CWE ID:"),
    WASC("WASC ID:"),
    SOURCE("Source:"),
    INPUTVECTOR("Input Vector:"),
    REFERENCE("Reference:"),
    DESCRIPTION("Description:"),
    OTHERINFO("Other Info:")
    ;
    private String titleName;
    AlertTitleType(String name) {
        this.titleName = name;
    }

    public String getTitleName() {
        return this.titleName;
    }
}
