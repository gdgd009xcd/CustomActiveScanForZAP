package org.zaproxy.zap.extension.customactivescan;

public class StartEndPosition {
    public int start;
    public int end;
    public String styleName = null;
    public StartEndPosition(int start, int end) {
        this.start = start;
        this.end = end;
    }
}
