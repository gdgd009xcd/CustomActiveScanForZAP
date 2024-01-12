package org.zaproxy.zap.extension.customactivescan;


public class UrlEncodedInsertionRange extends StartEndPosition{

    public UrlEncodedInsertionRange(int start, int end) {
        super(start, end);
    }

    public boolean isUrlEncoded(int start, int end) {
       if (this.start >= start && this.end <= end) {
           return true;
       }
       return false;
    }
}
