package org.zaproxy.zap.extension.customactivescan;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class StringSplitter {
    Pattern pattern = null;

    StringSplitter(String delimregex) {
        if (delimregex == null || delimregex.isEmpty()) {
            delimregex = "\n";
        }
        try {
            pattern = Pattern.compile(delimregex);
        } catch (Exception e) {
            pattern = Pattern.compile("\n"); // default delimiter
        }
    }

    public List<String> split(String data) {
        List<String> results = new ArrayList<>();
        Matcher matcher = pattern.matcher(data);
        int start=0;
        int end = data.length();
        for(start=0;matcher.find(start);) {
            int next_end = matcher.end();
            results.add(data.substring(start, next_end));
            start = next_end;
        }
        if(start < end) {
            results.add(data.substring(start, end));
        }
        if(results.isEmpty()) {
            results.add(data);
        }
        return results;
    }
}
