package org.zaproxy.zap.extension.customactivescan.model;

import java.util.ArrayList;
import java.util.List;

public class InjectionPatterns {

    public String name = null; // required : set something unique name
    public List<TrueFalsePattern> patterns = null;

    public InjectionPatterns() {
        clearPatterns();
    }

    public static class TrueFalsePattern {
        public String trueValuePattern = null; // required condition true   e.g.:[1'='1' -- ]
        public String falseValuePattern = null; // required condition false e.g.:[1'='0' -- ]
        public String errorValuePattern = null; // optional condition (SQL)error e.g.:[1'='1' - - ]
        public String trueNamePattern = null; // optional condition true for sanitizing name e.g. [$ne]
        public String falseNamePattern = null; // optional condition false for sanitizing name
        public String errorNamePattern = null; // optional condition error for sanitizing name
    }

    public void clearPatterns() {
        patterns = new ArrayList<>();
    }

    public void addPattern(String trueValue, String falseValue, String errorValue, String trueName, String falseName, String errorName) {
        TrueFalsePattern pattern = new TrueFalsePattern();
        pattern.trueValuePattern = trueValue;
        pattern.falseValuePattern = falseValue;
        pattern.errorValuePattern = errorValue;
        pattern.trueNamePattern = trueName;
        pattern.falseNamePattern = falseName;
        pattern.errorNamePattern = errorName;
        patterns.add(pattern);
    }
}
