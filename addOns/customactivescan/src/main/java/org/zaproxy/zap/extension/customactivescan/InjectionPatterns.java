package org.zaproxy.zap.extension.customactivescan;

import java.util.ArrayList;
import java.util.List;

public class InjectionPatterns {

    String name = null; // required : set something unique name
    List<TrueFalsePattern> patterns;

    public InjectionPatterns() {
        patterns = new ArrayList<>();
    }

    static class TrueFalsePattern {
        String trueValuePattern = null; // required condition true   e.g.:[1'='1' -- ]
        String falseValuePattern = null; // required condition false e.g.:[1'='0' -- ]
        String errorValuePattern = null; // optional condition (SQL)error e.g.:[1'='1' - - ]
        String trueNamePattern = null; // optional condition true for sanitizing name e.g. [$ne]
        String falseNamePattern = null; // optional condition false for sanitizing name
        String errorNamePattern = null; // optional condition error for sanitizing name
    }
}
