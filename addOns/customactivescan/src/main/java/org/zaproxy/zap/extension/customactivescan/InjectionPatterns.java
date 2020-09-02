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
        String truepattern = null; // required condition true   e.g.:[1'='1' -- ]
        String falsepattern = null; // required condition false e.g.:[1'='0' -- ]
        String errorpattern = null; // optional condition (SQL)error e.g.:[1'='1' - - ]

        public TrueFalsePattern(String tstr, String fstr, String estr) {
            truepattern = tstr;
            falsepattern = fstr;
            errorpattern = estr;
        }
    }
}
