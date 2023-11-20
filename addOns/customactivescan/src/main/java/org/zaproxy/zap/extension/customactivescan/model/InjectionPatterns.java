package org.zaproxy.zap.extension.customactivescan.model;

import com.google.gson.annotations.Expose;
import org.zaproxy.zap.extension.customactivescan.DeepClone;
import org.zaproxy.zap.extension.customactivescan.ListDeepCopy;

import java.util.ArrayList;
import java.util.List;

public class InjectionPatterns implements DeepClone {

    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    // <---START LINE: "@Expose" members output to JSON file.
    @Expose
    public String name = null; // required : set something unique name
    @Expose
    public List<TrueFalsePattern> patterns = null;
    // --->END LINE: "@Expose" members output to JSON file.

    public static class TrueFalsePattern implements DeepClone {
        // <---START LINE: "@Expose" members output to JSON file.
        @Expose
        public ModifyType modifyType = ModifyType.Add;
        @Expose
        public String trueValuePattern = null; // required condition true   e.g.:[1'='1' -- ]
        @Expose
        public String falseValuePattern = null; // required condition false e.g.:[1'='0' -- ]
        @Expose
        public String errorValuePattern = null; // optional condition (SQL)error e.g.:[1'='1' - - ]
        @Expose
        public String trueNamePattern = null; // optional condition true for sanitizing name e.g. [$ne]
        @Expose
        public String falseNamePattern = null; // optional condition false for sanitizing name
        @Expose
        public String errorNamePattern = null; // optional condition error for sanitizing name
        // --->END LINE: "@Expose" members output to JSON file.

        // Without "@Expose" members which is are NOT output to JSON file



        @Override
        public TrueFalsePattern clone() {
            TrueFalsePattern nobj = null;
            try {
                nobj = (TrueFalsePattern) super.clone();
            } catch (CloneNotSupportedException ex) {
                LOGGER4J.error(ex.getMessage(), ex);
            }
            return nobj;
        }
    }

    public InjectionPatterns() {
        clearPatterns();
    }
    public void clearPatterns() {
        patterns = new ArrayList<>();
    }

    public void addPattern(ModifyType modifyType, String trueValue, String falseValue, String errorValue, String trueName, String falseName, String errorName) {
        TrueFalsePattern pattern = new TrueFalsePattern();
        pattern.modifyType = modifyType;
        pattern.trueValuePattern = trueValue;
        pattern.falseValuePattern = falseValue;
        pattern.errorValuePattern = errorValue;
        pattern.trueNamePattern = trueName;
        pattern.falseNamePattern = falseName;
        pattern.errorNamePattern = errorName;
        patterns.add(pattern);
    }

    public void setName(String newName) {
        this.name = newName;
    }

    @Override
    public InjectionPatterns clone() {
        InjectionPatterns nobj = null;
        try {
            nobj = (InjectionPatterns) super.clone();
            nobj.patterns = new ArrayList<>();
            nobj.patterns = ListDeepCopy.listDeepCopyVClone(this.patterns, nobj.patterns);
        } catch (CloneNotSupportedException ex) {
            LOGGER4J.error(ex.getMessage(), ex);
        }
        return nobj;
    }
}
