package org.zaproxy.zap.extension.customactivescan.model;

import com.google.gson.Gson;
import com.google.gson.annotations.Expose;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.customactivescan.DeepClone;
import org.zaproxy.zap.extension.customactivescan.ExtensionAscanRules;

import java.io.FileReader;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;

// JSON data format for saving/loading CustomScanDataModel to/from file.

public class CustomScanJSONData {
    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    public static String VERSION_CONSTANT = "1.0";

    // Gson members
    @Expose
    public String Version = VERSION_CONSTANT;
    @Expose
    public int minIdleTime = 0;
    @Expose
    public int maxIdleTime = 0;
    @Expose
    public int requestCount = 0;
    @Expose
    public boolean randomieIdleTime = false;
    @Expose
    List<ScanRule> scanRuleList;
    // exclude the following field when serializing/deserializing
    List<ScanRule> sampleRuleList;

    // Non-Gson members(static)
    private static final String SAMPLE_PREFIX = "customactivescan.sample.";
    private static final String SAMPLE_SQL_FILE_PATH = ExtensionAscanRules.ZAPHOME_DIR + Constant.messages.getString(SAMPLE_PREFIX + "sql");
    private static final String SAMPLE_PENTEST_FILE_PATH = ExtensionAscanRules.ZAPHOME_DIR + Constant.messages.getString(SAMPLE_PREFIX + "pentest");
    private static String defaultpattern = "{" +
            "\"name\" : \"Sample SQL Injection\", " +
            "\"patterns\" :  [" +
            "{ " +
            "   \"trueValuePattern\": \"'||'\",  " +
            "   \"falseValuePattern\": \"'|''\", " +
            "   \"errorValuePattern\": null " +
            "}," +
            "{ " +
            "   \"trueValuePattern\": \"/**/\",  " +
            "   \"falseValuePattern\": \"/*//\", " +
            "   \"errorValuePattern\": null  " +
            "}," +
            "{ " +
            "   \"trueValuePattern\": \"+0\",  " +
            "   \"falseValuePattern\": \"+9\", " +
            "   \"errorValuePattern\": \"+-\"  " +
            "}," +
            "{ " +
            "   \"trueValuePattern\":  \"' or  1=1 -- \",  " +
            "   \"falseValuePattern\": \"' and 1=1 -- \", " +
            "   \"errorValuePattern\": \"' rr  1=1 -- \"  " +
            "}," +
            "{ " +
            "   \"trueNamePattern\":  \"[$ne]\",  " +
            "   \"trueValuePattern\":  \"1\",  " +
            "   \"falseNamePattern\":  \"[ne]\",  " +
            "   \"falseValuePattern\": \"1\" " +
            "}" +
            "]" +
            "}"
            ;

    private static String defaultPenTestPattern = "{" +
            "\"name\" : \"Sample PenTest\", " +
            "\"patterns\" :  [" +
            "{ " +
            "   \"trueValuePattern\": \"'||'\"  " +

            "}," +
            "{ " +
            "   \"trueValuePattern\": \"'|'\"  " +

            "}," +
            "{ " +
            "   \"trueValuePattern\": \"%a0\"  " +

            "}" +
            "]" +
            "}"
            ;

    private static String[] defaultFlagItems = {
            "Error","SQLERR", "Fatal"
    };

    public CustomScanJSONData() {
        scanRuleList = new ArrayList<>();
        createSampleRuleList();
    }

    public void createSampleRuleList() {
        sampleRuleList = new ArrayList<>();
        ScanRule scanRule = new ScanRule();
        scanRule.initSampleSQL();
        sampleRuleList.add(scanRule);
        scanRule = new ScanRule();
        scanRule.initSamplePenTest();
        sampleRuleList.add(scanRule);
    }

    public enum RuleType {// GSON has default [serial/deserial]ization capability for enum
        SQL,
        PenTest;

        public static List<String> getNameList() {
            RuleType[] enumArray = RuleType.values();
            List<String> allRuleTypes = new ArrayList<>();
            for(RuleType ruleType: enumArray) {
                allRuleTypes.add(ruleType.name());// must use name() method. toString() method returns value that may be not usable for valueOf() method.
            }
            return allRuleTypes;
        }

    };

    public static class ScanRule implements DeepClone {
        @Expose
        public RuleType ruleType;
        @Expose
        public boolean doScanLogOutput;
        @Expose
        public InjectionPatterns patterns;
        @Expose
        public List<String> flagResultItems;

        public String getRuleTypeName() {
            return ruleType.name();
        }

        public ScanRule() {
            this.ruleType = RuleType.SQL;
            this.doScanLogOutput = false;
            this.patterns = new InjectionPatterns();
            this.flagResultItems = new ArrayList<>();
        }

        @Override
        public ScanRule clone() {
            ScanRule nobj = null;
            try {
                nobj = (ScanRule) super.clone();
                nobj.patterns = this.patterns.clone();
                nobj.flagResultItems = new ArrayList<>();
                for(String item: this.flagResultItems) {
                    nobj.flagResultItems.add(item);
                }
            } catch (CloneNotSupportedException ex) {
                LOGGER4J.error(ex.getMessage(), ex);
            }
            return nobj;
        }

        public void setName(String newName) {
            this.patterns.setName(newName);
        }

        public void initSampleSQL() {
            this.ruleType = RuleType.SQL;
            this.doScanLogOutput = false;
            Gson gson = new Gson();
            try (Reader gsonReader = new FileReader(SAMPLE_SQL_FILE_PATH)) {
                this.patterns = gson.fromJson(gsonReader, InjectionPatterns.class);
            }catch (Exception e){
                this.patterns = gson.fromJson(defaultpattern, InjectionPatterns.class);
            }
            this.flagResultItems.clear();
        }

        public void initSamplePenTest() {
            this.ruleType = RuleType.PenTest;
            this.doScanLogOutput = true;
            Gson gson = new Gson();
            try (Reader gsonReader = new FileReader(SAMPLE_PENTEST_FILE_PATH)) {
                this.patterns = gson.fromJson(gsonReader, InjectionPatterns.class);
            }catch (Exception e){
                this.patterns = gson.fromJson(defaultPenTestPattern, InjectionPatterns.class);
            }

            this.flagResultItems.clear();
            for(String flag: defaultFlagItems) {
                this.flagResultItems.add(flag);
            }
        }
    }

    public void addSampleDataToScanRuleList() {
        for(ScanRule scanRule: sampleRuleList) {
            scanRuleList.add(scanRule);
        }
    }
}
