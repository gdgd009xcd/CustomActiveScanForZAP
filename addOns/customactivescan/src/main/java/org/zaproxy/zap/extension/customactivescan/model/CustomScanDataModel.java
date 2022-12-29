package org.zaproxy.zap.extension.customactivescan.model;

import com.google.gson.Gson;

import java.io.FileReader;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;

public class CustomScanDataModel {
    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();
    private String filename = null;// saved filename
    public int minIdleTime = 0;
    public int maxIdleTime = 0;
    public boolean randomieIdleTime = false;
    public List<String> flagResultItems;
    public enum RuleType {
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

    static String defaultpattern = "{" +
            "\"name\" : \"SQL Injection\", " +
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

    static String defaultPenTestPattern = "{" +
            "\"name\" : \"PenTest1\", " +
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

    String[] defaultFlagItems = {
            "Error","SQLERR", "Fatal"
    };

    public static class ScanRule {
        public RuleType ruleType;
        public boolean doScanLogOutput;
        public InjectionPatterns patterns;
        public String getRuleTypeName() {
            return ruleType.name();
        }
    }

    public List<ScanRule> scanRuleList;

    public CustomScanDataModel() {
        scanRuleList = new ArrayList<>();
        flagResultItems = new ArrayList<>();
    }

    public ScanRule getScanRule(int index) {
        try {
            return scanRuleList.get(index);
        } catch(IndexOutOfBoundsException e) {
            return null;
        }
    }

    public void createSampleData() {
        ScanRule scanRule = new ScanRule();
        scanRule.ruleType = RuleType.SQL;
        scanRule.doScanLogOutput = false;
        Gson gson = new Gson();
        String gsonfile = "/mnt/oldroot/home/daike/.ZAP_D/sqlinjection.txt";
        try (Reader gsonReader = new FileReader(gsonfile)) {
            scanRule.patterns = gson.fromJson(gsonReader, InjectionPatterns.class);
        }catch (Exception e){
            scanRule.patterns = gson.fromJson(defaultpattern, InjectionPatterns.class);
        }
        scanRuleList.add(scanRule);

        scanRule = new ScanRule();
        scanRule.ruleType = RuleType.PenTest;
        scanRule.doScanLogOutput = true;
        gson = new Gson();
        gsonfile = "/mnt/oldroot/home/daike/.ZAP_D/pentest.txt";
        try (Reader gsonReader = new FileReader(gsonfile)) {
            scanRule.patterns = gson.fromJson(gsonReader, InjectionPatterns.class);
        }catch (Exception e){
            scanRule.patterns = gson.fromJson(defaultPenTestPattern, InjectionPatterns.class);
        }
        scanRuleList.add(scanRule);

        for(String flag: defaultFlagItems) {
            flagResultItems.add(flag);
        }

    }

    public void saveToFile(String filename) {
        if (filename!=null && !filename.isEmpty()) {
            this.filename = filename;
            LOGGER4J.debug("File[" + this.filename + "] saved.");
        }
    }

    public String getSaveFileName() {
        return filename;
    }

    public boolean isSaved() {
        return filename==null?false:true;
    }
}
