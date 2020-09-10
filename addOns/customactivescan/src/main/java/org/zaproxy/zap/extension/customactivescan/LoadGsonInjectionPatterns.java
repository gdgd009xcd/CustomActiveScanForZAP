package org.zaproxy.zap.extension.customactivescan;

import com.google.gson.Gson;

import java.io.FileReader;
import java.io.Reader;
import java.util.List;

public class LoadGsonInjectionPatterns {
    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    private InjectionPatterns patterns;

    static String defaultpattern = "{" +
            "\"name\" : \"default patterns\", " +
            "\"patterns\" :  [" +
            "{ " +
            "   \"truepattern\": \"'||'\",  " +
            "   \"falsepattern\": \"'|''\", " +
            "   \"errorpattern\": null " +
            "}," +
            "{ " +
            "   \"truepattern\": \"/**/\",  " +
            "   \"falsepattern\": \"/*//\", " +
            "   \"errorpattern\": null  " +
            "}," +
            "{ " +
            "   \"truepattern\": \"+0\",  " +
            "   \"falsepattern\": \"+9\", " +
            "   \"errorpattern\": \"+-\"  " +
            "}," +
            "{ " +
            "   \"truepattern\":  \"' or  1=1 -- \",  " +
            "   \"falsepattern\": \"' and 1=1 -- \", " +
            "   \"errorpattern\": \"' rr  1=1 -- \"  " +
            "}" +
            "]" +
            "}"
            ;
    public LoadGsonInjectionPatterns(String gsonfile) {
        Gson gson = new Gson();
        try {
            Reader gsonreader = new FileReader(gsonfile);
            this.patterns = gson.fromJson(gsonreader, InjectionPatterns.class);
            LOGGER4J.info("SQLInjectionPatternFile Loaded[" + gsonfile + "]");
        }catch (Exception e){
            this.patterns = gson.fromJson(defaultpattern, InjectionPatterns.class);
            LOGGER4J.info("SQLInjectionPatternFile FAILED to load. Default pattern will be applied.[" + gsonfile + "]");
        }
    }

    public List<InjectionPatterns.TrueFalsePattern> getPatternList() {
        return this.patterns.patterns;
    }

    public String getName() {return this.patterns.name;}
}
