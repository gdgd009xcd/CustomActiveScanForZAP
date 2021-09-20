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
