package org.zaproxy.zap.extension.customactivescan;

import com.google.gson.Gson;

import java.io.FileReader;
import java.io.Reader;
import java.util.List;

public class LoadGsonInjectionPatterns {
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
            "   \"truepattern\": \"1'='1' -- \",  " +
            "   \"falsepattern\": \"0'='1' -- \", " +
            "   \"errorpattern\": \"1'='1' - - \"  " +
            "}" +
            "]" +
            "}"
            ;
    public LoadGsonInjectionPatterns(String gsonfile) {
        Gson gson = new Gson();
        try {
            Reader gsonreader = new FileReader(gsonfile);
            this.patterns = gson.fromJson(gsonreader, InjectionPatterns.class);
        }catch (Exception e){
            this.patterns = gson.fromJson(defaultpattern, InjectionPatterns.class);
        }
    }

    public List<InjectionPatterns.TrueFalsePattern> getPatternList() {
        return this.patterns.patterns;
    }

    public String getName() {return this.patterns.name;}
}
