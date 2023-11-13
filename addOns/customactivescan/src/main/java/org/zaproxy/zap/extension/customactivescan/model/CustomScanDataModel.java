package org.zaproxy.zap.extension.customactivescan.model;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.Expose;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.customactivescan.ExtensionAscanRules;
import org.zaproxy.zap.extension.customactivescan.FileWriterPlus;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.util.List;

public class CustomScanDataModel {
    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();
    private final String CONFIG_FILE_PATH = ExtensionAscanRules.ZAPHOME_DIR + Constant.messages.getString("customactivescan.config.filename");
    private ConfigFile configFile = null;// config file JSON data which includes save file name path(absFileNamePath)

    private CustomScanJSONData customScanData;// configration data which is saved absFileNamePath

    public static class ConfigFile {
        // <---START LINE: "@Expose" members output to JSON file.
        @Expose
        String absFileNamePath;
        @Expose
        boolean isSaved;
        // --->END LINE: "@Expose" members output to JSON file.

        boolean isSampleLoaded;

        ConfigFile() {
            absFileNamePath = null;
            isSaved = false;
            isSampleLoaded = false;
        }

    }

    public CustomScanDataModel() {
        this.customScanData = null;
        init();
    }

    private void init() {
        Gson gson = new Gson();
        boolean isLoaded = false;
        try (Reader configReader = new FileReader(CONFIG_FILE_PATH)) {
            this.configFile = gson.fromJson(configReader, ConfigFile.class);
            // load scanRule Data from configFile.absFileNamePath
            try (Reader dataReader = new FileReader(this.configFile.absFileNamePath)) {
                this.customScanData = gson.fromJson(dataReader, CustomScanJSONData.class);
                this.customScanData.createSampleRuleList();
                isLoaded = true;
            } catch(Exception e) {
                LOGGER4J.error(e.getMessage(), e);
            }
        }catch (Exception e){
            LOGGER4J.error(e.getMessage(), e);
        }

        if (!isLoaded) {
            if (this.configFile == null) {
                this.configFile = new ConfigFile();
            }
            this.configFile.isSaved = false;
            this.configFile.isSampleLoaded = true;
            // new & call createSampleRuleList();
            this.customScanData = new CustomScanJSONData();
            // add sampleRuleList to ScanRuleList
            this.customScanData.addSampleDataToScanRuleList();
            try {
                this.saveConfig();
            } catch (Exception ex) {
                LOGGER4J.error(ex.getMessage(), ex);
            }
        }
    }

    private CustomScanJSONData openFileAndLoadCustomScanJSONData(String filename) {
        Gson gson = new Gson();
        CustomScanJSONData customScanJSONData = null;
        // load scanRule Data from file
        try (Reader dataReader = new FileReader(filename)) {
            customScanJSONData = gson.fromJson(dataReader, CustomScanJSONData.class);
            customScanJSONData.createSampleRuleList();
        } catch(Exception e) {
            LOGGER4J.error(e.getMessage(), e);
            customScanJSONData = null;
        }
        return customScanJSONData;
    }

    /**
     * load JSON from specified file.
     *
     * @param filename
     * @return true:succeeded false:faile
     */
    public boolean loadModel(String filename){
        String previousFileName = this.configFile.absFileNamePath;
        boolean previousIsSampleLoaded = this.configFile.isSampleLoaded;
        boolean isLoaded = false;
        Gson gson = new Gson();
        CustomScanJSONData customScanJSONData = openFileAndLoadCustomScanJSONData(filename);
        if (customScanJSONData != null) {

            try {
                this.configFile.absFileNamePath = filename;
                this.configFile.isSaved = true;
                this.configFile.isSampleLoaded = true;
                saveConfig();
                this.customScanData = customScanJSONData;
                isLoaded = true;
            } catch (Exception ex) {
                this.configFile.absFileNamePath = previousFileName;
                this.configFile.isSaved = false;
                this.configFile.isSampleLoaded = previousIsSampleLoaded;
                LOGGER4J.error(ex.getMessage(), ex);
            }
        }

        return isLoaded;
    }

    public CustomScanJSONData.ScanRule getScanRule(int index) {
        try {
            return this.customScanData.scanRuleList.get(index);
        } catch(IndexOutOfBoundsException e) {
            return null;
        }
    }

    public int getScanRuleCount() {
        if (this.customScanData != null && this.customScanData.scanRuleList != null) {
            return this.customScanData.scanRuleList.size();
        }
        return 0;
    }

    public List<CustomScanJSONData.ScanRule> getScanRuleList() {
        return this.customScanData.scanRuleList;
    }

    public List<CustomScanJSONData.ScanRule> getSampleScanRuleList() {
        return this.customScanData.sampleRuleList;
    }



    public void saveModelToNewFile(String filename) {
        if (filename!=null && !filename.isEmpty()) {
            this.configFile.absFileNamePath = filename;
            saveModel();
        }
    }

    public void saveConfig() throws FileNotFoundException, UnsupportedEncodingException {
        FileWriterPlus writerConfigFile = new FileWriterPlus(CONFIG_FILE_PATH);
        GsonBuilder gbuilder = new GsonBuilder();
        gbuilder.setPrettyPrinting();
        String prettyConfigFile = gbuilder.create().toJson(this.configFile);
        writerConfigFile.print(prettyConfigFile);
        writerConfigFile.close();
        LOGGER4J.debug("File[" + this.configFile.absFileNamePath + "] saved.");
        LOGGER4J.debug("File[" + CONFIG_FILE_PATH + "] saved.");
    }
    public void saveModel() {
        if (this.configFile.absFileNamePath != null && !this.configFile.absFileNamePath.isEmpty()) {
            try {
                FileWriterPlus writerCustomScanData = new FileWriterPlus(this.configFile.absFileNamePath);
                GsonBuilder gbuilder = new GsonBuilder();
                gbuilder.setPrettyPrinting();
                String prettyCustomScanData = gbuilder.excludeFieldsWithoutExposeAnnotation().create().toJson(this.customScanData);
                writerCustomScanData.print(prettyCustomScanData);
                writerCustomScanData.close();
                this.configFile.isSaved = true;

                saveConfig();
            } catch (Exception ex) {
                LOGGER4J.error(ex.getMessage(), ex);
            }
        }
    }

    public String getSaveFileName() {
        return this.configFile.absFileNamePath;
    }

    public boolean isSaved() {
        return this.configFile.isSaved;
    }

    public boolean isSampleLoaded() {
        return this.configFile.isSampleLoaded;
    }

    public void modifiedSample() {
        this.configFile.isSampleLoaded = false;
    }

    public boolean ruleNameIsExistInModel(String ruleName, boolean exceptSample) {
        if (ruleName != null && !ruleName.isEmpty()) {
            for (CustomScanJSONData.ScanRule rule : this.customScanData.scanRuleList) {
                if (ruleName.equals(rule.patterns.name)) {
                    return true;
                }
            }
            if (!exceptSample) {
                for (CustomScanJSONData.ScanRule rule : this.customScanData.sampleRuleList) {
                    if (ruleName.equals(rule.patterns.name)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    public void addNewScanRule(CustomScanJSONData.ScanRule scanRule) {
        this.customScanData.scanRuleList.add(scanRule);
    }

    public void removeScanRule(int index) {
        this.customScanData.scanRuleList.remove(index);
    }

}
