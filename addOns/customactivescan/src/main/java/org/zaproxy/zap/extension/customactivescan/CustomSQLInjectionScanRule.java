package org.zaproxy.zap.extension.customactivescan;

import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.Level;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.HostProcess;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.extension.ascan.ActiveScan;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.customactivescan.model.CustomScanJSONData;
import org.zaproxy.zap.extension.customactivescan.model.InjectionPatterns;
import org.zaproxy.zap.extension.customactivescan.model.PauseActionObject;
import org.zaproxy.zap.extension.customactivescan.model.WaitTimerObject;
import org.zaproxy.zap.extension.customactivescan.view.ScanLogPanel;
import org.zaproxy.zap.extension.customactivescan.view.ScanLogPanelFrame;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.network.HttpResponseBody;

import javax.swing.*;
import java.lang.reflect.InvocationTargetException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.zaproxy.zap.extension.customactivescan.ExtensionAscanRules.MESSAGE_PREFIX;

/**
 * this is special custmizable SQL injection logic test.
 *
 * @author gdgd009xcd
 *
 */
public class CustomSQLInjectionScanRule extends AbstractAppParamPlugin {

    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    final Level DEBUGBINGO = Level.getLevel("DEBUGBINGO");
    private final int PRINTVALUEMAXLEN = 255; // max length of debug print string.
    private PrintableString printableString = null;

    private int NEALYEQUALPERCENT; // If this value or more(value >= NEALYEQUALPECENT), it is considered to match
    private int NEALYDIFFERPERCENT; // If less than this value(value < NEALYDIFFERPECENT), it is considered as a mismatch
    private int ALMOSTDIFFERPERCENT; // if less than this value, it is considered as almost diffrerent each other.

    private int MAXMASKBODYSIZE = 100000000; // If response body size is larger than this size, do not apply the asterisk conversion to the body
    private boolean isMaskBodyWithAsterisk;

    private int MINWORDLEN = 5; // if extractedOriginalTrueLCS.size < MINWORDLEN then compare extractedOriginalTrueString and extractedFalseString

    private HttpMessageWithLCSResponse refreshedmessage = null;
    private String mResBodyNormalUnstripped = null;
    private String mResBodyNormalStripped = null;

    // regex pattern for masking random id such as CSRF token from HttpResponse
    private String cookieNameValueRegex = "([^\\cA-\\cZ()<>@,;:\\\\\"/\\[\\]?={} ]+)[\\r\\n\\t ]*=[\\r\\n\\t ]*\"?([\\x21\\x23-\\x2B\\x2D-\\x3A\\x3C-\\x5B\\x5D-\\x7E]+)\"?";
    private String quotedValueRegex = "(?<!\\\\)\"([^\\r\\t\\n ]+?)(?<!\\\\)\"";
    private String inputTagQuotedValueRegex = "value[\\t ]*=[\\t ]*(?<!\\\\)\"([^\\r\\t\\n ]+?)(?<!\\\\)\"";
    private Pattern cookieNameValuePattern;
    private Pattern quotedValuePattern;
    private Pattern inputTagQuotedValuePattern;
    private Pattern sqlErrorPattern;
    private String sqlErrorMsgRegex;

    private ExtensionActiveScan extensionActiveScan;

    ScanLogPanelFrame scanLogPanelFrame;

    String[] SQLERRORMSGS = {
            // Oracle
            "(\\b|^)ORA-",
            // postgres
            "unterminated quoted string at or near",
            "syntax error at or near",
            "invalid input syntax for",
            "Role does not exist",
            "Relation does not exist",
            "Permission denied for database",
            // mysql
            "You have an error in your SQL syntax",
            // mongodb where
            "Exception:SyntaxError",
            "Exception:ReferenceError",
            // SQLite
            "SQLITE_ERROR"
    };

    @Override
    public void init() {
        super.init();

        isMaskBodyWithAsterisk = false;

        scanLogPanelFrame = null;
        HostProcess hProcess = getParent();

        extensionActiveScan =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionActiveScan.class);
        List<ActiveScan> ascanList = extensionActiveScan.getActiveScans();

        CustomScanJSONData.ScanRule selectedScanRule = ExtensionAscanRules.customScanMainPanel.getSelectedScanRule();
        List<InjectionPatterns.TrueFalsePattern> listTrueFalsePatterns = selectedScanRule.patterns.patterns;
        List<String> flagResultItems = new ArrayList<>();
        for(String item: selectedScanRule.flagResultItems) {
            flagResultItems.add(item);
        }

        String[] flagResultItemArray = flagResultItems.toArray(new String[0]);// convert list to new Array of String
        int scannerId = -1;
        for(ActiveScan ascan: ascanList) {
            List<HostProcess> hostProcessList = ascan.getHostProcesses();
            for(HostProcess hPro: hostProcessList) {
                if (hPro == hProcess) {
                    scannerId = ascan.getId();
                    ExtensionAscanRules.hostProcessScannerIdMap.put(hProcess, scannerId);
                    WaitTimerObject waitTimerObject = new WaitTimerObject();
                    ExtensionAscanRules.scannerIdWaitTimerMap.put(scannerId, waitTimerObject);
                    if (selectedScanRule.doScanLogOutput) {
                        final int finalScannerId = scannerId;
                        try {
                            SwingUtilities.invokeAndWait(new Runnable() {
                                @Override
                                public void run() {
                                    scanLogPanelFrame = new ScanLogPanelFrame(flagResultItemArray, finalScannerId);
                                    ExtensionAscanRules.scannerIdScanLogFrameMap.put(finalScannerId, scanLogPanelFrame);
                                    ascan.addScannerListener(new CustomScannerListener());
                                    scanLogPanelFrame.updateRequestCounter(0);
                                }
                            });
                        } catch (InterruptedException e) {
                            LOGGER4J.error(e.getMessage(), e);
                        } catch (InvocationTargetException e) {
                            LOGGER4J.error(e.getMessage(), e);
                        }

                    } else {
                        ascan.addScannerListener(new CustomScannerListener());
                    }
                }
            }
        }

        if (scannerId != -1) {
            LOGGER4J.debug("start SCANNING scannerId[" + scannerId + "]" + " instance:" + this);
        } else {
            LOGGER4J.debug("can't get SCANNING scannerId!!!");
        }
        printableString = new PrintableString("");

        this.NEALYEQUALPERCENT = getNealyEqualPercent();
        this.NEALYDIFFERPERCENT = getNealyDifferPercent();
        this.ALMOSTDIFFERPERCENT = 5;

        switch (this.getAttackStrength() ) {
            case  LOW:
                break;
            case HIGH:
                break;
            case INSANE:
                break;
            case MEDIUM:
            default:
                break;
        }

        cookieNameValuePattern = Pattern.compile(cookieNameValueRegex, Pattern.MULTILINE);
        quotedValuePattern = Pattern.compile(quotedValueRegex, Pattern.MULTILINE);
        inputTagQuotedValuePattern = Pattern.compile(inputTagQuotedValueRegex, Pattern.MULTILINE);

        sqlErrorMsgRegex = "";
        for(String errmsg: SQLERRORMSGS) {
            sqlErrorMsgRegex = sqlErrorMsgRegex + (sqlErrorMsgRegex.isEmpty() ? errmsg : ("|" + errmsg));
        }
        LOGGER4J.debug("SQL ERROR Message regex:" + sqlErrorMsgRegex);
        sqlErrorPattern = Pattern.compile(sqlErrorMsgRegex, Pattern.MULTILINE|Pattern.CASE_INSENSITIVE);

    }

    @Override
    public void scan(HttpMessage msg, String origParamName, String origParamValue) {
        CustomScanJSONData.ScanRule selectedScanRule = ExtensionAscanRules.customScanMainPanel.getSelectedScanRule();
        int scannerId = ExtensionAscanRules.hostProcessScannerIdMap.get(getParent());
        PauseActionObject pauseActionObject = ExtensionAscanRules.scannerIdPauseActionMap.get(scannerId);
        WaitTimerObject waitTimerObject = ExtensionAscanRules.scannerIdWaitTimerMap.get(scannerId);
        LOGGER4J.debug("scan start scannerId:" + scannerId);
        try {
            switch (selectedScanRule.ruleType) {
                case SQL:
                    scanBySQLRule(msg, origParamName, origParamValue, scannerId, selectedScanRule, pauseActionObject, waitTimerObject);
                    break;
                case PenTest:
                    scanByPenTestRule(msg, origParamName, origParamValue, scannerId, selectedScanRule, pauseActionObject, waitTimerObject);
                    break;
                default:
                    break;
            }
        } catch (Exception ex) {
            LOGGER4J.error(ex.getMessage(), ex);
        }
    }

    private void scanBySQLRule(HttpMessage msg, String origParamName, String origParamValue, int scannerId, CustomScanJSONData.ScanRule selectedScanRule, PauseActionObject pauseActionObject, WaitTimerObject waitTimerObject) throws Exception{
        List<InjectionPatterns.TrueFalsePattern> patterns = selectedScanRule.patterns.patterns;
        boolean sqlInjectionFoundForUrl = false;

        // calcurate response body responseTotalSize
        HttpResponseHeader responseHeader = msg.getResponseHeader();
        HttpResponseBody responseBody = msg.getResponseBody();
        String resBodyString = responseBody == null ? "" : responseBody.toString();
        String primeString = responseHeader.getPrimeHeader();
        String stringsOfHeaders = responseHeader.getHeadersAsString();
        int responseHeaderSize = primeString.length() + 2; // primeString.length + lineDelimiter.length(2)
        responseHeaderSize += stringsOfHeaders.length();
        int responseTotalSize = responseHeaderSize + resBodyString.length();

        if (responseTotalSize < MAXMASKBODYSIZE) {
            isMaskBodyWithAsterisk = true;
        }

        LOGGER4J.debug("scan HttpMessage RequestBody Charset[" + msg.getRequestBody().getCharset() + "]");

        LcsStringListComparator comparator = new LcsStringListComparator();

        refreshedmessage = sendRequestAndCalcLCS(comparator, null, null, scannerId, selectedScanRule, pauseActionObject, waitTimerObject);
        int normalAverageResponseSize = refreshedmessage.getOriginalAverageResponseSize();
        if(refreshedmessage==null)return;

        String[] normalBodyOutputs = getUnstrippedStrippedResponse(refreshedmessage, origParamValue, null);

        LOOPTRUE: for(Iterator<InjectionPatterns.TrueFalsePattern> it = patterns.iterator(); it.hasNext() && !sqlInjectionFoundForUrl;) {
            InjectionPatterns.TrueFalsePattern tfrpattern = it.next();

            // 1. Original response matches true condition
            String trueValue = origParamValue + tfrpattern.trueValuePattern;
            String trueParamName = origParamName + (tfrpattern.trueNamePattern != null ? tfrpattern.trueNamePattern : "");
            HttpMessageWithLCSResponse truemessage = sendRequestAndCalcLCS(comparator, trueParamName, trueValue, scannerId, selectedScanRule, pauseActionObject, waitTimerObject);
            int trueAverageResponseSize = truemessage.getOriginalAverageResponseSize();
            if (truemessage == null) continue;

            String[] trueBodyOutputs = getUnstrippedStrippedResponse(truemessage, trueValue, null);
            LcsStringList[] originalTrueLCSs = {new LcsStringList(), new LcsStringList()};
            LcsStringList[] originalFalseLCSs = {new LcsStringList(), new LcsStringList()};
            LcsStringList[] errorLCSs = {new LcsStringList(), new LcsStringList()};

            String falseValue = null;
            String falseParamName = null;
            String[] falseBodyOutputs = null;
            String[] errorBodyOutputs = null;
            HttpMessageWithLCSResponse errormessage = null;
            boolean bingoError = false;

            int falseAverageResponseSize = -1;

            for(int i=0;i<2;i++) {
                boolean trueHasSQLError = false;
                boolean falseHasSQLError = false;
                boolean errorHasSQLError = false;
                // 1. compare true and original/false
                int normalTruePercent = comparator.compare(normalBodyOutputs[i] , trueBodyOutputs[i], originalTrueLCSs[i]);
                if (hasSQLErrors(trueBodyOutputs[i]) != null) {
                    trueHasSQLError = true;
                }
                int normalFalsePercent = -1;
                // 1-1.true response matched original response
                if (LOGGER4J.isDebugEnabled()) {
                    String debugmess = "ParamName["
                            + trueParamName
                            + "] value["
                            + printableString.convert(trueValue, PRINTVALUEMAXLEN)
                            + "] truepercent["
                            + normalTruePercent
                            + "]"
                            + (normalTruePercent >= this.NEALYEQUALPERCENT ? ">=" : "<")
                            + "NEALYEQUALPERCENT["
                            + this.NEALYEQUALPERCENT
                            + "]";
                    LOGGER4J.debug(debugmess);
                }

                // 1-1. original(normal body) is equal to true body
                if (normalTruePercent >= this.NEALYEQUALPERCENT && !trueHasSQLError) {
                    if (falseBodyOutputs == null) {
                        falseValue = origParamValue + tfrpattern.falseValuePattern;
                        falseParamName = origParamName + (tfrpattern.falseNamePattern != null ? tfrpattern.falseNamePattern : "");
                        HttpMessageWithLCSResponse falsemessage = sendRequestAndCalcLCS(comparator, falseParamName, falseValue, scannerId, selectedScanRule, pauseActionObject, waitTimerObject);
                        falseAverageResponseSize = falsemessage.getOriginalAverageResponseSize();
                        if (falsemessage == null) continue;
                        falseBodyOutputs = getUnstrippedStrippedResponse(falsemessage, falseValue, null);
                    }
                    normalFalsePercent = comparator.compare(normalBodyOutputs[i], falseBodyOutputs[i], originalFalseLCSs[i]);
                    LOGGER4J.debug("ParamName["
                            + falseParamName
                            + "] value["
                            + printableString.convert(falseValue, PRINTVALUEMAXLEN)
                            + "] falsepercent["
                            + normalFalsePercent
                            + "]"
                            + (normalFalsePercent < this.NEALYDIFFERPERCENT ? "<" : ">=")
                            + "NEALYDIFFERPERCENT["
                            + this.NEALYDIFFERPERCENT
                            + "]"
                    );
                    // 1-2. original body is diffrent from false body.
                    if (normalFalsePercent < this.NEALYDIFFERPERCENT) {
                        // bingo.
                        LOGGER4J.debug("bingo 1-1.truepercent["
                                + normalTruePercent
                                + "]>="
                                + this.NEALYEQUALPERCENT
                                + " 1-2.falsepercent["
                                + normalFalsePercent + "<" + this.NEALYDIFFERPERCENT
                                + "]"
                        );
                        String evidence = Constant.messages.getString(MESSAGE_PREFIX + "alert.booleanbased.trueequaloriginal.evidence");
                        raiseAlertBooleanBased(Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, i > 0 ? true : false, truemessage,origParamName, trueParamName, trueValue, falseParamName, falseValue, null, evidence);
                        sqlInjectionFoundForUrl = true;
                        break LOOPTRUE;
                    }
                }

                if (falseBodyOutputs == null) {
                    falseValue = origParamValue + tfrpattern.falseValuePattern;
                    falseParamName = origParamName + (tfrpattern.falseNamePattern != null ? tfrpattern.falseNamePattern : "");
                    HttpMessageWithLCSResponse falsemessage = sendRequestAndCalcLCS(comparator, falseParamName, falseValue, scannerId, selectedScanRule, pauseActionObject, waitTimerObject);
                    falseAverageResponseSize = falsemessage.getOriginalAverageResponseSize();
                    if (falsemessage == null) continue;
                    falseBodyOutputs = getUnstrippedStrippedResponse(falsemessage, falseValue, null);

                }

                if (normalFalsePercent == -1) {
                    normalFalsePercent = comparator.compare(normalBodyOutputs[i], falseBodyOutputs[i], originalFalseLCSs[i]);
                }



                ArrayListWrapperFactory normalFalseResultFactory = new ArrayListWrapperFactory(originalFalseLCSs[i]);
                ArrayListWrapper<String> extractedOriginalDataList = normalFalseResultFactory.createArrayListWrapper(ArrayListWrapperFactory.ListType.DIFFA);
                ArrayListWrapper<String> extractedFalseDataList = normalFalseResultFactory.createArrayListWrapper(ArrayListWrapperFactory.ListType.DIFFB);

                LcsStringList extractedTrueLcs = new LcsStringList();
                int trueFalsePercent  = comparator.compare(trueBodyOutputs[i], falseBodyOutputs[i], extractedTrueLcs);
                LOGGER4J.debug("trueFalsePercent:" + trueFalsePercent);

                // 3. compare  extracted True data and extracted original data
                ArrayListWrapperFactory trueFalseResultFactory = new ArrayListWrapperFactory(extractedTrueLcs);
                ArrayListWrapper<String> extractedTrueDataList = trueFalseResultFactory.createArrayListWrapper(ArrayListWrapperFactory.ListType.DIFFA);
                LcsStringList extractedOriginalTrueLCS = new LcsStringList();
                comparator.compare(extractedOriginalDataList, extractedTrueDataList, extractedOriginalTrueLCS);
                ArrayListWrapperFactory originalTrueFactory = new ArrayListWrapperFactory(extractedOriginalTrueLCS);
                ArrayListWrapper<String> extractedOriginalTrueLcsDataList = originalTrueFactory.createArrayListWrapper(ArrayListWrapperFactory.ListType.LCS);

                int extractedOriginalSize = extractedOriginalDataList.size();
                int extractedOriginalTrueLcsSize = extractedOriginalTrueLCS.size();
                long extractedOriginalTrueCompPercent = 0;
                String extractedOriginalTrueLcsString = extractedOriginalTrueLCS.getLCSString(null);
                if (extractedOriginalSize > 0) {
                        if (extractedOriginalTrueLCS.hasSameDelimiter(extractedOriginalDataList)
                            && extractedOriginalTrueLCS.hasSameRowSize(extractedOriginalDataList)
                        ) {
                            extractedOriginalTrueCompPercent = Math.round((double) extractedOriginalTrueLcsSize / extractedOriginalSize * 1000);
                        } else {

                            LcsStringList originalAndTrueLcs = new LcsStringList();
                            extractedOriginalTrueCompPercent = comparator.compare(extractedOriginalDataList, extractedOriginalTrueLcsDataList, originalAndTrueLcs);
                            extractedOriginalTrueLcsString = originalAndTrueLcs.getLCSString(null);
                            LOGGER4J.debug("originalAndTrueLcs[" + printableString.convert(originalAndTrueLcs.getLCSString(null), PRINTVALUEMAXLEN) + "]");
                            LOGGER4J.debug("original[" + printableString.convert(originalFalseLCSs[i].getDiffAString(null), PRINTVALUEMAXLEN) + "]");
                        }
                }

                LOGGER4J.debug("ParamName["
                        + trueParamName
                        + "] value["
                        + printableString.convert(trueValue, PRINTVALUEMAXLEN)
                        + "] extractedOriginalTrueCompPercent["
                        + extractedOriginalTrueCompPercent
                        + "]"
                );

                //3-1. Extracted original true response is the same as  extracted original response and extracted true response does not exist in false response
                if (extractedOriginalTrueCompPercent >= this.NEALYEQUALPERCENT
                        && !trueHasSQLError
                        && extractedOriginalTrueLCS.size()>0
                        && trueFalsePercent < this.NEALYDIFFERPERCENT){
                    LOGGER4J.debug("bingo 3-1.extractedOriginalTrueCompPercent["
                            + extractedOriginalTrueCompPercent
                            + "]>="
                            + this.NEALYEQUALPERCENT
                    );
                    if (DEBUGBINGO != null) {
                        LOGGER4J.log(DEBUGBINGO, "extractedOriginalTrueLCS[" + printableString.convert(extractedOriginalTrueLcsString, PRINTVALUEMAXLEN) + "]");
                        String normalData = normalBodyOutputs[i];
                        String trueData = trueBodyOutputs[i];
                        String falseData = falseBodyOutputs[i];
                        String normalDataPath = ExtensionAscanRules.ZAPHOME_DIR + "NORMALDATA.txt";
                        String trueDataPath = ExtensionAscanRules.ZAPHOME_DIR + "TRUEDATA.txt";
                        String falseDataPath = ExtensionAscanRules.ZAPHOME_DIR + "FALSEDATA.txt";
                        try {
                            FileWriterPlus normalWriter = new FileWriterPlus(normalDataPath);
                            normalWriter.print(normalData);
                            normalWriter.close();
                            FileWriterPlus trueWriter = new FileWriterPlus(trueDataPath);
                            trueWriter.print(trueData);
                            trueWriter.close();
                            FileWriterPlus falseWriter = new FileWriterPlus(falseDataPath);
                            falseWriter.print(falseData);
                            falseWriter.close();
                        } catch (Exception ex) {
                            LOGGER4J.error(ex.getMessage(), ex);
                        }
                    }
                    String evidence = Constant.messages.getString(MESSAGE_PREFIX + "alert.booleanbased.extractedOriginalTrueLCS.evidence");
                    raiseAlertBooleanBased(Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, i > 0 ? true : false, truemessage, origParamName, trueParamName, trueValue, falseParamName, falseValue, null, evidence);
                    sqlInjectionFoundForUrl = true;
                    break LOOPTRUE;
                }


                LcsStringList extractedTrueAndFalseLcs = new LcsStringList();
                int extractedTrueFalsePercent  = comparator.compare(extractedOriginalTrueLcsDataList, falseBodyOutputs[i], extractedTrueAndFalseLcs);
                String extractedTrueAndFalseLcsString = extractedTrueAndFalseLcs.getLCSString(null);

                // 3-2. Extracted true response contains part of the extracted original response
                if (!extractedOriginalTrueLcsString.isEmpty()
                        && !trueHasSQLError
                        && extractedTrueFalsePercent < this.ALMOSTDIFFERPERCENT
                        && !almostSameSize(trueAverageResponseSize, falseAverageResponseSize)
                ){
                    boolean bingoFailed = false;
                    if (!Utilities.hasAlphaNumberChars(extractedOriginalTrueLcsString)) {
                        bingoFailed = true;
                    }


                    if (!bingoFailed) {
                        LOGGER4J.debug("bingo 3-2.extractedTrueFalsePercent["
                                + extractedTrueFalsePercent
                                + "]<"
                                + this.ALMOSTDIFFERPERCENT
                                + " normalTruePercent:" + normalTruePercent
                                + " normalFalsePercent:" + normalFalsePercent
                                + " trueFalsePercent:" + trueFalsePercent
                                + " extractedOriginalTrueLcs length:" + extractedOriginalTrueLcsString.length()
                                + " extractedTrueAndFalseLcs length:" + extractedTrueAndFalseLcsString.length()

                        );
                        if (DEBUGBINGO != null) {
                            LOGGER4J.log(DEBUGBINGO, "extractedOriginalTrueLCSComp[" + printableString.convert(extractedOriginalTrueLcsString, PRINTVALUEMAXLEN) + "]");
                            String normalData = normalBodyOutputs[i];
                            String trueData = trueBodyOutputs[i];
                            String falseData = falseBodyOutputs[i];
                            String lcsDataPath = ExtensionAscanRules.ZAPHOME_DIR + "LCS.txt";
                            String normalDataPath = ExtensionAscanRules.ZAPHOME_DIR + "NORMALDATA.txt";
                            String trueDataPath = ExtensionAscanRules.ZAPHOME_DIR + "TRUEDATA.txt";
                            String falseDataPath = ExtensionAscanRules.ZAPHOME_DIR + "FALSEDATA.txt";
                            try {
                                FileWriterPlus normalWriter = new FileWriterPlus(normalDataPath);
                                normalWriter.print(normalData);
                                normalWriter.close();
                                FileWriterPlus trueWriter = new FileWriterPlus(trueDataPath);
                                trueWriter.print(trueData);
                                trueWriter.close();
                                FileWriterPlus falseWriter = new FileWriterPlus(falseDataPath);
                                falseWriter.print(falseData);
                                falseWriter.close();
                                FileWriterPlus lcsWriter = new FileWriterPlus(lcsDataPath);
                                lcsWriter.print(extractedOriginalTrueLcsString);
                                lcsWriter.close();
                            } catch (Exception ex) {
                                LOGGER4J.error(ex.getMessage(), ex);
                            }
                        }
                        String evidence = Constant.messages.getString(MESSAGE_PREFIX + "alert.booleanbased.extractedOriginalTrueSmallLCS.evidence");
                        raiseAlertBooleanBased(Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, i > 0 ? true : false, truemessage, origParamName, trueParamName, trueValue, falseParamName, falseValue, null, evidence);
                        sqlInjectionFoundForUrl = true;
                        break LOOPTRUE;
                    }
                }

                // 4-1. error response has SQL error messages.
                String errorParamName = origParamName;
                if (tfrpattern.errorValuePattern != null && !tfrpattern.errorValuePattern.isEmpty()) {
                    errorParamName = origParamName + (tfrpattern.errorNamePattern != null ? tfrpattern.errorNamePattern : "");
                    String errorValue = origParamValue + tfrpattern.errorValuePattern;
                    if (errorBodyOutputs == null) {

                        errormessage = sendRequestAndCalcLCS(comparator, errorParamName, errorValue, scannerId, selectedScanRule, pauseActionObject, waitTimerObject);
                        if (errormessage == null) continue;
                        errorBodyOutputs = getUnstrippedStrippedResponse(errormessage, errorValue, null);
                    }

                    String ext1FoundErrorMsg = "";
                    if ((ext1FoundErrorMsg = hasSQLErrors(errorBodyOutputs[i])) != null){
                        errorHasSQLError = true;
                        LOGGER4J.debug("4-1. bingo");
                        String evidence = Constant.messages.getString(MESSAGE_PREFIX + "alert.booleanbased.errorHasSQLError.evidence");
                        raiseAlertErrorBased(Alert.RISK_MEDIUM, Alert.CONFIDENCE_MEDIUM, i > 0 ? true : false, truemessage,origParamName, null, null, null, null, errorParamName, errorValue, evidence, ext1FoundErrorMsg);
                    }
                }

                // 4-2 false response has SQL error messages
                String ext1FoundErrorMsg = "";
                if ((ext1FoundErrorMsg = hasSQLErrors(falseBodyOutputs[i])) != null){
                    falseHasSQLError = true;
                    LOGGER4J.debug("4-2. bingo");
                    String evidence = Constant.messages.getString(MESSAGE_PREFIX + "alert.booleanbased.falseHasSQLError.evidence");
                    raiseAlertErrorBased(Alert.RISK_MEDIUM, Alert.CONFIDENCE_MEDIUM, i > 0 ? true : false, truemessage,origParamName, null, null, falseParamName, falseValue, null, null, evidence, ext1FoundErrorMsg);
                }
                if (isStop()) {
                    LOGGER4J.info("scan stopped by user request");
                    return;
                }
            }
            if (isStop()) {
                LOGGER4J.info("scan stopped by user request");
                return;
            }
        }
    }

    private void scanByPenTestRule(HttpMessage msg, String origParamName, String origParamValue, int scannerId, CustomScanJSONData.ScanRule selectedScanRule, PauseActionObject pauseActionObject, WaitTimerObject waitTimerObject) {
        LOGGER4J.debug("start scanByPenTestRule");

        List<InjectionPatterns.TrueFalsePattern> patterns = selectedScanRule.patterns.patterns;

        for(Iterator<InjectionPatterns.TrueFalsePattern> it = patterns.iterator(); it.hasNext();) {
            InjectionPatterns.TrueFalsePattern tfrpattern = it.next();
            String injectedParamValue = origParamValue + tfrpattern.trueValuePattern;
            HttpMessage resultMessage = sendOneMessage(origParamName, injectedParamValue, scannerId, pauseActionObject, waitTimerObject, selectedScanRule);
        }
    }

    private void addSendResultToScanLogPanel(HttpMessage resultMessage, CustomScanJSONData.ScanRule selectedScanRule) {
        // search regex pattern in response result message
        if (resultMessage != null && scanLogPanelFrame != null) {
            // get baseColumn data : "Time", "Method", "URL", "Code", "Reason", "Length"
            // extract "Time" String from response header
            String timeString = "";
            HttpResponseHeader httpResponseHeader = resultMessage.getResponseHeader();
            String dateString = httpResponseHeader.getHeader("Date");
            if (dateString != null && !dateString.isEmpty()) {
                SimpleDateFormat simpleDateFormat = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss z", Locale.US);
                try {
                    Date responseDate = simpleDateFormat.parse(dateString);
                    SimpleDateFormat defaultDateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
                    timeString = defaultDateFormat.format(responseDate);
                } catch (ParseException ex) {
                    LOGGER4J.error(ex.getMessage(), ex);
                }
            }
            // extract "Method" String from request header
            HttpRequestHeader httpRequestHeader = resultMessage.getRequestHeader();
            String methodString = httpRequestHeader.getMethod();

            // extract URL string from request header
            org.apache.commons.httpclient.URI uri = httpRequestHeader.getURI();
            String urlString = "";
            try {
                urlString = uri.getURI();
            } catch (URIException e) {
                LOGGER4J.error(e.getMessage(), e);
            }

            // get Status 3 digit code
            int statusCode = httpResponseHeader.getStatusCode();
            String statusCodeString = Integer.toString(statusCode);

            // get Reason code
            String reasonCodeString = httpResponseHeader.getReasonPhrase();

            // get length
            int contentLength = httpResponseHeader.getContentLength();
            String contentLengthString = Integer.toString(contentLength);

            String entireResponseString = resultMessage.getResponseHeader().toString() + resultMessage.getResponseBody().toString();
            List<String> resultRecord = new ArrayList<>();
            resultRecord.add(timeString);
            resultRecord.add(methodString);
            resultRecord.add(urlString);
            resultRecord.add(statusCodeString);
            resultRecord.add(reasonCodeString);
            resultRecord.add(contentLengthString);

            for (String flagItem : selectedScanRule.flagResultItems) {
                Pattern compiledRegex = Pattern.compile(flagItem);
                Matcher m = compiledRegex.matcher(entireResponseString);
                int foundCount = 0;
                while (m.find()) {
                    foundCount++;
                }
                resultRecord.add(Integer.toString(foundCount));
            }

            String[] resultRecordArray = resultRecord.toArray(new String[0]);
            ScanLogPanel scanLogPanel = scanLogPanelFrame.getScanLogPanel();
            if (scanLogPanel != null) {
                scanLogPanel.addRowToScanLogTableModel(resultRecordArray, resultMessage);
            }
        }
    }

    @Override
    // must be unique in https://github.com/zaproxy/zaproxy/blob/develop/docs/scanners.md
    public int getId() {
        return 40037;
    }

    @Override
    // must be unique in all plugins.
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX+ "name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    @Override
    public boolean targets(TechSet technologies) {
        if (technologies.includes(Tech.Db)) {
            return true;
        }

        for (Tech tech : technologies.getIncludeTech()) {
            if (tech.getParent() == Tech.Db) {
                return true;
            }
        }
        return false;
    }

    @Override
    public int getCweId() {
        return 89;
    }

    @Override
    public int getWascId() {
        return 19;
    }

    // int NealyEqualPercent = 950;// 95 %
    int getNealyEqualPercent(){
        int nepercent = 950;//default
        String per = "";
        try{
            per = Constant.messages.getString(MESSAGE_PREFIX + "nealyequalpercent");
            if(per!=null&&per.length()>0){
                int nper = Integer.parseInt(per);
                if(nper>0){
                    nepercent = nper;
                }
            }
        }catch(Exception e){
            LOGGER4J.debug(MESSAGE_PREFIX + "nealyequalpercent:" + per );
        }
        return nepercent;
    }


    //private int NealyDifferPercent = 751;// 75.1%
    int getNealyDifferPercent(){
        int nepercent = 751;//default
        String per = "";
        try{
            per = Constant.messages.getString(MESSAGE_PREFIX + "nealydifferpercent");
            if(per!=null&&per.length()>0){
                int nper = Integer.parseInt(per);
                if(nper>0){
                    nepercent = nper;
                }
            }
        }catch(Exception e){
            LOGGER4J.debug(MESSAGE_PREFIX + "nealydifferpercent:" + per );
        }
        return nepercent;
    }

    /**
     * Replace body by stripping of pattern string. The URLencoded pattern will
     * also be stripped off. The URL decoded pattern will not be stripped off,
     * as this is not necessary of rour purposes, and causes issues when
     * attempting to decode parameter values such as '%' (a single percent
     * character) This is mainly used for stripping off a testing string in HTTP
     * response for comparison against the original response. Reference:
     * TestInjectionSQL
     *
     * this code derived from org/zaproxy/zap/extension/ascanrules/TestSQLInjection.java
     *
     * @author 70pointer
     *
     * @param body
     * @param pattern
     *
     * @return
     */
    protected String stripOff(String body, String pattern) {
        if (pattern == null) {
            return body;
        }

        String urlEncodePattern = getURLEncode(pattern);
        String htmlEncodePattern1 = getHTMLEncode(pattern);
        String htmlEncodePattern2 = getHTMLEncode(urlEncodePattern);
        String result = body.replaceAll("\\Q" + pattern + "\\E", "").replaceAll("\\Q" + urlEncodePattern + "\\E", "");
        result = result.replaceAll("\\Q" + htmlEncodePattern1 + "\\E", "").replaceAll("\\Q" + htmlEncodePattern2 + "\\E", "");
        return result;
    }

    /**
     * Replace body by stripping off pattern strings.
     *
     * this code derived from org/zaproxy/zap/extension/ascanrules/TestSQLInjection.java
     *
     * @author 70pointer
     */
    protected String stripOffOriginalAndAttackParam(String body, String originalPattern, String attackPattern) {
        String result = this.stripOff(
                this.stripOff(
                        body,
                        attackPattern),
                originalPattern);
        return result;
    }

    /**
     *  send same two request with specified parameter, then calculate two response's LCS(Longest Common Sequence).
     * because same 2 request's response  have differences which contains CSRF token or something random value. By Extract the LCS from 2 request's response,
     * It can remove CSRF token or random's from response.
     *
     * @param comparator
     * @param origParamName
     * @param paramValue
     * @return
     */
    HttpMessageWithLCSResponse sendRequestAndCalcLCS(LcsStringListComparator comparator, String origParamName, String paramValue, int scannerId, CustomScanJSONData.ScanRule selectedScanRule, PauseActionObject pauseActionObject, WaitTimerObject waitTimerObject) {
        String[] res = new String[2];
        res[0]=null; res[1] = null;
        HttpMessage msg2 = null;
        HttpMessageWithLCSResponse msg2withlcs = null;
        String lcsResponse = "";

        for(int cn = 0 ; cn<2; cn++) {
            msg2 = getNewMsg();
            if(origParamName!=null&&paramValue!=null) {
                setParameter(msg2, origParamName, paramValue);
            }

            // wait until specified MSec passed
            waitTimerObject.waitUntilSpecifiedTimePassed(selectedScanRule);
            // take pause Action before sending message.
            pauseAction(scannerId, pauseActionObject);

            try {
                sendAndReceive(msg2, false); //do not follow redirects
                // add resultMessage to ScanLogPanel
                addSendResultToScanLogPanel(msg2, selectedScanRule);
            } catch (Exception ex) {
                LOGGER4J.error("Caught " + ex.getClass().getName() + " " + ex.getMessage() +
                        " when accessing: " + msg2.getRequestHeader().getURI().toString(), ex);
                return null;
            }
            res[cn] =  maskRandomIdsFromResponseString(msg2);
        }

        int originalAverageResponseSize = -1;
        if(res[0]!=null&&res[1]!=null) {
            originalAverageResponseSize = (res[0].length() + res[1].length())/2;// calcurate average size from 2 responses.
            LcsStringList clcs = new LcsStringList();
            comparator.extractLCS(res[0], res[1], clcs);
            lcsResponse = clcs.getLCSString(null);
            lcsResponse = lcsResponse == null ? "" : lcsResponse;
        }

        if (msg2 != null) {
            msg2withlcs = new HttpMessageWithLCSResponse(msg2, lcsResponse, originalAverageResponseSize);
        }

        return msg2withlcs;
    }

    /**
     * get Unstripped and Stripped(removed origParamValue and attackPattern) Response bodies from message
     *
     * @param message
     * @param origParamValue
     * @param attackPattern
     * @return
     */
    String[] getUnstrippedStrippedResponse(HttpMessageWithLCSResponse message, String origParamValue, String attackPattern) {
        String resBodyUnstripped = message.getLCSResponse();
        String resBodyStripped;
        if (attackPattern!=null && !attackPattern.isEmpty()) {
            resBodyStripped = stripOffOriginalAndAttackParam(resBodyUnstripped, origParamValue, attackPattern); // omit origParamValue and attackPattern from Reponse
        } else {
            resBodyStripped = this.stripOff(resBodyUnstripped, origParamValue); // omit origParamValue from Response
        }
        String[] arraytemp = {resBodyUnstripped, resBodyStripped};

        return arraytemp;
    }

    /**
     * raise alert(bingo) when a boolean based SQL injection is detected.
     *
     * @param risk
     * @param confidence
     * @param isStripped
     * @param message
     * @param origParamName
     * @param trueParamName
     * @param trueValue
     * @param falseParamName
     * @param falseValue
     * @param errorValue
     * @param evidence
     */
    void raiseAlertBooleanBased(int risk, int confidence, boolean isStripped, HttpMessage message, String origParamName,  String trueParamName, String trueValue, String falseParamName, String falseValue, String errorValue, String evidence) {
        String extraInfo = null; // extraInfo is displayed in the pane which titled "Other info:".
        String extraTrueValue = trueValue;
        String extraFalseValue = falseValue;
        if (origParamName != null) {
            if (trueParamName != null && !origParamName.equals(trueParamName)) {
                extraTrueValue = trueParamName + "=" +trueValue;
            }
            if (falseParamName != null && !origParamName.equals(falseParamName)) {
                extraFalseValue = falseParamName + "=" + falseValue;
            }
        }
        if (isStripped) { // Stripped
            extraInfo = Constant.messages.getString(MESSAGE_PREFIX + "alert.booleanbased.extrainfo", printableString.convert(extraTrueValue, PRINTVALUEMAXLEN), printableString.convert(extraFalseValue, PRINTVALUEMAXLEN), "");
        } else { // Unstripped
            extraInfo = Constant.messages.getString(MESSAGE_PREFIX + "alert.booleanbased.extrainfo", printableString.convert(extraTrueValue, PRINTVALUEMAXLEN), printableString.convert(extraFalseValue, PRINTVALUEMAXLEN), "NOT ");
        }
        extraInfo = extraInfo + "\n" + Constant.messages.getString(MESSAGE_PREFIX + "alert.booleanbased.extrainfo.dataexists");

        //raise the alert, and save the attack string for the "Authentication Bypass" alert, if necessary
        String sqlInjectionAttack = "true[" + printableString.convert(extraTrueValue, PRINTVALUEMAXLEN) +"]false[" + printableString.convert(extraFalseValue, PRINTVALUEMAXLEN) + "]" + (errorValue == null ? "" : "error[" + printableString.convert(errorValue, PRINTVALUEMAXLEN) + "]");

        newAlert()
                .setRisk(risk)
                .setConfidence(confidence)
                .setParam(origParamName)
                .setAttack(sqlInjectionAttack)
                .setOtherInfo(extraInfo)
                .setEvidence(evidence)
                .setMessage(message)
                .raise();

    }

    /**
     * raise alert when error messages found in response contents
     *
     * @param risk
     * @param confidence
     * @param isStripped
     * @param message
     * @param origParamName
     * @param trueParamName
     * @param trueValue
     * @param falseParamName
     * @param falseValue
     * @param errorValue
     * @param evidence
     * @param ext1msg
     */
    void raiseAlertErrorBased(int risk, int confidence, boolean isStripped, HttpMessage message, String origParamName,  String trueParamName, String trueValue, String falseParamName, String falseValue, String errorParamName, String errorValue, String evidence, String ext1msg) {
        String extraInfo = null; // extraInfo is displayed in the pane which titled "Other info:".
        String testpagetype = "";
        if (errorValue != null && !errorValue.isEmpty()) {
            testpagetype = "error response";
        } else if (falseValue != null && !falseValue.isEmpty()) {
            testpagetype = "false response";
        }
        extraInfo = Constant.messages.getString(MESSAGE_PREFIX + "alert.sqlerrorbased.extrainfo", testpagetype, ext1msg);

        String extraTrueValue = printableString.convert(trueValue, PRINTVALUEMAXLEN);
        String extraFalseValue = printableString.convert(falseValue, PRINTVALUEMAXLEN);
        String extraErrorValue = printableString.convert(errorValue, PRINTVALUEMAXLEN);
        if (origParamName != null) {
            if (trueParamName != null && !origParamName.equals(trueParamName)) {
                extraTrueValue = trueParamName + "=" + trueValue;
            }
            if (falseParamName != null && !origParamName.equals(falseParamName)) {
                extraFalseValue = falseParamName + "=" + falseValue;
            }
            if (errorParamName != null && !origParamName.equals(errorParamName)) {
                extraErrorValue = errorParamName + "=" + errorValue;
            }
        }
        //raise the alert, and save the attack string for the "Authentication Bypass" alert, if necessary
        String sqlInjectionAttack = (extraTrueValue == null ? "" : "true[" + extraTrueValue + "] ")
                + (extraFalseValue == null ? "" : "false[" + extraFalseValue + "] ")
                + (extraErrorValue == null ? "" : "error[" + extraErrorValue + "]");

        newAlert()
                .setRisk(risk)
                .setConfidence(confidence)
                .setParam(origParamName)
                .setAttack(sqlInjectionAttack)
                .setOtherInfo(extraInfo)
                .setEvidence(evidence)
                .setMessage(message)
                .raise();
    }

    /**
     * mask(replace with asterisk) random ids such as CSRF token or something which is different per each request<BR>
     * and remove unnecessary response headers.<BR>
     * @param msg
     * @return
     */
    String maskRandomIdsFromResponseString(HttpMessage msg) {
        HttpResponseHeader responseHeader = msg.getResponseHeader();
        HttpResponseBody responseBody = msg.getResponseBody();
        String resBodyString = responseBody == null ? "" : responseBody.toString();
        String primeString = responseHeader.getPrimeHeader();
        List<HttpHeaderField> headerFields = responseHeader.getHeaders();
        List<HttpHeaderField> maskedHeaderFields = new ArrayList<>();

        if (headerFields != null) {
            for (HttpHeaderField headerField : headerFields) {
                String name = headerField.getName();
                String value = headerField.getValue();
                HttpHeaderField headerFieldMasked = null;
                if (name.equalsIgnoreCase("Set-Cookie")) {
                    Matcher matcher = cookieNameValuePattern.matcher(value);
                    int lastpos = 0;
                    String tail = "";
                    String valuemasked = "";
                    while (matcher.find()) {
                        int groupcount = matcher.groupCount();
                        if (groupcount > 1) {
                            int valuestartpos = matcher.start(2);
                            int valueendpos = matcher.end(2);
                            valuemasked += value.substring(lastpos, valuestartpos);
                            String cookievalue = value.substring(valuestartpos, valueendpos);
                            valuemasked += Utilities.convTokenPart2Asterisk(cookievalue);
                            lastpos = valueendpos;
                        }
                    }
                    if (value.length() > lastpos) {
                        valuemasked += value.substring(lastpos);
                    }
                    if (valuemasked.isEmpty()) {
                        valuemasked = value;
                    }
                    headerFieldMasked = new HttpHeaderField(name, valuemasked);
                } else if (!name.equalsIgnoreCase("Date")
                        && !name.equalsIgnoreCase("ETag")
                        && !name.equalsIgnoreCase("Keep-Alive")
                        && !name.equalsIgnoreCase("Connection")
                        && !name.equalsIgnoreCase("Content-Length")) {// we need to remove these headders such as Etag , Date header for improving vulnerability detection.
                    String valuemasked = value;
                    valuemasked = Utilities.convTokenPart2Asterisk(value);
                    headerFieldMasked = new HttpHeaderField(name, valuemasked);
                }
                if (headerFieldMasked != null) {
                    maskedHeaderFields.add(headerFieldMasked);
                }
            }
        }

        String maskedbody = resBodyString;
        if (isMaskBodyWithAsterisk) {
            Matcher valueMatcher;
            if (responseHeader.hasContentType("json")) {
                valueMatcher = quotedValuePattern.matcher(resBodyString);
            } else {
                valueMatcher = inputTagQuotedValuePattern.matcher(resBodyString);
            }
            // masked random ids from resBodyString

            maskedbody = "";
            int lastpos = 0;
            while (valueMatcher.find()) {
                int idstartpos = valueMatcher.start(1);
                int idendpos = valueMatcher.end(1);
                String id = resBodyString.substring(idstartpos, idendpos);
                String maskedid = id;
                maskedid = Utilities.convTokenPart2Asterisk(id);
                maskedbody += resBodyString.substring(lastpos, idstartpos) + maskedid;
                lastpos = idendpos;
            }
            if (lastpos < resBodyString.length()) {
                maskedbody += resBodyString.substring(lastpos);
            }
        }

        String lineDelimiter = responseHeader.getLineDelimiter();
        String maskedResponseBody = primeString + lineDelimiter;

        for (HttpHeaderField maskedHeaderField : maskedHeaderFields) {
            String n = maskedHeaderField.getName();
            String v = maskedHeaderField.getValue();
            maskedResponseBody += n + ": " + v + lineDelimiter;
        }
        maskedResponseBody += lineDelimiter + maskedbody;

        return maskedResponseBody;
    }

    /**
     * find msg contain sql error messages.
     *
     * @param msg
     * @return String - found error, null - not found error
     */
    String hasSQLErrors(String msg) {
        Matcher m = sqlErrorPattern.matcher(msg);
        if (m.find()) {
            int sts = m.start();
            int ets = m.end();
            String foundMsg = msg.substring(sts, ets);
            return foundMsg;
        }
        return null;
    }

    HttpMessage sendOneMessage(String origParamName, String paramValue, int scannerId, PauseActionObject pauseActionObject, WaitTimerObject waitTimerObject, CustomScanJSONData.ScanRule selectedScanRule) {

        // wait until specified MSec passed
        waitTimerObject.waitUntilSpecifiedTimePassed(selectedScanRule);
        // take pause Action before sending message.
        pauseAction(scannerId, pauseActionObject);

        HttpMessage msg2 = getNewMsg();
        if(origParamName!=null&&paramValue!=null) {
            setParameter(msg2, origParamName, paramValue);
        }

        try {
            LOGGER4J.debug("sending message.");
            sendAndReceive(msg2, false); //do not follow redirects
            // add resultMessage to ScanLogPanel
            addSendResultToScanLogPanel(msg2, selectedScanRule);
        } catch (Exception ex) {
            LOGGER4J.error("Caught " + ex.getClass().getName() + " " + ex.getMessage() +
                    " when accessing: " + msg2.getRequestHeader().getURI().toString(), ex);
            return null;
        }

        return msg2;
    }

    void pauseAction(int scannerId, PauseActionObject pauseActionObject) {
        if (pauseActionObject != null) {
            if (pauseActionObject.isCounterDecrementable()) {
                if (pauseActionObject.decrementCounter() <= 0) {
                    ScanLogPanelFrame scanLogPanelFrame = ExtensionAscanRules.scannerIdScanLogFrameMap.get(scannerId);
                    if (scanLogPanelFrame != null) {
                        ScanLogPanel scanLogPanel = scanLogPanelFrame.getScanLogPanel();
                        if (scanLogPanel != null) {
                            try {
                                SwingUtilities.invokeAndWait(new Runnable() {
                                    @Override
                                    public void run() {
                                        if (scanLogPanel.setSelectedPauseAction(scannerId, true)) {
                                            scanLogPanel.setSelectedPauseCheckBox(true, true);
                                        }
                                    }
                                });
                            }catch(Exception ex) {
                                LOGGER4J.error(ex.getMessage(), ex);
                            }
                        }
                    }
                }
            }
            Thread th = null;
            synchronized (pauseActionObject) {
                th = ExtensionAscanRules.scannerIdThreadMap.get(scannerId);
            }
            if (th != null) {
                pauseActionObject.terminate();
                if (th.isAlive() && th.getState() == Thread.State.WAITING) {// join if thread is alive, then join until thread is terminated.
                    try {
                        LOGGER4J.debug("Thread id[" + th.getId() + "] join started");
                        th.join();
                        ScanLogPanelFrame scanLogPanelFrame = ExtensionAscanRules.scannerIdScanLogFrameMap.get(scannerId);
                        if (scanLogPanelFrame != null) {
                            scanLogPanelFrame.updateRequestCounter(-1);
                        }
                    } catch (InterruptedException e) {
                        LOGGER4J.error(e.getMessage(), e);
                    }
                    LOGGER4J.debug("Thread id[" + th.getId() + "] join ended.");
                } else {
                    pauseActionObject.notifyAll();
                }
                ExtensionAscanRules.scannerIdThreadMap.remove(scannerId);// forget everything about thread.
            }
        }
    }

    /**
     * Returns true if two size is almost same length.
     * @param aSize
     * @param bSize
     * @return
     */
    private boolean almostSameSize(int aSize, int bSize) {
        int denominatorSize = bSize;
        int numeratorSize = aSize;
        if (aSize > bSize) {
            denominatorSize = aSize;
            numeratorSize = bSize;
        }

        if (denominatorSize == 0) {
            if (numeratorSize == 0) return true;
            return false;
        }
        long percent = Math.round((double) numeratorSize / denominatorSize * 1000);
        if (percent >= this.NEALYEQUALPERCENT) return true;

        return false;
    }
}
