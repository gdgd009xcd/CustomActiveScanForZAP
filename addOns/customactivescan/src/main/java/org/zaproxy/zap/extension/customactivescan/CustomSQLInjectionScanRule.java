package org.zaproxy.zap.extension.customactivescan;

import org.apache.logging.log4j.Level;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.*;
import org.parosproxy.paros.network.*;
import org.zaproxy.zap.extension.ascan.ActiveScan;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.customactivescan.model.*;
import org.zaproxy.zap.extension.customactivescan.view.ScanLogPanel;
import org.zaproxy.zap.extension.customactivescan.view.ScanLogPanelFrame;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.network.HttpResponseBody;

import javax.swing.*;
import java.lang.reflect.InvocationTargetException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.zaproxy.zap.extension.customactivescan.DecoderTag.getDecodedStringList;

/**
 * this is special custmizable SQL injection logic test.
 *
 * @author gdgd009xcd
 *
 */
public class CustomSQLInjectionScanRule extends AbstractAppParamPlugin {

    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    ParmGenMacroTraceParams traceParams = null;

    final Level DEBUGBINGO = Level.getLevel("DEBUGBINGO");
    private final int PRINTVALUEMAXLEN = 255; // max length of debug print string.
    private PrintableString printableString = null;

    private int NEALYEQUALPERCENT; // If this value or more(value >= NEALYEQUALPECENT), it is considered to match
    private int NEALYDIFFERPERCENT; // If less than this value(value < NEALYDIFFERPECENT), it is considered as a mismatch
    private int ALMOSTDIFFERPERCENT; // if less than this value, it is considered as almost diffrerent each other.

    private int MAXMASKBODYSIZE = 100000000; // If response body size is larger than this size, do not apply the asterisk conversion to the body
    private boolean isMaskBodyWithAsterisk;

    private int MINWORDLEN = 5; // if extractedOriginalTrueLCS.size < MINWORDLEN then compare extractedOriginalTrueString and extractedFalseString

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

        traceParams = null;
        isMaskBodyWithAsterisk = false;

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
            HostProcess hPro = null;
            if (hostProcessList != null) {
                int hostProcessIndex = hostProcessList.indexOf(hProcess);
                if (hostProcessIndex != -1) {
                    hPro = hostProcessList.get(hostProcessIndex);
                }
            }
            if (hPro == hProcess) {
                scannerId = ascan.getId();
                ExtensionAscanRules.hostProcessScannerIdMap.put(hProcess, scannerId);
                WaitTimerObject waitTimerObject = new WaitTimerObject();
                ExtensionAscanRules.scannerIdWaitTimerMap.put(scannerId, waitTimerObject);
                if (selectedScanRule.getDoScanLogOutput()) {
                    final int finalScannerId = scannerId;
                    try {

                        SwingUtilities.invokeAndWait(new Runnable() {
                            @Override
                            public void run() {
                                ScanLogPanelFrame frame = new ScanLogPanelFrame(flagResultItemArray, finalScannerId);
                                ExtensionAscanRules.registerScanLogPanelFrame(finalScannerId, frame);
                                ascan.addScannerListener(new CustomScannerListener());
                                frame.updateRequestCounter(0);
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
                break;
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
    public void scan(HttpMessage msg, NameValuePair originalParam) {
        CustomScanJSONData.ScanRule selectedScanRule = ExtensionAscanRules.customScanMainPanel.getSelectedScanRule();
        int scannerId = ExtensionAscanRules.hostProcessScannerIdMap.get(getParent());
        PauseActionObject pauseActionObject = ExtensionAscanRules.scannerIdPauseActionMap.get(scannerId);
        WaitTimerObject waitTimerObject = ExtensionAscanRules.scannerIdWaitTimerMap.get(scannerId);
        LOGGER4J.debug("scan start scannerId:" + scannerId);
        try {
            switch (selectedScanRule.ruleType) {
                case SQL:
                    scanBySQLRule(
                            msg,
                            originalParam,
                            scannerId,
                            selectedScanRule,
                            pauseActionObject,
                            waitTimerObject);
                    break;
                case PenTest:
                    scanByPenTestRule(
                            msg,
                            originalParam,
                            scannerId,
                            selectedScanRule,
                            pauseActionObject,
                            waitTimerObject);
                    break;
                default:
                    break;
            }
        } catch (Exception ex) {
            LOGGER4J.error(ex.getMessage(), ex);
        }
    }

    private void scanBySQLRule(
            HttpMessage msg,
            NameValuePair originalParam,
            int scannerId,
            CustomScanJSONData.ScanRule selectedScanRule,
            PauseActionObject pauseActionObject,
            WaitTimerObject waitTimerObject) throws Exception{
        String origParamName = originalParam.getName();
        String origParamValue = originalParam.getValue();
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

        HttpMessageWithLCSResponse normalMessage = sendRequestAndCalcLCS(
                comparator,
                ModifyType.Add,
                originalParam,
                null,
                null,
                scannerId,
                selectedScanRule,
                pauseActionObject,
                waitTimerObject,
                AttackTitleType.Original,
                "[" + origParamValue + "]");
        if(normalMessage==null)return;
        normalMessage.setPercentString("");
        updateScanLogPanel(scannerId,normalMessage, originalParam, origParamName,-1,null, selectedScanRule);
        String[] normalBodyOutputs = getUnstrippedStrippedResponse(normalMessage, origParamValue, null);
        int injectionPatternGroupIndex = 0;

        boolean hasJsonBodyInRequest = false;
        HttpRequestHeader requestHeader = msg.getRequestHeader();
        if (requestHeader.hasContentType("json")) {
            hasJsonBodyInRequest = true;
        }
        LOOPTRUE: for(Iterator<InjectionPatterns.TrueFalsePattern> it = patterns.iterator(); it.hasNext() && !sqlInjectionFoundForUrl; injectionPatternGroupIndex++) {
            InjectionPatterns.TrueFalsePattern tfrpattern = it.next();

            if (!hasJsonBodyInRequest && tfrpattern.modifyType == ModifyType.JSON) {// skip JSON test if request body Content-Type is NOT json.
                continue;
            }

            // 1. Original response matches true condition
            String patternValue = tfrpattern.trueValuePattern;
            String trueValue = origParamValue + tfrpattern.trueValuePattern;
            if (tfrpattern.modifyType != ModifyType.Add) {
                trueValue = tfrpattern.trueValuePattern;
            }
            String trueParamName = origParamName + (tfrpattern.trueNamePattern != null ? tfrpattern.trueNamePattern : "");
            HttpMessageWithLCSResponse trueMessage = sendRequestAndCalcLCS(
                    comparator,
                    tfrpattern.modifyType,
                    originalParam,
                    trueParamName,
                    patternValue,
                    scannerId,
                    selectedScanRule,
                    pauseActionObject,
                    waitTimerObject,
                    AttackTitleType.True,
                    "[" + trueValue +"]");
            int trueAverageResponseSize = trueMessage.getOriginalAverageResponseSize();
            int trueResponseStatus = trueMessage.getWorstResponseStatus();
            if (trueMessage == null) continue;

            String[] trueBodyOutputs = getUnstrippedStrippedResponse(trueMessage, trueValue, null);
            LcsStringList[] originalTrueLCSs = {new LcsStringList(), new LcsStringList()};
            LcsStringList[] originalFalseLCSs = {new LcsStringList(), new LcsStringList()};
            LcsStringList[] errorLCSs = {new LcsStringList(), new LcsStringList()};

            String falseValue = null;
            String falseParamName = null;
            String[] falseBodyOutputs = null;
            String[] errorBodyOutputs = null;
            HttpMessageWithLCSResponse errorMessage = null;
            HttpMessageWithLCSResponse falseMessage = null;
            boolean bingoError = false;

            int falseAverageResponseSize = -1;

            for(int i=0;i<2;i++) {
                boolean trueHasSQLError = false;
                boolean falseHasSQLError = false;
                boolean errorHasSQLError = false;
                // 1. compare true and original/false
                int normalTruePercent = comparator.compare(normalBodyOutputs[i] , trueBodyOutputs[i], originalTrueLCSs[i]);
                if (i==0) {
                    updateScanLogPanel(scannerId, trueMessage, originalParam, trueParamName,originalTrueLCSs[i].getBpercent(), originalTrueLCSs[i].getCharacterPositionListOfLcsIdxDiffB(), selectedScanRule);
                }
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
                        patternValue = tfrpattern.falseValuePattern;
                        falseValue = origParamValue + tfrpattern.falseValuePattern;
                        if (tfrpattern.modifyType != ModifyType.Add) {
                            falseValue = tfrpattern.falseValuePattern;
                        }
                        falseParamName = origParamName + (tfrpattern.falseNamePattern != null ? tfrpattern.falseNamePattern : "");
                        falseMessage = sendRequestAndCalcLCS(
                                comparator,
                                tfrpattern.modifyType,
                                originalParam,
                                falseParamName,
                                patternValue,
                                scannerId,
                                selectedScanRule,
                                pauseActionObject,
                                waitTimerObject,
                                AttackTitleType.False,
                                "[" + falseValue + "]");
                        falseAverageResponseSize = falseMessage.getOriginalAverageResponseSize();
                        if (falseMessage == null) continue;
                        falseBodyOutputs = getUnstrippedStrippedResponse(falseMessage, falseValue, null);
                    }
                    normalFalsePercent = comparator.compare(normalBodyOutputs[i], falseBodyOutputs[i], originalFalseLCSs[i]);

                    if (i==0) {
                        updateScanLogPanel(scannerId, falseMessage, originalParam, falseParamName,originalFalseLCSs[i].getBpercent() ,originalFalseLCSs[i].getCharacterPositionListOfLcsIdxDiffB(), selectedScanRule);
                    }
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
                        String evidence = Constant.messages.getString("customactivescan.testsqlinjection.alert.booleanbased.trueequaloriginal.evidence");
                        Alert alert = raiseAlertBooleanBased(
                                Alert.RISK_HIGH,
                                Alert.CONFIDENCE_MEDIUM,
                                i > 0 ? true : false,
                                trueMessage,
                                origParamName,
                                trueParamName,
                                trueValue,
                                falseParamName,
                                falseValue,
                                null,
                                evidence);
                        // Modify the message in ScanLogPanel to display SQL injection results.
                        updateLcsInfoForScanLogPanel(
                                alert,
                                comparator,
                                normalMessage,
                                normalBodyOutputs[i],
                                trueMessage,
                                trueBodyOutputs[i],
                                falseMessage,
                                falseBodyOutputs[i],
                                originalTrueLCSs[i],
                                originalFalseLCSs[i]);
                        sqlInjectionFoundForUrl = true;
                        break LOOPTRUE;
                    }
                }

                if (falseBodyOutputs == null) {
                    falseValue = origParamValue + tfrpattern.falseValuePattern;
                    patternValue = tfrpattern.falseValuePattern;
                    if (tfrpattern.modifyType != ModifyType.Add) {
                        falseValue = tfrpattern.falseValuePattern;
                    }
                    falseParamName = origParamName + (tfrpattern.falseNamePattern != null ? tfrpattern.falseNamePattern : "");
                    falseMessage = sendRequestAndCalcLCS(
                            comparator,
                            tfrpattern.modifyType,
                            originalParam,
                            falseParamName,
                            patternValue,
                            scannerId,
                            selectedScanRule,
                            pauseActionObject,
                            waitTimerObject,
                            AttackTitleType.False,
                            "[" + falseValue + "]");
                    falseAverageResponseSize = falseMessage.getOriginalAverageResponseSize();
                    if (falseMessage == null) continue;
                    falseBodyOutputs = getUnstrippedStrippedResponse(falseMessage, falseValue, null);

                }

                if (normalFalsePercent == -1) {
                    normalFalsePercent = comparator.compare(normalBodyOutputs[i], falseBodyOutputs[i], originalFalseLCSs[i]);
                    if (i==0) {
                        updateScanLogPanel(scannerId, falseMessage, originalParam, falseParamName,originalFalseLCSs[i].getBpercent(),originalFalseLCSs[i].getCharacterPositionListOfLcsIdxDiffB(), selectedScanRule);
                    }
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
                    String evidence = Constant.messages.getString("customactivescan.testsqlinjection.alert.booleanbased.extractedOriginalTrueLCS.evidence");
                    Alert alert = raiseAlertBooleanBased(
                            Alert.RISK_HIGH,
                            Alert.CONFIDENCE_MEDIUM,
                            i > 0 ? true : false,
                            trueMessage,
                            origParamName,
                            trueParamName,
                            trueValue,
                            falseParamName,
                            falseValue,
                            null,
                            evidence);
                    updateLcsInfoForScanLogPanel(
                            alert,
                            comparator,
                            normalMessage,
                            normalBodyOutputs[i],
                            trueMessage,
                            trueBodyOutputs[i],
                            falseMessage,
                            falseBodyOutputs[i],
                            originalTrueLCSs[i],
                            originalFalseLCSs[i]);
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
                        && trueResponseStatus < 400
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
                        String evidence = Constant.messages.getString("customactivescan.testsqlinjection.alert.booleanbased.extractedOriginalTrueSmallLCS.evidence");
                        Alert alert = raiseAlertBooleanBased(
                                Alert.RISK_HIGH,
                                Alert.CONFIDENCE_MEDIUM,
                                i > 0 ? true : false,
                                trueMessage,
                                origParamName,
                                trueParamName,
                                trueValue,
                                falseParamName,
                                falseValue,
                                null,
                                evidence);
                        updateLcsInfoForScanLogPanel(
                                alert,
                                comparator,
                                normalMessage,
                                normalBodyOutputs[i],
                                trueMessage,
                                trueBodyOutputs[i],
                                falseMessage,
                                falseBodyOutputs[i],
                                originalTrueLCSs[i],
                                originalFalseLCSs[i]);
                        sqlInjectionFoundForUrl = true;
                        break LOOPTRUE;
                    }
                }

                // 4-1. error response has SQL error messages.
                String errorParamName = origParamName;
                if (tfrpattern.errorValuePattern != null && !tfrpattern.errorValuePattern.isEmpty()) {
                    errorParamName = origParamName + (tfrpattern.errorNamePattern != null ? tfrpattern.errorNamePattern : "");
                    patternValue = tfrpattern.errorValuePattern;
                    String errorValue = origParamValue + tfrpattern.errorValuePattern;
                    if (tfrpattern.modifyType != ModifyType.Add) {
                        errorValue = tfrpattern.errorValuePattern;
                    }
                    if (errorBodyOutputs == null) {
                        errorMessage = sendRequestAndCalcLCS(
                                comparator,
                                tfrpattern.modifyType,
                                originalParam,
                                errorParamName,
                                patternValue,
                                scannerId,
                                selectedScanRule,
                                pauseActionObject,
                                waitTimerObject,
                                AttackTitleType.Error,
                                "[" + errorValue + "]");
                        if (errorMessage == null) continue;
                        errorBodyOutputs = getUnstrippedStrippedResponse(errorMessage, errorValue, null);
                    }

                    String ext1FoundErrorMsg = "";
                    if ((ext1FoundErrorMsg = hasSQLErrors(errorBodyOutputs[i])) != null){
                        errorHasSQLError = true;
                        LOGGER4J.debug("4-1. bingo");
                        String evidence = Constant.messages.getString("customactivescan.testsqlinjection.alert.booleanbased.errorHasSQLError.evidence");
                        Alert alert = raiseAlertErrorBased(Alert.RISK_MEDIUM, Alert.CONFIDENCE_MEDIUM, i > 0 ? true : false, trueMessage,origParamName, null, null, null, null, errorParamName, errorValue, evidence, ext1FoundErrorMsg);
                    }
                }

                // 4-2 false response has SQL error messages
                String ext1FoundErrorMsg = "";
                if ((ext1FoundErrorMsg = hasSQLErrors(falseBodyOutputs[i])) != null){
                    falseHasSQLError = true;
                    LOGGER4J.debug("4-2. bingo");
                    String evidence = Constant.messages.getString("customactivescan.testsqlinjection.alert.booleanbased.falseHasSQLError.evidence");
                    Alert alert = raiseAlertErrorBased(Alert.RISK_MEDIUM, Alert.CONFIDENCE_MEDIUM, i > 0 ? true : false, trueMessage,origParamName, null, null, falseParamName, falseValue, null, null, evidence, ext1FoundErrorMsg);
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

    private void scanByPenTestRule(HttpMessage msg,
                                   NameValuePair nameValuePair,
                                   int scannerId,
                                   CustomScanJSONData.ScanRule selectedScanRule,
                                   PauseActionObject pauseActionObject,
                                   WaitTimerObject waitTimerObject) {
        LOGGER4J.debug("start scanByPenTestRule");
        String origParamName = nameValuePair.getName();
        String origParamValue = nameValuePair.getValue();

        List<InjectionPatterns.TrueFalsePattern> patterns = selectedScanRule.patterns.patterns;

        for(Iterator<InjectionPatterns.TrueFalsePattern> it = patterns.iterator(); it.hasNext();) {
            InjectionPatterns.TrueFalsePattern tfrpattern = it.next();
            String patternValue = tfrpattern.trueValuePattern;

            HttpMessage resultMessage = sendOneMessage(
                    tfrpattern.modifyType,
                    nameValuePair,
                    origParamName,
                    patternValue,
                    scannerId,
                    pauseActionObject,
                    waitTimerObject,
                    selectedScanRule,
                    AttackTitleType.PenTest
                    );
        }
    }

    /**
     * add result message to ScanLogPanel
     * @param resultMessage
     * @param selectedScanRule
     * @return size of ScanLogPanel.resultMessageList
     */
    private int addSendResultToScanLogPanel(
            int scannerId,
            HttpMessageWithLCSResponse resultMessage,
            NameValuePair nameValuePair,
            String paramName,
            CustomScanJSONData.ScanRule selectedScanRule,
            StartEndPosition userDefinedStartEnd) {
        ScanLogPanelFrame frame = ExtensionAscanRules.getScanLogPanelFrame(scannerId);
        if (frame != null) {
            ScanLogPanel scanLogPanel = frame.getScanLogPanel();
            if (scanLogPanel != null) {
                return scanLogPanel.addMessageToScanLogTableModel(
                        resultMessage,
                        nameValuePair,
                        paramName,
                        selectedScanRule,
                        userDefinedStartEnd);
            }
        }
        return -1;
    }

    /**
     * update ScanLogTableModel with resultMessage
     * @param resultMessage
     * @param selectedScanRule
     * @return index of resultMessage in ScanLogPanel.resultMessageList
     */
    private int updateScanLogPanel(int scannerId, HttpMessageWithLCSResponse resultMessage, NameValuePair nameValuePair, String paramName,int percent,List<StartEndPosition> lcsCharIndexOfResponseBody, CustomScanJSONData.ScanRule selectedScanRule) {
        ScanLogPanelFrame frame = ExtensionAscanRules.getScanLogPanelFrame(scannerId);
        if (frame != null) {
            ScanLogPanel scanLogPanel = frame.getScanLogPanel();
            if (scanLogPanel != null) {
                if (percent > -1) {
                    resultMessage.setPercentString(Integer.toString(percent / 10));
                }
                if (lcsCharIndexOfResponseBody != null &&  !lcsCharIndexOfResponseBody.isEmpty()) {
                    resultMessage.setLcsCharacterIndexOfLcsResponse(lcsCharIndexOfResponseBody);
                }
                return scanLogPanel.updateScanLogTableModelWithResultMessage(resultMessage, nameValuePair, paramName, selectedScanRule);
            }
        }
        return -1;
    }

    @Override
    // must be unique in https://github.com/zaproxy/zaproxy/blob/develop/docs/scanners.md
    public int getId() {
        return 40037;
    }

    @Override
    // must be unique in all plugins.
    public String getName() {
        return Constant.messages.getString("customactivescan.testsqlinjection.name.text");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("customactivescan.testsqlinjection.desc.text");
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString("customactivescan.testsqlinjection.soln.text");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString("customactivescan.testsqlinjection.refs.text");
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
            per = Constant.messages.getString("customactivescan.testsqlinjection.nealyequalpercent");
            if(per!=null&&per.length()>0){
                int nper = Integer.parseInt(per);
                if(nper>0){
                    nepercent = nper;
                }
            }
        }catch(Exception e){
            LOGGER4J.debug("customactivescan.testsqlinjection.nealyequalpercent:" + per );
        }
        return nepercent;
    }


    //private int NealyDifferPercent = 751;// 75.1%
    int getNealyDifferPercent(){
        int nepercent = 751;//default
        String per = "";
        try{
            per = Constant.messages.getString("customactivescan.testsqlinjection.nealydifferpercent");
            if(per!=null&&per.length()>0){
                int nper = Integer.parseInt(per);
                if(nper>0){
                    nepercent = nper;
                }
            }
        }catch(Exception e){
            LOGGER4J.debug("customactivescan.testsqlinjection.nealydifferpercent:" + per );
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
     *      * because same 2 request's response  have differences which contains CSRF token or something random value. By Extract the LCS from 2 request's response,
     *      * It can remove CSRF token or random's from response.
     * @param comparator
     * @param origParamName
     * @param patternValue
     * @param scannerId
     * @param selectedScanRule
     * @param pauseActionObject
     * @param waitTimerObject
     * @param lastPartOfTitleString
     * @return
     */
    HttpMessageWithLCSResponse sendRequestAndCalcLCS(
            LcsStringListComparator comparator,
            ModifyType modifyType,
            NameValuePair nameValuePair,
            String origParamName,
            String patternValue,
            int scannerId,
            CustomScanJSONData.ScanRule selectedScanRule,
            PauseActionObject pauseActionObject,
            WaitTimerObject waitTimerObject,
            AttackTitleType attackTitleType,
            String lastPartOfTitleString) {

        String[] res = new String[2];
        res[0]=null; res[1] = null;
        HttpMessage msg2 = getNewMsg();
        if (selectedScanRule.isConvertURLdecodedValue()
                && patternValue != null) {
            patternValue = patternValue.replace("+", "%2b");
        }

        HttpMessageWithLCSResponse msg2withlcs = null;
        String lcsResponse = "";

        int worstResponseStatus = -1;

        StartEndPosition userDefinedStartEnd = null;
        boolean userDefinedPositionIsOutOfRangeInDecoderTags = false;
        if (nameValuePair.getType() == NameValuePair.TYPE_UNDEFINED) {
            HttpMessageWithLCSResponse httpMessageWithLCSResponse = new HttpMessageWithLCSResponse(msg2);
            userDefinedStartEnd = httpMessageWithLCSResponse.getUserDefinedNameValuePairStartEnd(nameValuePair);
            userDefinedPositionIsOutOfRangeInDecoderTags = httpMessageWithLCSResponse.isUserDefinedPositionOutOfDecoderTagsRange(userDefinedStartEnd);
        }
        for(int cn = 0 ; cn<2; cn++) {
            msg2 = getNewMsg();

            if (patternValue != null) {
                setPatternToHttpMessage(
                        modifyType,
                        selectedScanRule,
                        origParamName,
                        msg2,
                        nameValuePair,
                        patternValue,
                        userDefinedPositionIsOutOfRangeInDecoderTags);
            }

            // wait until specified MSec passed
            waitTimerObject.waitUntilSpecifiedTimePassed(selectedScanRule);
            // take pause Action before sending message.
            pauseAction(scannerId, pauseActionObject);

            try {
                sendAndReceive(msg2, false); //do not follow redirects
                // add resultMessage to ScanLogPanel

                HttpResponseHeader responseHeader = msg2.getResponseHeader();
                int digit3 = responseHeader.getStatusCode();
                if (digit3 > worstResponseStatus) {
                    worstResponseStatus = digit3;
                }
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
            msg2withlcs = new HttpMessageWithLCSResponse(
                    msg2,
                    lcsResponse,
                    worstResponseStatus,
                    originalAverageResponseSize,
                    attackTitleType,
                    attackTitleType.name() + lastPartOfTitleString);
            addSendResultToScanLogPanel(
                    scannerId,
                    msg2withlcs,
                    nameValuePair,
                    origParamName,
                    selectedScanRule,
                    userDefinedStartEnd);
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
     * @return Alert - copy of raised alert.
     */
    Alert raiseAlertBooleanBased(int risk, int confidence, boolean isStripped, HttpMessage message, String origParamName,  String trueParamName, String trueValue, String falseParamName, String falseValue, String errorValue, String evidence) {
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
            extraInfo = Constant.messages.getString("customactivescan.testsqlinjection.alert.booleanbased.extrainfo.text", printableString.convert(extraTrueValue, PRINTVALUEMAXLEN), printableString.convert(extraFalseValue, PRINTVALUEMAXLEN), "");
        } else { // Unstripped
            extraInfo = Constant.messages.getString("customactivescan.testsqlinjection.alert.booleanbased.extrainfo.text", printableString.convert(extraTrueValue, PRINTVALUEMAXLEN), printableString.convert(extraFalseValue, PRINTVALUEMAXLEN), "NOT ");
        }
        extraInfo = extraInfo + "\n" + Constant.messages.getString("customactivescan.testsqlinjection.alert.booleanbased.extrainfo.dataexists.text");

        //raise the alert, and save the attack string for the "Authentication Bypass" alert, if necessary
        String sqlInjectionAttack = "true[" + printableString.convert(extraTrueValue, PRINTVALUEMAXLEN) +"]false[" + printableString.convert(extraFalseValue, PRINTVALUEMAXLEN) + "]" + (errorValue == null ? "" : "error[" + printableString.convert(errorValue, PRINTVALUEMAXLEN) + "]");

        AlertBuilder builder = newAlert()
                .setRisk(risk)
                .setConfidence(confidence)
                .setParam(origParamName)
                .setAttack(sqlInjectionAttack)
                .setOtherInfo(extraInfo)
                .setEvidence(evidence)
                .setMessage(message);

        builder.raise();

        return builder.build();
    }

    /**
     * raise alert when error messages found in response contents
     * @param risk
     * @param confidence
     * @param isStripped
     * @param message
     * @param origParamName
     * @param trueParamName
     * @param trueValue
     * @param falseParamName
     * @param falseValue
     * @param errorParamName
     * @param errorValue
     * @param evidence
     * @param ext1msg
     * @return Alert - copy of alert
     */
    Alert raiseAlertErrorBased(int risk, int confidence, boolean isStripped, HttpMessage message, String origParamName,  String trueParamName, String trueValue, String falseParamName, String falseValue, String errorParamName, String errorValue, String evidence, String ext1msg) {
        String extraInfo = null; // extraInfo is displayed in the pane which titled "Other info:".
        String testpagetype = "";
        if (errorValue != null && !errorValue.isEmpty()) {
            testpagetype = "error response";
        } else if (falseValue != null && !falseValue.isEmpty()) {
            testpagetype = "false response";
        }
        extraInfo = Constant.messages.getString("customactivescan.testsqlinjection.alert.sqlerrorbased.extrainfo", testpagetype, ext1msg);

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

        AlertBuilder builder = newAlert()
                .setRisk(risk)
                .setConfidence(confidence)
                .setParam(origParamName)
                .setAttack(sqlInjectionAttack)
                .setOtherInfo(extraInfo)
                .setEvidence(evidence)
                .setMessage(message);

        builder.raise();

        return builder.build();
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

    HttpMessage sendOneMessage(
            ModifyType modifyType,
            NameValuePair nameValuePair,
            String origParamName,
            String patternValue,
            int scannerId,
            PauseActionObject pauseActionObject,
            WaitTimerObject waitTimerObject,
            CustomScanJSONData.ScanRule selectedScanRule,
            AttackTitleType attackTitleType) {

        // wait until specified MSec passed
        waitTimerObject.waitUntilSpecifiedTimePassed(selectedScanRule);
        // take pause Action before sending message.
        pauseAction(scannerId, pauseActionObject);

        HttpMessage msg2 = getNewMsg();

        boolean userDefinedPositionIsOutOfRangeInDecoderTags = false;
        StartEndPosition userDefinedStartEnd = null;
        if (nameValuePair.getType() == NameValuePair.TYPE_UNDEFINED) {
            HttpMessageWithLCSResponse httpMessageWithLCSResponse = new HttpMessageWithLCSResponse(msg2);
            userDefinedStartEnd = httpMessageWithLCSResponse.getUserDefinedNameValuePairStartEnd(nameValuePair);
            userDefinedPositionIsOutOfRangeInDecoderTags = httpMessageWithLCSResponse.isUserDefinedPositionOutOfDecoderTagsRange(userDefinedStartEnd);
        }

        if (patternValue != null) {
            if (selectedScanRule.isConvertURLdecodedValue()) {
                patternValue = patternValue.replace("+", "%2b");
            }
            setPatternToHttpMessage(
                    modifyType,
                    selectedScanRule,
                    origParamName,
                    msg2,
                    nameValuePair,
                    patternValue,
                    userDefinedPositionIsOutOfRangeInDecoderTags);
        }


        try {
            LOGGER4J.debug("sending message.");
            sendAndReceive(msg2, false); //do not follow redirects
            // add resultMessage to ScanLogPanel
            HttpMessageWithLCSResponse httpMessageWithLCSResponse = new HttpMessageWithLCSResponse(msg2, attackTitleType);
            addSendResultToScanLogPanel(
                    scannerId,
                    httpMessageWithLCSResponse,
                    nameValuePair,
                    origParamName,selectedScanRule,
                    userDefinedStartEnd);
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
                    ScanLogPanelFrame scanLogPanelFrame = ExtensionAscanRules.getScanLogPanelFrame(scannerId);
                    if (scanLogPanelFrame != null) {
                        if(!scanLogPanelFrame.isDisposed()) {// if isDisposed return true,
                            // ScanLogPanelFrame has been destroyed. So cancel the pauseAction.
                            ScanLogPanel scanLogPanel = scanLogPanelFrame.getScanLogPanel();
                            if (scanLogPanel != null) {
                                try {
                                    SwingUtilities.invokeAndWait(new Runnable() {
                                        @Override
                                        public void run() {
                                            // set Paused button label and create New waiting thread.
                                            if (scanLogPanel.setSelectedPauseAction(scannerId, true)) {
                                                scanLogPanel.setSelectedPauseCheckBox(true, true);
                                            }
                                        }
                                    });
                                } catch (Exception ex) {
                                    LOGGER4J.error(ex.getMessage(), ex);
                                }
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
                        LOGGER4J.debug("Thread id[" + Utilities.getThreadId(th) + "] join started");
                        th.join();
                        ScanLogPanelFrame scanLogPanelFrame = ExtensionAscanRules.getScanLogPanelFrame(scannerId);
                        if (scanLogPanelFrame != null) {
                            scanLogPanelFrame.updateRequestCounter(-1);
                        }
                    } catch (InterruptedException e) {
                        LOGGER4J.error(e.getMessage(), e);
                    }
                    LOGGER4J.debug("Thread id[" + Utilities.getThreadId(th) + "] join ended.");
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

    private void updateLcsInfoForScanLogPanel(Alert alert, LcsStringListComparator comparator,
                            HttpMessageWithLCSResponse normalMessage,
                            String normalBodyOutput,
                            HttpMessageWithLCSResponse trueMessage,
                            String trueBodyOutput,
                            HttpMessageWithLCSResponse falseMessage,
                            String falseBodyOutput,
                            LcsStringList originalTrueLCS,
                            LcsStringList originalFalseLCS) throws Exception {
        List<StartEndPosition> lcsCharIndexOfNormalBody = originalTrueLCS.getCharacterPositionListOfLcsIdxDiffA();
        List<StartEndPosition> lcsCharIndexOfTrueBody = originalTrueLCS.getCharacterPositionListOfLcsIdxDiffB();
        List<StartEndPosition> lcsCharIndexOfFalseBody = originalFalseLCS.getCharacterPositionListOfLcsIdxDiffB();
        int truePercent = originalTrueLCS.getBpercent();
        int falsePercent = originalFalseLCS.getBpercent();
        String normalBodyString = normalBodyOutput;
        String trueBodyString = trueBodyOutput;
        String falseBodyString = falseBodyOutput;

        //normalMessage.setAlert(alert);
        trueMessage.setAlert(alert);
        falseMessage.setAlert(alert);
        normalMessage.updateLcsResponse(normalBodyString);
        normalMessage.setLcsCharacterIndexOfLcsResponse(lcsCharIndexOfNormalBody);
        trueMessage.updateLcsResponse(trueBodyString);
        trueMessage.setLcsCharacterIndexOfLcsResponse(lcsCharIndexOfTrueBody);
        trueMessage.setPercentString(Integer.toString(truePercent / 10));
        falseMessage.updateLcsResponse(falseBodyString);
        falseMessage.setLcsCharacterIndexOfLcsResponse(lcsCharIndexOfFalseBody);
        falseMessage.setPercentString(Integer.toString(falsePercent / 10));

        String originalRequestString = normalMessage.getRequestHeader().toString() + normalMessage.getRequestBody().toString();
        String trueRequestString = trueMessage.getRequestHeader().toString() + trueMessage.getRequestBody().toString();
        String falseRequestString = falseMessage.getRequestHeader().toString() + falseMessage.getRequestBody().toString();
        LcsStringList originalTrueRequestResult = new LcsStringList();
        LcsStringList originalFalseRequestResult = new LcsStringList();
        if(originalRequestString.length()< 3000) {
            comparator.compareStringByChar(originalRequestString, trueRequestString, originalTrueRequestResult);
            comparator.compareStringByChar(originalRequestString, falseRequestString, originalFalseRequestResult);
        } else {
            comparator.compare(originalRequestString, trueRequestString, originalTrueRequestResult);
            comparator.compare(originalRequestString, falseRequestString, originalFalseRequestResult);
        }
        List<StartEndPosition> lcsCharIndexOfNormalRequest = originalTrueRequestResult.getCharacterPositionListOfLcsIdxDiffA();
        List<StartEndPosition> lcsCharIndexOfTrueRequest = originalTrueRequestResult.getCharacterPositionListOfLcsIdxDiffB();

        List<StartEndPosition> lcsCharIndexOfFalseRequest = originalFalseRequestResult.getCharacterPositionListOfLcsIdxDiffB();
        normalMessage.setLcsCharacterIndexOfLcsRequest(lcsCharIndexOfNormalRequest);
        trueMessage.setLcsCharacterIndexOfLcsRequest(lcsCharIndexOfTrueRequest);
        falseMessage.setLcsCharacterIndexOfLcsRequest(lcsCharIndexOfFalseRequest);
    }


    private java.nio.charset.Charset getDecodeCharsetFromNameValuePair(NameValuePair nameValuePair) {
        java.nio.charset.Charset decodeCharSet = StandardCharsets.ISO_8859_1;
        switch(nameValuePair.getType()){
            case NameValuePair.TYPE_URL_PATH:
                // special URLencode for URL_PATH
                // solution: newValue = encodeUTF8 originalValue + encodeISO8859_1 patternValue
                // and use setEscapedParameter
                break;
            case NameValuePair.TYPE_QUERY_STRING:
                // UTF-8 encode
                // hardcoded value is UTF-8 in org.parosproxy.paros.core.scanner.AbstractPlugin::getURLEncode
                // solution: newValue = encodeUTF8 originalValue + encodeISO8859_1 patternValue
                // and use setEscapedParameter
                decodeCharSet = StandardCharsets.UTF_8;
                break;
            case NameValuePair.TYPE_COOKIE:
                // UTF-8 encode
                // solution: newValue = encodeUTF8 originalValue + encodeISO8859_1 patternValue
                // and use setEscapedParameter
                break;
            case NameValuePair.TYPE_HEADER:
                // non-encode, but this Type has not capable to handle byte data.
                // solution: use ordinary setParameter .
                break;
            case NameValuePair.TYPE_POST_DATA:
                // UTF-8 encode
                // hardcoded value is UTF-8 in org.parosproxy.paros.core.scanner.AbstractPlugin::getURLEncode
                // solution: newValue = encodeUTF8 originalValue + encodeISO8859_1 patternValue
                // and use setEscapedParameter
                decodeCharSet = StandardCharsets.UTF_8;
                break;
            case NameValuePair.TYPE_MULTIPART_DATA_PARAM:// non-file param
                // solution: use byte data of request body.
                // 1) set dummy string to value, and call ordinary setParameter.
                // 2) use getBytes() for getting body bytes.
                // 3) get position of dummy string by searching dummy string in body as binary data.
                // 4) replace dummy string to raw value with using it's position.
                break;
            case NameValuePair.TYPE_MULTIPART_DATA_FILE_PARAM:// file content
                // solution: same as above.
                break;
            case NameValuePair.TYPE_MULTIPART_DATA_FILE_NAME:// file name
                // this Type cannot handle byte data.
                // solution: use ordinary setParameter .
                break;
            case NameValuePair.TYPE_MULTIPART_DATA_FILE_CONTENTTYPE:// content-type
                // this Type cannot handle byte data.
                // solution: use ordinary setParameter .
                break;
            case NameValuePair.TYPE_JSON:
                //String escapeSafeChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%()=~|-^`{}*_?@[]:;/.,";
                // double quoted
                // whether it is escaped or not , always it applied StringEscapeUtils.escapeJava(value)
                // solution: use byte data of request body.
                // 1) set dummy string to value, and call ordinary setParameter.
                // 2) use getBytes() for getting body bytes.
                // 3) get position of dummy string by searching dummy string in body as binary data.
                // 4) replace dummy string to escapedJava value with using it's position.
                break;
            case NameValuePair.TYPE_GRAPHQL_INLINE:// inline arguments in GRAPH QL
                //String escapeSafeChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%()=~|-^`{}*_?@[]:;/.,";
                // solution: use above steps.
                // StringEscapeUtils.escapeXml11(value)
                break;
            case NameValuePair.TYPE_UNDEFINED:

                break;
            default:
                break;
        }
        return decodeCharSet;
    }

    /**
     * set Parameter to httpMessage
     *
     * @param modifyType
     * @param selectedScanRule
     * @param paramName
     * @param httpMessage
     * @param nameValuePair
     * @param patternValue
     */
    private void setPatternToHttpMessage(
            ModifyType modifyType,
            CustomScanJSONData.ScanRule selectedScanRule,
            String paramName,
            HttpMessage httpMessage,
            NameValuePair nameValuePair,
            String patternValue,
            boolean userDefinedPositionIsOutOfRangeInDecoderTags) {

        String originalValue = nameValuePair.getValue();
        if (modifyType != ModifyType.Add) {
            originalValue = "";
        }
        boolean isConvertURLDecodedValue = selectedScanRule.isConvertURLdecodedValue();
        switch(nameValuePair.getType()){
            case NameValuePair.TYPE_URL_PATH:
                // special URLencode for URL_PATH
                // solution: newValue = encodeUTF8 originalValue + encodeISO8859_1 patternValue
                // and use setEscapedParameter
                if (isConvertURLDecodedValue) {
                    setEscapedParameter(httpMessage, paramName, getEscapedParamValueUTF8(originalValue, patternValue));
                } else {
                    setParameter(httpMessage, paramName, originalValue + patternValue);
                }
                break;
            case NameValuePair.TYPE_QUERY_STRING:
                // UTF-8 encode
                // hardcoded value is UTF-8 in org.parosproxy.paros.core.scanner.AbstractPlugin::getURLEncode
                // solution: newValue = encodeUTF8 originalValue + encodeISO8859_1 patternValue
                // and use setEscapedParameter
                if (isConvertURLDecodedValue) {
                    setEscapedParameter(httpMessage, paramName, getEscapedParamValueUTF8(originalValue, patternValue));
                } else {
                    setParameter(httpMessage, paramName, originalValue + patternValue);
                }
                break;
            case NameValuePair.TYPE_COOKIE:
                // UTF-8 encode
                // solution: newValue = encodeUTF8 originalValue + encodeISO8859_1 patternValue
                // and use setEscapedParameter
                if (isConvertURLDecodedValue) {
                    setEscapedParameter(httpMessage, paramName, getEscapedParamValueUTF8(originalValue, patternValue));
                } else {
                    setParameter(httpMessage, paramName, originalValue + patternValue);
                }
                break;
            case NameValuePair.TYPE_HEADER:
                // non-encode, but this Type has not capable to handle byte data.
                if(isConvertURLDecodedValue) {
                    // convert the portion of URLEncoded ISO8859 value to String
                    setEscapedParameter(httpMessage, paramName, originalValue + getRawParamValueUTF8(patternValue));
                } else {
                    setParameter(httpMessage, paramName, originalValue + patternValue);
                }
                break;
            case NameValuePair.TYPE_POST_DATA:
                // UTF-8 encode
                // hardcoded value is UTF-8 in org.parosproxy.paros.core.scanner.AbstractPlugin::getURLEncode
                // solution: newValue = encodeUTF8 originalValue + encodeISO8859_1 patternValue
                // and use setEscapedParameter
                if (isConvertURLDecodedValue) {
                    setEscapedParameter(httpMessage, paramName, getEscapedParamValueUTF8(originalValue, patternValue));
                } else {
                    setParameter(httpMessage, paramName, originalValue + patternValue);
                }
                break;
            case NameValuePair.TYPE_MULTIPART_DATA_PARAM:// non-file param
                embedParamValueToRequestBodyAsBytes(httpMessage, paramName, originalValue, patternValue, isConvertURLDecodedValue);
                break;
            case NameValuePair.TYPE_MULTIPART_DATA_FILE_PARAM:// file content
                embedParamValueToRequestBodyAsBytes(httpMessage, paramName, originalValue, patternValue, isConvertURLDecodedValue);
                break;
            case NameValuePair.TYPE_MULTIPART_DATA_FILE_NAME:// file name
                // this Type cannot handle byte data.
                if (isConvertURLDecodedValue) {
                    setEscapedParameter(httpMessage, paramName, originalValue + getRawParamValueUTF8(patternValue));
                } else {
                    setParameter(httpMessage, paramName, originalValue + patternValue);
                }
                break;
            case NameValuePair.TYPE_MULTIPART_DATA_FILE_CONTENTTYPE:// content-type
                // this Type cannot handle byte data.
                if (isConvertURLDecodedValue) {
                    setEscapedParameter(httpMessage, paramName, originalValue + getRawParamValueUTF8(patternValue));
                } else {
                    setParameter(httpMessage, paramName, originalValue + patternValue);
                }
                break;
            case NameValuePair.TYPE_JSON:
                // String escapeSafeChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%()=~|-^`{}*_?@[]:;/.,";
                // double quoted
                // whether it is escaped or not , always it applied StringEscapeUtils.escapeJava(value)
                // solution: use byte data of request body.
                // 1) set dummy string to value, and call ordinary setParameter.
                // 2) use getBytes() for getting body bytes.
                // 3a) get position of dummy string by searching dummy string in body as binary data.
                //    if ModifyType.JSON then apply following 3b step for removing double quotes.
                // 3b) get position of double quoted dummy string by searching those string in body as binary data
                // 4) replace founded dummy string to escapedJava value with using it's position as binary data.
                {
                    HttpMessage msg2 = getNewMsg();
                    UUID uuid = UUIDGenerator.getUUID();
                    String embedDummy = "X___" + uuid.toString() + "~~~Y";
                    setParameter(msg2, paramName, embedDummy);
                    byte[] bodyBytes = msg2.getRequestBody().getContent();
                    String charsetName = msg2.getRequestBody().getCharset();
                    Charset charset = Charset.forName(charsetName);
                    LOGGER4J.debug("embed charset:" + charset);
                    ParmGenBinUtil binBytes = new ParmGenBinUtil(originalValue.getBytes(charset));
                    if (isConvertURLDecodedValue) {
                        PartialURLDecodeISO8859_1ToBytes partialURLDecodeISO88591ToBytes = new PartialURLDecodeISO8859_1ToBytes(
                                patternValue,
                                StandardCharsets.UTF_8);
                        binBytes.concat(partialURLDecodeISO88591ToBytes.action());
                    } else {
                        binBytes.concat(patternValue.getBytes(StandardCharsets.UTF_8));
                    }
                    String quotedDummy = "\"" + embedDummy + "\"";
                    String bodyString = msg2.getRequestBody().toString();
                    String keyString = embedDummy;
                    if (bodyString != null
                            && bodyString.indexOf(quotedDummy) != -1
                            && modifyType == ModifyType.JSON) {
                        keyString = quotedDummy;
                    }
                    ReplaceByteSequence replaceByteSequence = new ReplaceByteSequence(
                            bodyBytes,
                            keyString.getBytes(StandardCharsets.UTF_8),
                            binBytes.getBytes());
                    byte[] outputBodyBytes = replaceByteSequence.action(0);
                    httpMessage.getRequestBody().setContent(outputBodyBytes);
                }
                break;
            case NameValuePair.TYPE_GRAPHQL_INLINE:// inline arguments in GRAPH QL
                // currently, no use.
                LOGGER4J.warn("TYPE_GRAPHQL_INLINE");
                if (isConvertURLDecodedValue) {
                    setEscapedParameter(httpMessage, paramName, originalValue + getRawParamValueUTF8(patternValue));
                } else {
                    setParameter(httpMessage, paramName, originalValue + patternValue);
                }
                break;
            case NameValuePair.TYPE_UNDEFINED:
                // if isNameValuePariWithInUrlEncoded is true then encode value and set value by using oridinary setParameter
                // THe isNameValuePairWithInUrlEncoded method must detect following URLencoded areas.
                //  a) URL path in primeheader http://domain.com/URL_path1/URL_path2/index.php
                //  b) The query string is placed after question mark in the primeheader.
                //  c) the value is placed in www-url-encoded body.
                // else then use TYPE_JSON steps except 3b step.
                // Hint
                // URI uri = HttpMessage.getRequestHeader().getURI();
                // String uri.getPath()
                // String uri.getQuery();
                // List<String> HttpMessage.getRequestHeader().getHeaderValues(HttpHeader.COOKIE)
                {
                    HttpMessage msg2 = getNewMsg();
                    UUID uuid = UUIDGenerator.getUUID();
                    String embedDummy = "X___" + uuid.toString() + "~~~Y";
                    setParameter(msg2, paramName, embedDummy);
                    String charsetName = msg2.getRequestBody().getCharset();
                    Charset charset = Charset.forName(charsetName);
                    LOGGER4J.debug("embed charset:" + charset);

                    boolean isURLEncoded = false;
                    org.apache.commons.httpclient.URI uri = msg2.getRequestHeader().getURI();
                    try {
                        String paths = uri.getPath();
                        if (paths != null && paths.indexOf(embedDummy) != -1) {
                            isURLEncoded = true;
                        }
                        String queries = uri.getQuery();
                        if (queries != null && queries.indexOf(embedDummy) != -1) {
                            isURLEncoded = true;
                        }
                        List<String> cookies = msg2.getRequestHeader().getHeaderValues(HttpHeader.COOKIE);
                        for(String cookie: cookies) {
                            if(cookie != null && cookie.indexOf(embedDummy) != -1) {
                                isURLEncoded = true;
                                break;
                            }
                        }
                    }catch (Exception ex) {
                    }
                    String primeHeaderWithOutCrLf = msg2.getRequestHeader().getPrimeHeader();
                    String requestHeaderStrings = msg2.getRequestHeader().getHeadersAsString();
                    String headerPartString = primeHeaderWithOutCrLf + CRLF + requestHeaderStrings + CRLF;
                    boolean insertionPointIsHeaderPart = false;
                    int headerInsertionPointOfEmbedDummy = headerPartString.indexOf(embedDummy);
                    if (headerInsertionPointOfEmbedDummy != -1){
                        insertionPointIsHeaderPart = true;
                    }

                    if (!isURLEncoded) {
                        String contentTypeValue = msg2.getRequestHeader().getHeader(HttpRequestHeader.CONTENT_TYPE);
                        if (contentTypeValue != null
                                && contentTypeValue.toUpperCase().indexOf(
                                HttpRequestHeader
                                        .FORM_URLENCODED_CONTENT_TYPE
                                        .toUpperCase()
                        ) != -1
                                && !insertionPointIsHeaderPart) {
                            isURLEncoded = true;
                        }
                    }

                    String paramValueEncoded = "";
                    String paramValueRaw = originalValue + patternValue;
                    if (isURLEncoded) {
                        if (isConvertURLDecodedValue) {
                            paramValueEncoded = getEscapedParamValueUTF8(originalValue, patternValue);
                        } else {
                            paramValueEncoded = URLEncoder.encode(originalValue + patternValue, StandardCharsets.UTF_8);
                        }
                    } else if (isConvertURLDecodedValue) {
                        paramValueRaw = originalValue + getRawParamValueUTF8(patternValue);
                    }

                    if (userDefinedPositionIsOutOfRangeInDecoderTags) {
                        isURLEncoded = false;
                    }

                    if (insertionPointIsHeaderPart) {
                        // embed position is header
                        if(isURLEncoded) {
                            setEscapedParameter(httpMessage, paramName, paramValueEncoded);
                        } else {
                            LOGGER4J.debug("paramName=" + paramName + " paramValueRaw=" + paramValueRaw);
                            setParameter(httpMessage, paramName, paramValueRaw);
                        }
                    } else {
                        // embed position is body
                        if (isURLEncoded) {
                            setEscapedParameter(httpMessage, paramName, paramValueEncoded);
                        } else {
                            byte[] bodyBytes = msg2.getRequestBody().getContent();//this decode request body with using Content-Encoding method and return it.
                            ParmGenBinUtil replaceBytes = new ParmGenBinUtil(originalValue.getBytes(charset));
                            if (isConvertURLDecodedValue) {
                                PartialURLDecodeISO8859_1ToBytes partialURLDecodeISO88591ToBytes =
                                        new PartialURLDecodeISO8859_1ToBytes(
                                                patternValue,
                                                StandardCharsets.UTF_8);
                                replaceBytes.concat(partialURLDecodeISO88591ToBytes.action());
                            } else {
                                replaceBytes.concat(patternValue.getBytes(StandardCharsets.UTF_8));
                            }
                            ReplaceByteSequence replaceByteSequence =
                                    new ReplaceByteSequence(
                                            bodyBytes,
                                            embedDummy.getBytes(StandardCharsets.UTF_8),
                                            replaceBytes.getBytes());
                            byte[] outputBodyBytes = replaceByteSequence.action(0);

                            httpMessage.getRequestBody().setContent(outputBodyBytes);// This encode specified binary with using the Content-Encoding method and set it to request body.
                        }
                    }
                }
                break;
            default:
                break;
        }
    }

    /**
     * embed parameter value which contains URL encoded value to request body.
     *
     * @param httpMessage
     * @param paramName
     * @param originalValue
     * @param patternValue
     * @param isConvertURLDecodedValue
     */
    private void embedParamValueToRequestBodyAsBytes(
            HttpMessage httpMessage,
            String paramName,
            String originalValue,
            String patternValue,
            boolean isConvertURLDecodedValue)
    {
        HttpMessage msg2 = getNewMsg();
        UUID uuid = UUIDGenerator.getUUID();
        String embedDummy = "X___" + uuid.toString() + "~~~Y";
        setParameter(msg2, paramName, embedDummy);
        byte[] bodyBytes = msg2.getRequestBody().getContent();
        String charsetName = msg2.getRequestBody().getCharset();
        Charset charset = Charset.forName(charsetName);
        LOGGER4J.debug("embed charset:" + charset);
        ParmGenBinUtil binBuffer =  new ParmGenBinUtil(originalValue.getBytes(charset));
        byte[] patternBytes = patternValue.getBytes(StandardCharsets.UTF_8);
        if (isConvertURLDecodedValue) {
            PartialURLDecodeISO8859_1ToBytes partialURLDecodeISO88591ToBytes = new PartialURLDecodeISO8859_1ToBytes(
                    patternValue,
                    StandardCharsets.UTF_8);
            patternBytes = partialURLDecodeISO88591ToBytes.action();
        }
        binBuffer.concat(patternBytes);
        ReplaceByteSequence replaceByteSequence = new ReplaceByteSequence(
                bodyBytes,
                embedDummy.getBytes(StandardCharsets.UTF_8),
                binBuffer.getBytes());
        byte[] outputBodyBytes = replaceByteSequence.action(0);
        httpMessage.getRequestBody().setContent(outputBodyBytes);
    }

    private String getEscapedParamValueUTF8(String originalValue, String patternValue) {
        String originalValueEncoded = "";
        if(!originalValue.isEmpty()) {
            originalValueEncoded = URLEncoder.encode(originalValue, StandardCharsets.UTF_8);
        }
        PartialURLEncodeUTF8 partialURLEncodeUTF8 = new PartialURLEncodeUTF8(patternValue);
        return originalValueEncoded + partialURLEncodeUTF8.action();
    }


    private String getRawParamValueUTF8(String patternValue) {
        PartialURLDecodeISO8859_1 partialURLDecodeISO88591 = new PartialURLDecodeISO8859_1(patternValue);
        return partialURLDecodeISO88591.action();
    }


    public void hello(String mess, Integer i) {
        LOGGER4J.info("ScanRule hello mess:" + mess + " i=" + i.toString());
    }

}
