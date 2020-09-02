package org.zaproxy.zap.extension.customactivescan;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

import java.util.Iterator;
import java.util.List;

/**
 * this is special custmizable SQL injection logic test.
 *
 */
public class CustomSQLInjectionLogic extends AbstractAppParamPlugin {

    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    private int NEALYEQUALPERCENT; // If this value or more(value >= NEALYEQUALPECENT), it is considered to match
    private int NEALYDIFFERPERCENT; // If less than this value(value < NEALYDIFFERPECENT), it is considered as a mismatch

    private static final String MESSAGE_PREFIX = "customactivescan.testsqlinjection.";

    private List<InjectionPatterns.TrueFalsePattern> patterns;

    private HttpMessage refreshedmessage = null;
    private String mResBodyNormalUnstripped = null;
    private String mResBodyNormalStripped = null;


    @Override
    public void init() {
        super.init();

        LoadGsonInjectionPatterns gsonloader = new LoadGsonInjectionPatterns("/mnt/oldroot/home/daike/Document/Samples/Patterns/injection.txt");
        this.patterns = gsonloader.getPatternList();

        this.NEALYEQUALPERCENT = getNealyEqualPercent();
        this.NEALYDIFFERPERCENT = getNealyDifferPercent();

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
    }

    @Override
    public void scan(HttpMessage msg, String origParamName, String origParamValue) {

        boolean sqlInjectionFoundForUrl = false;

        LcsStringListComparator comparator = new LcsStringListComparator();

        refreshedmessage = sendRequestAndCalcLCS(comparator, null, null);
        if(refreshedmessage==null)return;

        String[] normalBodyOutputs = getUnstrippedStrippedResponse(refreshedmessage, origParamValue, null);

        LOOPTRUE: for(Iterator<InjectionPatterns.TrueFalsePattern> it = this.patterns.iterator(); it.hasNext() && !sqlInjectionFoundForUrl;) {
            InjectionPatterns.TrueFalsePattern tfrpattern = it.next();

            // 1. Original response matches true condition
            String trueValue = origParamValue + tfrpattern.truepattern;
            HttpMessage truemessage = sendRequestAndCalcLCS(comparator, origParamName, trueValue);
            if (truemessage == null) continue;

            String[] trueBodyOutputs = getUnstrippedStrippedResponse(truemessage, origParamValue, tfrpattern.truepattern);
            LcsStringList[] trueLCSs = {new LcsStringList(), new LcsStringList()};
            LcsStringList[] falseLCSs = {new LcsStringList(), new LcsStringList()};
            LcsStringList[] errorLCSs = {new LcsStringList(), new LcsStringList()};

            String falseValue = null;
            String[] falseBodyOutputs = null;
            String[] errorBodyOutputs = null;
            HttpMessage errormessage = null;
            boolean bingoError = false;

            for(int i=0;i<2;i++) {
                int truepercent = comparator.compare(normalBodyOutputs[i] , trueBodyOutputs[i], trueLCSs[i]);
                int falsepercent = -1;
                // 1-1.true response matched original response
                if (LOGGER4J.isDebugEnabled()) {
                    String debugmess = "origParamName["
                            + origParamName
                            + "] value["
                            + trueValue
                            + "] truepercent["
                            + truepercent
                            + "]"
                            + (truepercent >= this.NEALYEQUALPERCENT ? ">=" : "<")
                            + "NEALYEQUALPERCENT["
                            + this.NEALYEQUALPERCENT
                            + "]";
                    LOGGER4J.debug(debugmess);
                }
                if (truepercent >= this.NEALYEQUALPERCENT) {

                    if (falseBodyOutputs == null) {
                        falseValue = origParamValue + tfrpattern.falsepattern;
                        HttpMessage falsemessage = sendRequestAndCalcLCS(comparator, origParamName, falseValue);
                        if (falsemessage == null) continue;
                        falseBodyOutputs = getUnstrippedStrippedResponse(falsemessage, origParamValue, tfrpattern.falsepattern);
                    }
                    falsepercent = comparator.compare(normalBodyOutputs[i], falseBodyOutputs[i], falseLCSs[i]);
                    LOGGER4J.debug("origParamName["
                            + origParamName
                            + "] value["
                            + falseValue
                            + "] falsepercent["
                            + falsepercent
                            + "]"
                            + (falsepercent < this.NEALYDIFFERPERCENT ? "<" : ">=")
                            + "NEALYDIFFERPERCENT["
                            + this.NEALYDIFFERPERCENT
                            + "]");
                    // 1-2. original response is diffrent from false response.
                    if (falsepercent < this.NEALYDIFFERPERCENT) {
                        // bingo.
                        LOGGER4J.debug("bingo 1-1.truepercent["
                                + truepercent
                                + "]>="
                                + this.NEALYEQUALPERCENT
                                + " 1-2.falsepercent["
                                + falsepercent + "<" + this.NEALYDIFFERPERCENT);
                        String evidence = Constant.messages.getString(MESSAGE_PREFIX + "alert.booleanbased.trueequaloriginal.evidence");
                        raiseAlertBooleanBased(Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, i > 0 ? true : false, truemessage,origParamName, trueValue, falseValue, null, evidence);
                        sqlInjectionFoundForUrl = true;
                        break LOOPTRUE;
                    }
                }
                // 2-1. LCS(Longest Common Sequence) of true and original  matched oririnal response.
                //     that means true response contains original.
                int truecontainoriginalpercent = comparator.compare(trueLCSs[i].getLCSString(), normalBodyOutputs[i] , null);
                LOGGER4J.debug("origParamName["
                        + origParamName
                        + "] value["
                        + trueValue
                        + "] truecontainoriginalpercent["
                        + truecontainoriginalpercent
                        + "]"
                        + (truecontainoriginalpercent >= this.NEALYEQUALPERCENT ? ">=" : "<")
                        + "NEALYEQUALPERCENT["
                        + this.NEALYEQUALPERCENT
                        + "]"
                        + " trueLCS.length="
                        + (trueLCSs[i].getLCSString() == null ? "0(null)" : trueLCSs[i].getLCSString().length())
                        + " normalBodyOutput.lenght=" +  (normalBodyOutputs[i] == null ? "0(null)" : normalBodyOutputs[i].length()));
                if (truecontainoriginalpercent >= this.NEALYEQUALPERCENT) {
                    if (falseBodyOutputs == null) {
                        falseValue = origParamValue + tfrpattern.falsepattern;
                        HttpMessage falsemessage = sendRequestAndCalcLCS(comparator, origParamName, falseValue);
                        if (falsemessage == null) continue;
                        falseBodyOutputs = getUnstrippedStrippedResponse(falsemessage, origParamValue, tfrpattern.falsepattern);

                    }

                    if (falsepercent == -1) {
                        falsepercent = comparator.compare(normalBodyOutputs[i], falseBodyOutputs[i], falseLCSs[i]);
                    }
                    LOGGER4J.debug("origParamName["
                            + origParamName
                            + "] value["
                            + falseValue
                            + "] falsepercent["
                            + falsepercent
                            + "]"
                            + (falsepercent < this.NEALYDIFFERPERCENT ? "<" : ">=")
                            + "NEALYDIFFERPERCENT["
                            + this.NEALYDIFFERPERCENT
                            + "]");
                    // 2-2. original response is diffrent from false response.
                    if (falsepercent < this.NEALYDIFFERPERCENT) {
                        // bingo.
                        LOGGER4J.debug("bingo 2-1.truecontainoriginalpercent["
                                + truecontainoriginalpercent
                                + "]>="
                                + this.NEALYEQUALPERCENT
                                + "\n 2-2.falsepercent["
                                + falsepercent + "<" + this.NEALYDIFFERPERCENT);
                        String evidence = Constant.messages.getString(MESSAGE_PREFIX + "alert.booleanbased.truecontainoriginal.evidence");
                        raiseAlertBooleanBased(Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, i > 0 ? true : false, truemessage,origParamName, trueValue, falseValue, null,evidence);
                        sqlInjectionFoundForUrl = true;
                        break LOOPTRUE;
                    }
                }

                if (falseBodyOutputs == null) {
                    falseValue = origParamValue + tfrpattern.falsepattern;
                    HttpMessage falsemessage = sendRequestAndCalcLCS(comparator, origParamName, falseValue);
                    if (falsemessage == null) continue;
                    falseBodyOutputs = getUnstrippedStrippedResponse(falsemessage, origParamValue, tfrpattern.falsepattern);
                }

                LcsStringList truefalseLCS = new LcsStringList();
                int truefalsepercent = comparator.compare(trueBodyOutputs[i], falseBodyOutputs[i], truefalseLCS);
                LOGGER4J.debug("origParamName["
                        + origParamName
                        + "] values true["
                        + trueValue
                        + "]false["
                        + falseValue
                        + "] truefalsepercent["
                        + truefalsepercent
                        + "]"
                        + (truefalsepercent < this.NEALYDIFFERPERCENT ? "<" : ">=")
                        + "NEALYDIFFERPERCENT["
                        + this.NEALYDIFFERPERCENT
                        + "]");
                // 3-1. LCS of true and false matched false
                //    that means true response contains false response but has not same contents.
                int truecontainsfalsepercent = comparator.compare(truefalseLCS.getLCSString(), falseBodyOutputs[i], null);
                LOGGER4J.debug("origParamName["
                        + origParamName
                        + "] values true["
                        + trueValue
                        + "]false["
                        + falseValue
                        + "] truecontainsfalsepercent["
                        + truecontainsfalsepercent
                        + "]"
                        + (truecontainsfalsepercent >= this.NEALYEQUALPERCENT ? ">=" : "<")
                        + "NEALYEQUALPERCENT["
                        + this.NEALYEQUALPERCENT
                        + "]");
                if (truecontainsfalsepercent >= this.NEALYEQUALPERCENT && truefalsepercent < this.NEALYDIFFERPERCENT) {

                    if (falsepercent == -1) {
                        falsepercent = comparator.compare(normalBodyOutputs[i], falseBodyOutputs[i], falseLCSs[i]);
                    }

                    // 3-2.  LCS of original and false  matched false
                    //    that means original response contains false response but has not same contents.
                    int normalcontainsfalsepercent = comparator.compare(falseLCSs[i].getLCSString(), falseBodyOutputs[i], null);
                    if ( normalcontainsfalsepercent >= this.NEALYEQUALPERCENT
                            && falsepercent < this.NEALYDIFFERPERCENT
                            && trueBodyOutputs[i].length() > normalBodyOutputs[i].length()) {
                            //bingo
                            LOGGER4J.debug("bingo 3-1. truecontainsfalsepercent["
                                    + truecontainsfalsepercent + "]>="
                                    + this.NEALYEQUALPERCENT
                                    + " and truefalsepercent["
                                    + truefalsepercent + "]<" + this.NEALYDIFFERPERCENT
                                    + "\n 3-2.normalcontainsfalsepercent[" + normalcontainsfalsepercent
                                    + "]>="
                                    + this.NEALYEQUALPERCENT
                                    + " and falsepercent["
                                    + falsepercent
                                    + "]<"
                                    + this.NEALYDIFFERPERCENT
                                    + " and trueBodyOutputs.length["
                                    + trueBodyOutputs[i].length()
                                    + "] > "
                                    + "normalBodyOutputs.length[" + normalBodyOutputs[i].length() + "]");
                            String evidence = Constant.messages.getString(MESSAGE_PREFIX + "alert.booleanbased.truecontainfalsebody.evidence");
                            raiseAlertBooleanBased(Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, i > 0 ? true : false, truemessage,origParamName, trueValue, falseValue, null, evidence);
                            sqlInjectionFoundForUrl = true;
                            break LOOPTRUE;
                    }
                }

                // 4-1. If original matches true condition and false condition but does not match error condition, SQL injection may be possible.
                if (tfrpattern.errorpattern != null && !tfrpattern.errorpattern.isEmpty()) {
                    if (truepercent >= this.NEALYEQUALPERCENT
                            && truefalsepercent >= this.NEALYEQUALPERCENT) {
                        String errorValue = origParamValue + tfrpattern.errorpattern;
                        if (errorBodyOutputs == null) {
                            errormessage = sendRequestAndCalcLCS(comparator, origParamName, errorValue);
                            if (errormessage == null) continue;
                            errorBodyOutputs = getUnstrippedStrippedResponse(errormessage, origParamValue, tfrpattern.errorpattern);
                        }

                        int errorpercent = comparator.compare(normalBodyOutputs[i], errorBodyOutputs[i], errorLCSs[i]);
                        // 4-2 false condition does not match error.
                        if (errorpercent < this.NEALYDIFFERPERCENT && !bingoError) {
                            // bingo
                            bingoError = true;
                            LOGGER4J.debug("bingo 4-1. truepercent["
                                    + truepercent + "]>="
                                    + this.NEALYEQUALPERCENT
                                    + " and truefalsepercent["
                                    + truefalsepercent + "]>=" + this.NEALYEQUALPERCENT
                                    + "\n 4-2.errorpercent[" + errorpercent
                                    + "]<"
                                    + this.NEALYDIFFERPERCENT);
                            String evidence = Constant.messages.getString(MESSAGE_PREFIX + "alert.booleanbased.founddberror.evidence");
                            raiseAlertBooleanBased(Alert.RISK_HIGH, Alert.CONFIDENCE_LOW, i > 0 ? true : false, errormessage,origParamName, errorValue, falseValue, errorValue,evidence);
                        }

                    }

                }
            }
        }
    }

    @Override
    // must be unique in all plugins.
    public int getId() {
        return 120001;
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
     * @param body
     * @param pattern
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
    HttpMessage sendRequestAndCalcLCS(LcsStringListComparator comparator, String origParamName, String paramValue) {
        String[] res = new String[2];
        res[0]=null; res[1] = null;String responsebody = "";
        HttpMessage msg2 = null;

        for(int cn = 0 ; cn<2; cn++) {
            //needs a new message for each type of AND to be issued
            msg2 = getNewMsg();
            if(origParamName!=null&&paramValue!=null) {
                setParameter(msg2, origParamName, paramValue);
            }

            //send the AND with an additional TRUE statement tacked onto the end. Hopefully it will return the same results as the original (to find a vulnerability)
            try {
                sendAndReceive(msg2, false); //do not follow redirects
            } catch (Exception ex) {
                if (LOGGER4J.isDebugEnabled()) LOGGER4J.debug("Caught " + ex.getClass().getName() + " " + ex.getMessage() +
                        " when accessing: " + msg2.getRequestHeader().getURI().toString());
                return null; //Something went wrong, continue to the next item in the loop
            }
            String msg2responsebody = msg2.getResponseBody().toString();
            res[cn] =  new String(msg2responsebody == null ? "" : msg2responsebody );
            responsebody = res[cn];
        }

        if(res[0]!=null&&res[1]!=null) {
            LcsStringList clcs = new LcsStringList();
            comparator.extractLCS(res[0], res[1], clcs);
            responsebody = clcs.getLCSString();
            if(LOGGER4J.isDebugEnabled()) {
                //log.debug("ANDTRUE lcs[" + responsebody + "]");
            }

        }

        msg2.setResponseBody(responsebody);
        return msg2;
    }


    /**
     * get Unstripped and Stripped(removed origParamValue and attackPattern) Response bodies from message
     *
     * @param message
     * @param origParamValue
     * @param attackPattern
     * @return
     */

    String[] getUnstrippedStrippedResponse(HttpMessage message, String origParamValue, String attackPattern) {
        String resBodyUnstripped = message.getResponseBody().toString();
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
     * @param trueValue
     * @param falseValue
     * @param evidence
     */
    void raiseAlertBooleanBased(int risk, int confidence, boolean isStripped, HttpMessage message, String origParamName,  String trueValue, String falseValue, String errorValue, String evidence) {
        String extraInfo = null; // extraInfo is displayed in the pane which titled "Other info:".
        if (isStripped) { // Stripped
            extraInfo = Constant.messages.getString(MESSAGE_PREFIX + "alert.booleanbased.extrainfo", trueValue, falseValue, "");
        } else { // Unstripped
            extraInfo = Constant.messages.getString(MESSAGE_PREFIX + "alert.booleanbased.extrainfo", trueValue, falseValue, "NOT ");
        }
        extraInfo = extraInfo + "\n" + Constant.messages.getString(MESSAGE_PREFIX + "alert.booleanbased.extrainfo.dataexists");

        //raise the alert, and save the attack string for the "Authentication Bypass" alert, if necessary
        String sqlInjectionAttack = "true[" + trueValue +"]false[" + falseValue + "]" + (errorValue == null ? "" : "error[" + errorValue + "]");
        bingo(risk, confidence, getName(), getDescription(),
                null, //url
                origParamName, sqlInjectionAttack,
                extraInfo, getSolution(), evidence, message);
    }
}
