package org.zaproxy.zap.extension.customactivescan;

/** @author gdgd009xcd */
public class CastUtils {

    /**
     * @param <T>
     * @param obj
     * @return
     */
    @SuppressWarnings({"unchecked"})
    public static <T> T castToType(Object obj) {
        return (T) obj;
    }
}
