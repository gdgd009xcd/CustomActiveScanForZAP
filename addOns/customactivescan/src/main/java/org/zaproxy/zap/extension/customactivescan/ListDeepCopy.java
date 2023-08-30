package org.zaproxy.zap.extension.customactivescan;

import java.util.ArrayList;
import java.util.List;

import static org.zaproxy.zap.extension.customactivescan.CastUtils.castToType;

/** @author gdgd009xcd */
public class ListDeepCopy {

    // Usage: listDeepCopyVClone(src, dest);
    public static <V extends DeepClone> List<V> listDeepCopyVClone(List<V> src, List<V> dest) {

        if (src != null && dest != null) {
            src.forEach(
                    v -> {
                        dest.add(castToType(v.clone()));
                    });
        }

        return dest;
    }
}
