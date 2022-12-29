package org.zaproxy.zap.extension.customactivescan.view;

import javax.swing.*;
import javax.swing.plaf.FontUIResource;
import java.awt.*;
import java.util.Enumeration;

public class MyFontUtils {
    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();
    public static final String defaultFontKeyName = "Label.font";
    public static float DEFAULT_FONT_SIZE = 12;

    private static float getLookAndFeelFontScale() {
        float lookAndFeelFontSize = -1;
        float maxLookAndFeelFontSize = -1;
        if (lookAndFeelFontSize < 0) {
            // calculate fontSize from lookAndFeel defaults.
            UIDefaults defaults = UIManager.getDefaults();
            Font defaultFont = UIManager.getFont(defaultFontKeyName);
            if (defaultFont != null) {
                LOGGER4J.debug("getFont name[" + defaultFont.getFontName() + "] size2D=" + defaultFont.getSize2D());
                lookAndFeelFontSize = defaultFont.getSize2D();
                return lookAndFeelFontSize;
            }

            //UIDefaults defaults = UIManager.getLookAndFeelDefaults();
            Enumeration<Object> keys = defaults.keys();
            while (keys.hasMoreElements()) {
                Object key = keys.nextElement();
                if ((key instanceof String) && (((String) key).endsWith(".font"))) {
                    String keyName = (String)key;
                    FontUIResource font = (FontUIResource) UIManager.get(key);
                    if (maxLookAndFeelFontSize < font.getSize2D()) {
                        maxLookAndFeelFontSize = font.getSize2D();
                    }

                    if (keyName.equals(defaultFontKeyName)) {
                        lookAndFeelFontSize = font.getSize2D();
                    }
                }
            }
            if (lookAndFeelFontSize < 0) {
                lookAndFeelFontSize = maxLookAndFeelFontSize;
                if (lookAndFeelFontSize < 0) {
                    lookAndFeelFontSize = DEFAULT_FONT_SIZE;
                }
            }
            LOGGER4J.debug("getLookAndFeelFontSize changed size = " + lookAndFeelFontSize);
        }
        return lookAndFeelFontSize;
    }

    public static float getScale() {
        return getLookAndFeelFontScale() / DEFAULT_FONT_SIZE;
    }

    public static ImageIcon getScaledIcon(ImageIcon icon) {
        if (icon == null || getScale() == 1) {
            // don't need to scale
            return icon;
        }
        return new ImageIcon(
                (icon)
                        .getImage()
                        .getScaledInstance(
                                (int) (icon.getIconWidth() * getScale()),
                                (int) (icon.getIconHeight() * getScale()),
                                Image.SCALE_SMOOTH));
    }
}
