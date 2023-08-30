package org.zaproxy.zap.extension.customactivescan.view;

import javax.swing.filechooser.FileFilter;
import java.io.File;

/** @author gdgd009xcd */
public class FileFilterForJSON extends FileFilter {

    public boolean accept(File f) {
        /* if file is directory then display it. */
        if (f.isDirectory()) {
            return true;
        }

        /* extract file extension, and if it's name is  "json" then display it. */
        String ext = getExtension(f);
        if (ext != null) {
            if (ext.equals("json")) {
                return true;
            } else {
                return false;
            }
        }

        return false;
    }

    public String getDescription() {
        return "JSON";
    }

    /* extract file Extension */
    private String getExtension(File f) {
        String ext = null;
        String filename = f.getName();
        int dotIndex = filename.lastIndexOf('.');

        if ((dotIndex > 0) && (dotIndex < filename.length() - 1)) {
            ext = filename.substring(dotIndex + 1).toLowerCase();
        }

        return ext;
    }
}
