/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
