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
package org.zaproxy.zap.extension.customactivescan;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;

/** @author gdgd009xcd */
public class FileWriterPlus {
    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    PrintWriter pw;
    String fileName;
    String charSet;
    boolean append;
    boolean auto_flush;

    public FileWriterPlus(String _fileName)
            throws UnsupportedEncodingException, FileNotFoundException {
        fileName = _fileName; // filename
        charSet = "utf-8"; // character set is UTF-8
        append = false; // append mode off == truncate data
        auto_flush = true; // auto flash on
        open();
    }

    final void open() throws UnsupportedEncodingException, FileNotFoundException {

        pw =
                new PrintWriter(
                        new BufferedWriter(
                                new OutputStreamWriter(
                                        new FileOutputStream(new File(fileName), append),
                                        charSet)) // if omit charSet option then system default is applied.
                        ,
                        auto_flush);
        // ...

    }

    public void reOpen() {
        truncate();
    }

    public void truncate() {
        close();
        try {
            open();
        } catch (Exception ex) {
            LOGGER4J.error(ex.getMessage(),ex);
        }
    }

    public void println(String rec) {
        if (pw != null) {
            pw.println(rec);
        }
    }

    public void print(String data) {
        if (pw != null) {
            pw.print(data);
        }
    }

    public void close() {
        if (pw != null) {
            pw.close();
            pw = null;
        }
    }

    public PrintWriter getPrintWriter() {
        return pw;
    }
}

