/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.zaproxy.zap.extension.customactivescan;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Session;

import java.io.File;
import java.net.URI;

/**
 * A null extension just to cause the message bundle and help file to get loaded 
 * @author psiinon
 *
 */
public class ExtensionAscanRules extends ExtensionAdaptor {

	public static final String LOG4JXML_DIR = Constant.getZapHome();

	@Override
	public String getAuthor() {
		return Constant.ZAP_TEAM;
	}

	@Override
	// caution: this name must unique in All AddOns, even if the package name is unique.
	public String getName() {
		return "ExtensionCustomActiveScanRules";
	}

	@Override
	public String getDescription() {
		return Constant.messages.getString("customactivescan.desc");
	}
	
	@Override
	public boolean canUnload() {
		return true;
	}

	@Override
	public void hook(ExtensionHook hook) {
		super.hook(hook);
		File log4jdir =
				new File(LOG4JXML_DIR); // LOG4JXML_DIR: $HOME/.ZAP or .BurpSuite
		String fileName = "log4j2.xml";
		File logFile = new File(log4jdir, fileName);
		if (logFile.exists()) {
			LoggerContext context = (LoggerContext) LogManager.getContext(false);
			URI logURI = context.getConfigLocation();
			if (logURI == null) {
				context.setConfigLocation(logFile.toURI());
				System.out.println("log4j: set:" + logFile.getPath());
			} else {
				System.out.println("log4j: get URI:" + logURI.toString());
			}
		} else {
			System.out.println("log4j file not found.:" + logFile.getPath());
		}

		hook.addSessionListener(new SessionChangedListenerImpl());
	}

	private static class SessionChangedListenerImpl implements SessionChangedListener {

		@Override
		public void sessionScopeChanged(Session session) {
		}

		@Override
		public void sessionModeChanged(Mode mode) {
		}

		@Override
		public void sessionChanged(Session session) {
		}

		@Override
		public void sessionAboutToChange(Session session) {
		}
	}
}
