package org.zaproxy.zap.extension.customactivescan;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.HostProcess;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.extension.customactivescan.model.WaitTimerObject;
import org.zaproxy.zap.extension.customactivescan.view.CustomScanMainPanel;
import org.zaproxy.zap.extension.customactivescan.view.MainWorkPanelTab;
import org.zaproxy.zap.extension.customactivescan.model.PauseActionObject;
import org.zaproxy.zap.extension.customactivescan.view.PopUpMenuInAlert;
import org.zaproxy.zap.extension.customactivescan.view.ScanLogPanelFrame;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A new Extension AscanRules
 *
 * @author gdgd009xcd
 *
 */
public class ExtensionAscanRules extends ExtensionAdaptor {

	private final static org.apache.logging.log4j.Logger LOGGER4J =
			org.apache.logging.log4j.LogManager.getLogger();

	public static final String ZAPHOME_DIR = Constant.getZapHome();
	private static final String ZAP_RESOURCES_ROOT =
			"org/zaproxy/zap/extension/customactivescan/resources";// RESOURCE root is relative path from addOns/customactivescan/src/main/resources

	private static final String ZAP_RESOURCES_ROOT_ABSPATH = "/" + ZAP_RESOURCES_ROOT;
	public static final String ZAP_ICONS = ZAP_RESOURCES_ROOT_ABSPATH + "/icons";// you can access any files under ZAP_ICONS
																				 // by code like yourClassName.class.getResource(ZAP_ICONS + "/pause.png")

	//public static final String MESSAGE_PREFIX = "customactivescan.testsqlinjection.";

	public static CustomScanMainPanel customScanMainPanel = null;

	private PopUpMenuInAlert popUpMenuInAlert = null;
	private static boolean unLoadCalled = false;

	public static Map<HostProcess, Integer> hostProcessScannerIdMap = null;

	public static Map<Integer, ScanLogPanelFrame> scannerIdScanLogFrameMap = null;

	public static Map<Integer, Thread> scannerIdThreadMap = null;

	public static Map<Integer, PauseActionObject> scannerIdPauseActionMap = null;

	public static Map<Integer, WaitTimerObject> scannerIdWaitTimerMap = null;

	public void setCustomScanMainPanel(CustomScanMainPanel mainPanel) {
		ExtensionAscanRules.customScanMainPanel = mainPanel;
	}

	@Override
	public String getAuthor() {
		return "gdgd009xcd";
	}

	@Override
	// caution: this name must unique in All AddOns, even if the package name is unique.
	public String getName() {
		return "ExtensionCustomActiveScanRules";
	}

	@Override
	public String getDescription() {
		return Constant.messages.getString("customactivescan.desc.text");
	}
	
	@Override
	public boolean canUnload() {
		return true;
	}

	@Override
	public void unload() {
		super.unload();

		// In this addon, it's not necessary to override the method, as there's nothing to unload
		// manually, the components added through the class ExtensionHook (in hook(ExtensionHook))
		// are automatically removed by the base unload() method.
		// If you use/add other components through other methods you might need to free/remove them
		// here (if the extension declares that can be unloaded, see above method).
		LOGGER4J.debug("Custom ExtensionAscanRule unload called.");
		if (ExtensionAscanRules.customScanMainPanel != null) {
			ExtensionAscanRules.customScanMainPanel.saveToNewFileIfNoSaved();
		}
		unLoadCalled = true;
	}

	@Override
	public void hook(ExtensionHook hook) {
		super.hook(hook);

		if (hostProcessScannerIdMap == null) {
			hostProcessScannerIdMap = new ConcurrentHashMap<>();
		}

		if (scannerIdScanLogFrameMap == null) {
			scannerIdScanLogFrameMap = new ConcurrentHashMap<>();
		}

		if (scannerIdThreadMap == null) {
			scannerIdThreadMap = new ConcurrentHashMap<>();
		}

		if (scannerIdPauseActionMap == null) {
			scannerIdPauseActionMap = new ConcurrentHashMap<>();
		}

		if (scannerIdWaitTimerMap == null) {
			scannerIdWaitTimerMap = new ConcurrentHashMap<>();
		}

		hook
				.getHookView()
				.addWorkPanel(new MainWorkPanelTab(hook, this));

		//experimental use
		//hook.getHookMenu().addPopupMenuItem(getPopUpMenuInAlert());


	}

	private PopUpMenuInAlert getPopUpMenuInAlert() {
		if (this.popUpMenuInAlert == null) {
			this.popUpMenuInAlert = new PopUpMenuInAlert();
		}
		return this.popUpMenuInAlert;
	}

	@Override
	public void destroy() {
		super.destroy();
		LOGGER4J.debug("Destory called.");
		if (ExtensionAscanRules.customScanMainPanel != null && !unLoadCalled) {
			ExtensionAscanRules.customScanMainPanel.saveToNewFileIfNoSaved();
		}
	}
}
