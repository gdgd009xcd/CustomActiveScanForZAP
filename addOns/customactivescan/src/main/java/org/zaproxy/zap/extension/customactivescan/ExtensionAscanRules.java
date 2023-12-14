package org.zaproxy.zap.extension.customactivescan;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.HostProcess;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.control.AddOn;
import org.zaproxy.zap.control.ExtensionFactory;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.customactivescan.model.WaitTimerObject;
import org.zaproxy.zap.extension.customactivescan.view.*;
import org.zaproxy.zap.extension.customactivescan.model.PauseActionObject;
import org.zaproxy.zap.utils.DisplayUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.swing.ImageIcon;
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
	public static final String ZAP_ICONS = ZAP_RESOURCES_ROOT_ABSPATH + "/icons";
	// you can access any files under ZAP_ICONS
	// by code like yourClassName.class.getResource(ZAP_ICONS + "/pause.png")
	public static ImageIcon cIcon = DisplayUtils.getScaledIcon(new ImageIcon(ScanLogPanel.class.getResource(ZAP_ICONS + "/C.png")));
	public static ImageIcon triangleUpIcon = DisplayUtils.getScaledIcon(new ImageIcon(ScanLogPanel.class.getResource(ZAP_ICONS + "/triangleUp.png")));
	public static ImageIcon triangleDownIcon = DisplayUtils.getScaledIcon(new ImageIcon(ScanLogPanel.class.getResource(ZAP_ICONS + "/triangleDown.png")));

	//public static final String MESSAGE_PREFIX = "customactivescan.testsqlinjection.";

	public static CustomScanMainPanel customScanMainPanel = null;

	private MainWorkPanelTab mainWorkPanelTab = null;

	private PopUpMenuInAlert popUpMenuInAlert = null;
	private static boolean unLoadCalled = false;

	public static Map<HostProcess, Integer> hostProcessScannerIdMap = null;

	private static Map<Integer, ScanLogPanelFrame> scannerIdScanLogFrameMap = null;

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
		setEnabled(false);
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

		this.mainWorkPanelTab = new MainWorkPanelTab(hook, this);

		hook
				.getHookView()
				.addWorkPanel(this.mainWorkPanelTab);

		//experimental use
		//hook.getHookMenu().addPopupMenuItem(getPopUpMenuInAlert());

		// popUp item for ScanLogPanel.
		hook.getHookMenu().addPopupMenuItem(new PopUpMenuItem(ScanLogPanel.class,"showMessage", cIcon));
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



	private boolean isValidClassLoaded(
			Class<? extends Object> unknownClazz,
			String method,
			Class<? extends Object> validClazz) {

		try {
			return unknownClazz.getMethod(method).getDeclaringClass().equals(validClazz);
		} catch (NoSuchMethodException ex) {
			LOGGER4J.error("isValidClassLoaded failed NoSuchMethodException method:" + method);
		} catch (SecurityException ex) {
			LOGGER4J.error(ex.getMessage(), ex);
		}
		return false;
	}

	public static ScanLogPanelFrame registerScanLogPanelFrame(int scannerId, ScanLogPanelFrame frame) {
		return ExtensionAscanRules.scannerIdScanLogFrameMap.put(scannerId, frame);
	}

	public static ScanLogPanelFrame getScanLogPanelFrame(int scannerId) {
		return ExtensionAscanRules.scannerIdScanLogFrameMap.get(scannerId);
	}

	public static ScanLogPanelFrame removeScanLogPanelFrame(int scannerId) {
		return ExtensionAscanRules.scannerIdScanLogFrameMap.remove(scannerId);
	}

	public static int getSizeOfScanLogPanelFrameMap() {
		return ExtensionAscanRules.scannerIdScanLogFrameMap.size();
	}

	public Integer[] postPmtParams(List<Integer[]> listIntegerArray) {
		Integer[] postedArray = null;
		List<Integer> postedList = new ArrayList<>();
		for(Integer[] integerArray: listIntegerArray) {
			int scannerId = integerArray[0];
			int selectedRequestNo = integerArray[1];
			int lastRequestNo = integerArray[2];
			int tabIndex = integerArray[3];
			ScanLogPanelFrame frame = getScanLogPanelFrame(scannerId);
			if (frame != null) {
				frame.postPmtParamsToScanLogPanel(selectedRequestNo, lastRequestNo, tabIndex);
				postedList.add(scannerId);
			}
		}

		postedArray = new Integer[postedList.size()];
		int index = 0;
		for(Integer i: postedList) {
			postedArray[index++] = i;
		}
		return postedArray;
	}

	public MainWorkPanelTab getMainWorkPanelTab() {
		return this.mainWorkPanelTab;
	}
}
