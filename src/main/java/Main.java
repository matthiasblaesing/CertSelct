import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.platform.DesktopWindow;
import com.sun.jna.platform.WindowUtils;
import com.sun.jna.platform.win32.Crypt32;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.User32;
import com.sun.jna.platform.win32.WinCrypt;
import com.sun.jna.platform.win32.WinDef;
import com.sun.jna.ptr.IntByReference;
import java.awt.*;
import java.util.List;

public class Main {
    private static final String SELECT_CERT_PREFIX = "Select Certificate ";
    private WinCrypt.HCERTSTORE hCertStore = null;
    private WinDef.HWND parentHwnd = new WinDef.HWND();

    public WinCrypt.CERT_CONTEXT selectCertificate() {

        Cryptdlg cryptdlg = Cryptdlg.INSTANCE;

        Cryptdlg.CERT_SELECT_STRUCT pCertSelectInfo = new Cryptdlg.CERT_SELECT_STRUCT();
        pCertSelectInfo.hwndParent = parentHwnd;
        Memory message1 = new Memory(((SELECT_CERT_PREFIX.length() + 1) * (long) Native.WCHAR_SIZE));
        message1.setWideString(0, SELECT_CERT_PREFIX);
        pCertSelectInfo.szTitle = message1;
        pCertSelectInfo.pfnFilter = new CertCallback();
        pCertSelectInfo.cCertStore = 1;
        pCertSelectInfo.arrayCertStore = hCertStore.getPointer();
        pCertSelectInfo.cCertContext = 1;
        WinCrypt.CERT_CONTEXT[] pContexts = (WinCrypt.CERT_CONTEXT[]) new WinCrypt.CERT_CONTEXT().toArray(1);
        pCertSelectInfo.setArrayCertContext(pContexts);
        boolean suc = cryptdlg.CertSelectCertificate(pCertSelectInfo);
        return pCertSelectInfo.getArrayCertContext()[0];
    }


    public void setParentHwnd() {
        int parent = getParentHwnd();
        Pointer p = new Pointer(parent);
        this.parentHwnd = new WinDef.HWND(p);
    }

    public void openSystemStore() {
        // Open the local personal certificate store.
        String SYSTEM_STORE_NAME = "MY";
        WinCrypt.HCERTSTORE handle = Crypt32.INSTANCE.CertOpenSystemStore(Pointer.NULL, SYSTEM_STORE_NAME);
        if (handle == null) {
            System.out.println("Error in open");
        }

        this.hCertStore = handle;
    }
    protected int getParentHwnd() {
        // Get current process ID.
        int processId = Kernel32.INSTANCE.GetCurrentProcessId();

        // Get all visible windows.
        List<DesktopWindow> desktopWindows = WindowUtils.getAllWindows(true);

        for (DesktopWindow desktopWindow : desktopWindows) {
            final IntByReference windowPid = new IntByReference();
            WinDef.HWND desktopWindowHwnd = desktopWindow.getHWND();
            User32.INSTANCE.GetWindowThreadProcessId(desktopWindowHwnd, windowPid);

            // If the window is in the same process and is visible, return its handle.
            if (windowPid.getValue() == processId) {
                return (int) Pointer.nativeValue(desktopWindowHwnd.getPointer());
            }
        }

        // Return a default handle if no windows matching the criteria were found.
        return 0;
    }

    public void closeSystemStore(WinCrypt.CERT_CONTEXT pCertContext) throws Exception {
        Crypt32.INSTANCE.CertFreeCertificateContext(pCertContext);

        if (!CertCloseStore(hCertStore, 0)) {
            System.out.println("Error");
        }
    }

    public boolean CertCloseStore(WinCrypt.HCERTSTORE hCertStore, int dwFlags)
            throws Exception {
        try {
            return Crypt32.INSTANCE.CertCloseStore(hCertStore, dwFlags);
        } catch (final UnsatisfiedLinkError e) {
            throw new Exception(e);
        }
    }

    public Frame createWindown(){
        Frame f=new Frame();
        Button b=new Button("click me");
        b.setBounds(30,50,80,30);
        f.add(b);
        f.setSize(300,300);
        f.setLayout(null);
        f.setVisible(true);
        return f;
    }

    public static void main (String arg[]) throws Exception {
        Main ob = new Main();
        Frame f = ob.createWindown();
        ob.setParentHwnd();
        ob.openSystemStore();
        WinCrypt.CERT_CONTEXT ctx = ob.selectCertificate();
        ob.closeSystemStore(ctx);

    }
}
