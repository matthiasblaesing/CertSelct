import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.platform.DesktopWindow;
import com.sun.jna.platform.WindowUtils;
import com.sun.jna.platform.win32.Crypt32;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.User32;
import com.sun.jna.platform.win32.WinCrypt;
import com.sun.jna.platform.win32.WinCrypt.CERT_CONTEXT;
import com.sun.jna.platform.win32.WinDef;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.win32.W32APIOptions;
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
        pCertSelectInfo.szTitle = SELECT_CERT_PREFIX;
        pCertSelectInfo.pfnFilter = new CertCallback();
        pCertSelectInfo.cCertStore = 1;
        pCertSelectInfo.setArrayCertStore(new WinCrypt.HCERTSTORE[]{hCertStore});
        // Prepare space for exactly one CertContext (according to documentation
        // more is not used). The field is initialized with a null pointer, if
        // a value is passed in, it will be freed by CertFreeCertificateContext.
        pCertSelectInfo.cCertContext = 1;
        pCertSelectInfo.arrayCertContext = new Memory(Native.POINTER_SIZE);
        pCertSelectInfo.arrayCertContext.setPointer(0, Pointer.NULL);
        boolean suc = cryptdlg.CertSelectCertificate(pCertSelectInfo);
        // If a certificate was selected the first value of the result array
        // is a pointer to a CERT_CONTEXT, if user canceled, it will be null
        Pointer contextPointer = pCertSelectInfo.arrayCertContext.getPointer(0);
        if(contextPointer != null) {
            // use the returned pointer to build a CERT_CONTEXT and init the
            // java values with the native values
            CERT_CONTEXT cc = (CERT_CONTEXT) Structure.newInstance(CERT_CONTEXT.class, contextPointer);
            cc.read();
            return cc;
        } else {
            return null;
        }
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
        if(ctx != null) {
            System.out.println("Selected: ");
            System.out.printf("%20s: %s%n", "Issuer", decodeName(ctx.pCertInfo.Issuer));
            System.out.printf("%20s: %s%n", "Subject", decodeName(ctx.pCertInfo.Subject));
        } else {
            System.out.println("Cancel");
        }
        ob.closeSystemStore(ctx);

    }
    
    private static String decodeName(WinCrypt.DATA_BLOB blob) {
        int charCount = 512;
        boolean wide = W32APIOptions.DEFAULT_OPTIONS == W32APIOptions.UNICODE_OPTIONS;
        Memory buffer = new Memory(charCount * (wide ? Native.WCHAR_SIZE : 1));
        Crypt32.INSTANCE.CertNameToStr(1, blob, 1, buffer, charCount);
        if(wide) {
            return buffer.getWideString(0);
        } else {
            return buffer.getString(0);
        }
    }
}
