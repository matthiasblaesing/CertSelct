import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.Structure.FieldOrder;
import com.sun.jna.platform.win32.BaseTSD;
import com.sun.jna.platform.win32.WinCrypt;
import com.sun.jna.platform.win32.WinDef;
import com.sun.jna.platform.win32.WinDef.LPARAM;
import com.sun.jna.win32.W32APIOptions;

import com.sun.jna.win32.StdCallLibrary;

public interface Cryptdlg extends StdCallLibrary{
    public static final String LIBRARY_NAME = "Cryptdlg";

    Cryptdlg INSTANCE = Native.load(LIBRARY_NAME, Cryptdlg.class, W32APIOptions.DEFAULT_OPTIONS);

    public boolean CertSelectCertificate(CERT_SELECT_STRUCT pCertSelectInfo);

    @FieldOrder({
        "dwSize", "hwndParent", "hInstance", "pTemplateName", "dwFlags", 
        "szTitle", "cCertStore", "arrayCertStore", "szPurposeOid", 
        "cCertContext", "arrayCertContext", "lCustData", "pfnHook", "pfnFilter",
        "szHelpFileName", "dwHelpId", "hprov"})
    public static class CERT_SELECT_STRUCT extends Structure {


        public static class ByReference extends CERT_SELECT_STRUCT implements Structure.ByReference {}

        public int dwSize;
        public WinDef.HWND hwndParent;
        public WinDef.HINSTANCE hInstance;
        public String pTemplateName;
        public int dwFlags;
        public String szTitle;
        public int cCertStore;
        public Pointer arrayCertStore;
        public String szPurposeOid;
        public int cCertContext;
        public Pointer arrayCertContext;
        public WinDef.LPARAM lCustData;
        public Pointer pfnHook = null;
        public FncmFilterProcCallback pfnFilter;
        public String szHelpFileName;
        public int dwHelpId;
        public HCRYPTPROV hprov;

        public CERT_SELECT_STRUCT() {
            super();
        }

        public void setArrayCertStore(WinCrypt.HCERTSTORE[] stores) {
            if (stores == null || stores.length == 0) {
                arrayCertStore = null;
                cCertStore = 0;
            } else {
                Memory mem = new Memory(Native.POINTER_SIZE * stores.length);
                for (int i = 0; i < stores.length; i++) {
                    mem.setPointer(i * Native.POINTER_SIZE, stores[i].getPointer());
                }
                cCertStore = stores.length;
                arrayCertStore = mem;
            }
        }

        public WinCrypt.HCERTSTORE[] getArrayCertStore() {
            if (arrayCertStore == null || cCertStore == 0) {
                return new WinCrypt.HCERTSTORE[0];
            } else {
                WinCrypt.HCERTSTORE[] result = new WinCrypt.HCERTSTORE[cCertStore];
                for (int i = 0; i < result.length; i++) {
                    result[i] = new WinCrypt.HCERTSTORE(arrayCertStore.getPointer(i * Native.POINTER_SIZE));
                }
                return result;
            }
        }

        @Override
        public void write() {
            this.dwSize = size();
            super.write();
        }
    }

    public static class HCRYPTPROV extends BaseTSD.ULONG_PTR {

        public HCRYPTPROV() {}

        public HCRYPTPROV(long value) {
            super(value);
        }
    }

    public interface FncmFilterProcCallback extends StdCallLibrary.StdCallCallback {

        public boolean callback(
                WinCrypt.CERT_CONTEXT pCertContext, LPARAM lCustData, int dwFlags, int dwDisplayWell);
    }
}
