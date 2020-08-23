import com.sun.jna.platform.win32.WinCrypt;
import com.sun.jna.platform.win32.WinDef.LPARAM;

public class CertCallback implements Cryptdlg.FncmFilterProcCallback {

    public boolean callback(WinCrypt.CERT_CONTEXT pCertContext, LPARAM lCustData, int dwFlags, int dwDisplayWell) {
        return true;
    }
}
