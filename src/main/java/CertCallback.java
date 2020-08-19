import com.sun.jna.platform.win32.WinCrypt;

public class CertCallback implements Cryptdlg.FncmFilterProcCallback {

    public boolean callback(WinCrypt.CERT_CONTEXT pCertContext, String lCustData, int dwFlags, int dwDisplayWell) {
        return true;
    }
}
