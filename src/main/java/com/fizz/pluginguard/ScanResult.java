package com.fizz.pluginguard;

import java.io.File;
import java.util.List;

/**
 * Outcome of scanning one plugin jar. A jar is INFECTED if a malware signature matched OR it's in the
 * trusted vault but its hash no longer matches (tampered). TRUSTED = in the vault and hash matches.
 * UNVERIFIED = not in the vault and no signature hit (a plugin the guard has no baseline for yet).
 */
record ScanResult(File jar, String sha256, boolean signatureHit, boolean inVault, boolean hashMatch,
                  List<String> reasons) {

    enum Verdict { TRUSTED, INFECTED, UNVERIFIED }

    boolean tampered() {
        return inVault && !hashMatch;
    }

    Verdict verdict() {
        if (signatureHit || tampered()) {
            return Verdict.INFECTED;
        }
        if (inVault && hashMatch) {
            return Verdict.TRUSTED;
        }
        return Verdict.UNVERIFIED;
    }
}
