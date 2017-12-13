package org.cdoc4j;

import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;

public class ECRecipient extends Recipient {

    private final ECPublicKey ephemeralPublicKey;
    private final byte[] algorithmId;
    private final byte[] partyUInfo;
    private final byte[] partyVInfo;

    public ECRecipient(String cn, X509Certificate certificate, byte[] encryptedKey, ECPublicKey ephemeralPublicKey, byte[] algorithmId, byte[] partyUInfo, byte[] partyVInfo) {
        super(cn, certificate, encryptedKey);
        this.ephemeralPublicKey = ephemeralPublicKey;
        this.algorithmId = algorithmId;
        this.partyUInfo = partyUInfo;
        this.partyVInfo = partyVInfo;
    }

    public ECPublicKey getEphemeralPublicKey() {
        return ephemeralPublicKey;
    }

    public byte[] getAlgorithmId() {
        return algorithmId;
    }

    public byte[] getPartyUInfo() {
        return partyUInfo;
    }

    public byte[] getPartyVInfo() {
        return partyVInfo;
    }

} 
