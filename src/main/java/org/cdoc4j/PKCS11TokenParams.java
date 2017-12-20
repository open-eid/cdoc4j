package org.cdoc4j;

public class PKCS11TokenParams {

    private String pkcs11Path;
    private String pin;
    private int slot;

    public PKCS11TokenParams(String pkcs11Path, String pin, int slot) {
        this.pkcs11Path = pkcs11Path;
        this.pin = pin;
        this.slot = slot;
    }

    public String getPkcs11Path() {
        return pkcs11Path;
    }

    public String getPin() {
        return pin;
    }

    public int getSlot() {
        return slot;
    }

}
