package org.openeid.cdoc4j;

public class PKCS11TokenParams {

    private String pkcs11Path;
    private String pin;
    private int slot;
    private String label;

    public PKCS11TokenParams(String pkcs11Path, String pin, int slot) {
        this.pkcs11Path = pkcs11Path;
        this.pin = pin;
        this.slot = slot;
    }

    public PKCS11TokenParams(String pkcs11Path, String pin, int slot, String label) {
        this(pkcs11Path, pin, slot);
        this.label = label;
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

    public String getLabel() {
        return label;
    }

}
