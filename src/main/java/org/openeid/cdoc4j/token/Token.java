package org.openeid.cdoc4j.token;

import org.openeid.cdoc4j.ECRecipient;
import org.openeid.cdoc4j.RSARecipient;
import org.openeid.cdoc4j.exception.DecryptionException;

import java.security.cert.Certificate;

public interface Token {

    Certificate getCertificate();

    byte[] decrypt(RSARecipient recipient) throws DecryptionException;

    byte[] decrypt(ECRecipient recipient) throws DecryptionException;

}
