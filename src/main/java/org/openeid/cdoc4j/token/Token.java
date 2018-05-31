package org.openeid.cdoc4j.token;

import org.openeid.cdoc4j.ECRecipient;
import org.openeid.cdoc4j.RSARecipient;
import org.openeid.cdoc4j.exception.CDOCException;

import java.security.cert.Certificate;

public interface Token {

    Certificate getCertificate() throws CDOCException;

    byte[] decrypt(RSARecipient recipient) throws CDOCException;

    byte[] decrypt(ECRecipient recipient) throws CDOCException;

}
