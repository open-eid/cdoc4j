package org.openeid.cdoc4j;

import javax.crypto.SecretKey;
import java.util.List;

@FunctionalInterface
public interface SecretKeySupplier {
  SecretKey get(List<Recipient> recipients);
}
