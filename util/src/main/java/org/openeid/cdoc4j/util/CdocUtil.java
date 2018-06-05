package org.openeid.cdoc4j.util;

import org.openeid.cdoc4j.util.commands.Encrypt;
import org.openeid.cdoc4j.util.commands.PKCS11Decrypt;
import org.openeid.cdoc4j.util.commands.PKCS12Decrypt;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.util.concurrent.Callable;

@Command(
    version = {"cdoc4j-util version: 1.0-SNAPSHOT", "cdoc4j library version: 1.0-SNAPSHOT"},
    name = "cdoc4j-util",
    header = "\r\ncdoc4j-util is a command line interface for cdoc4j library\r\n",
    customSynopsis = { "[encrypt|pkcs12-decrypt|pkcs11-decrypt] <arguments>" },
    subcommands = {Encrypt.class, PKCS12Decrypt.class, PKCS11Decrypt.class}
)
public class CdocUtil implements Callable<Void> {

  @Option(names = {"--version"}, versionHelp = true, description = "display version info")
  boolean versionInfoRequested;

  public static void main(String... args) {
    if (args.length == 0) {
      CommandLine.usage(new CdocUtil(), System.out);
      CommandLine.usage(new Encrypt(), System.out);
      CommandLine.usage(new PKCS12Decrypt(), System.out);
      CommandLine.usage(new PKCS11Decrypt(), System.out);
    }
    CommandLine.call(new CdocUtil(), System.err, args);
  }

  @Override
  public Void call() throws Exception {
    return null;
  }
}
