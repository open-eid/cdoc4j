package org.openeid.cdoc4j.util.commands;

import org.openeid.cdoc4j.CDOCBuilder;
import org.openeid.cdoc4j.DataFile;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.*;
import java.nio.file.Files;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

@Command(name = "encrypt")
public class Encrypt implements Callable<Void> {

  @Option(names = {"-h", "--help"}, usageHelp = true, description = "display usage help")
  boolean usageHelpRequested;

  @Option(names = {"-r", "--recipient-certs"}, description = "recipient certificate path(s) 1..*", arity = "1..*", required = true)
  private List<File> recipientCertificateFiles;

  @Option(names = {"-o", "--output"}, description = "output destination | Default: current-directory/first-input-file.cdoc")
  private File outputPath;

  @Option(names = {"-f", "--files"}, description = "input file(s) 1..*", arity = "1..*", required = true)
  private List<File> inputFiles;

  @Option(names = {"-c", "--cdoc-version"}, description = "cdoc version (1.1 or 1.0) | Default: 1.1")
  private String cdocVersion = "1.1";

  @Override
  public Void call() {
    if (outputPath == null) {
      outputPath = new File(new File("."), inputFiles.get(0).getName() + ".cdoc");
    }

    try {
      encrypt();
    } catch (Exception e) {
      e.printStackTrace();
      CommandLine.usage(this, System.err);
    }
    return null;
  }

  private void encrypt() throws Exception {

    List<DataFile> dataFiles = toDataFiles(inputFiles);
    List<X509Certificate> certificates = toCertificates(recipientCertificateFiles);

    try (OutputStream fileOutPutStream = new FileOutputStream(outputPath)) {
      CDOCBuilder.version(cdocVersion)
              .withDataFiles(dataFiles)
              .withRecipients(certificates)
              .buildToOutputStream(fileOutPutStream);

    }
  }

  private List<DataFile> toDataFiles(List<File> files) throws IOException {
    List<DataFile> dataFiles = new ArrayList<>();
    for (File file : files) {
      DataFile dataFile = new DataFile(file.getName(), Files.readAllBytes(file.toPath()));
      dataFiles.add(dataFile);
    }
    return dataFiles;
  }

  private List<X509Certificate> toCertificates(List<File> certificateFiles) throws IOException, CertificateException {
    List<X509Certificate> certificates = new ArrayList<>();
    for (File file : certificateFiles) {
      try (InputStream inputStream = new FileInputStream(file)) {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(inputStream);
        inputStream.close();
        certificates.add(certificate);
      }
    }
    return certificates;
  }

}
