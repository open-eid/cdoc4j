package org.openeid.cdoc4j.util.commands;

import org.openeid.cdoc4j.CDOCDecrypter;
import org.openeid.cdoc4j.DataFile;
import org.apache.commons.io.FileUtils;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.*;
import java.util.List;
import java.util.concurrent.Callable;

@Command(name = "decrypt")
public class Decrypt implements Callable<Void> {

  @Option(names = {"-h", "--help"}, usageHelp = true, description = "display usage help")
  boolean usageHelpRequested;

  @Option(names = {"-f", "--file"}, description = "cdoc input file", required = true)
  private File inputFile;

  @Option(names = {"-k", "--decryption-key"}, description = "path to decryption key", required = true)
  private File decryptionKey;

  @Option(names = {"-c", "--certifcate"}, description = "path to certificate")
  private File certificate;

  @Option(names = {"-o", "--output"}, description = "output destination | Default: current-directory")
  private File outputPath = new File(".");


  @Override
  public Void call() throws Exception {
    try {
      decrypt();
    } catch (Exception e) {
      e.printStackTrace();
      CommandLine.usage(this, System.err);
    }
    return null;
  }

  private void decrypt() throws Exception {
    byte[] cdoc = FileUtils.readFileToByteArray(inputFile);
    InputStream keyIn = new FileInputStream(decryptionKey);

    CDOCDecrypter decrypter = new CDOCDecrypter();

    if (certificate != null) {
      try (InputStream certificateInputStream = new FileInputStream(certificate)) {
        decrypter.asRecipient(certificateInputStream);
      }
    }

    List<DataFile> dataFiles = decrypter
            .withPrivateKey(keyIn)
            .decrypt(new ByteArrayInputStream(cdoc));

    for (DataFile dataFile : dataFiles) {
      writeOutputFile(dataFile);
    }
  }

  private void writeOutputFile(DataFile dataFile) throws IOException {
    FileUtils.writeByteArrayToFile(new File(outputPath, dataFile.getFileName()), dataFile.getContent());
  }
}
