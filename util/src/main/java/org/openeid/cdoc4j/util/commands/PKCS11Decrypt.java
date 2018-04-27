package org.openeid.cdoc4j.util.commands;

import org.apache.commons.io.FileUtils;
import org.openeid.cdoc4j.CDOCDecrypter;
import org.openeid.cdoc4j.DataFile;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.concurrent.Callable;

@Command(name = "pkcs11-decrypt")
public class PKCS11Decrypt implements Callable<Void>  {

    @Option(names = {"-h", "--help"}, usageHelp = true, description = "display usage help")
    boolean usageHelpRequested;

    @Option(names = {"-f", "--file"}, description = "cdoc input file", required = true)
    private File inputFile;

    @Option(names = {"-d", "--driver"}, description = "PKCS#11 driver path", required = true)
    private String driver;

    @Option(names = {"-s", "--slot"}, description = "slot | Default: 0")
    private int slot;

    @Option(names = {"-l", "--label"}, description = "object label in PKCS11")
    private String label;

    @Option(names = {"-p", "--pin"}, description = "pin", required = true)
    private String pin;

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

        List<DataFile> dataFiles = new CDOCDecrypter()
                .withPkcs11(driver, pin, slot, label)
                .decrypt(new ByteArrayInputStream(cdoc));

        for (DataFile dataFile : dataFiles) {
            writeOutputFile(dataFile);
        }
    }

    private void writeOutputFile(DataFile dataFile) throws IOException {
        FileUtils.writeByteArrayToFile(new File(outputPath, dataFile.getFileName()), dataFile.getContent());
    }

}
