package org.openeid.cdoc4j.util.commands;

import org.openeid.cdoc4j.CDOCDecrypter;
import org.openeid.cdoc4j.token.Token;
import org.openeid.cdoc4j.token.pkcs12.PKCS12Token;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.File;
import java.io.FileInputStream;
import java.util.concurrent.Callable;

@Command(name = "pkcs12-decrypt")
public class PKCS12Decrypt implements Callable<Void> {

    @Option(names = {"-h", "--help"}, usageHelp = true, description = "display usage help")
    boolean usageHelpRequested;

    @Option(names = {"-f", "--file"}, description = "cdoc input file", required = true)
    private File inputFile;

    @Option(names = {"-k", "--keystore"}, description = "path to p12 keystore", required = true)
    private File keyStore;

    @Option(names = {"-p", "--password"}, description = "p12 keystore password")
    private String password;

    @Option(names = {"-a", "--alias"}, description = "object label in PKCS11")
    private String alias;

    @Option(names = {"-o", "--output"}, description = "output destination | Default: current-directory")
    private File outputPath = new File(".");


    @Override
    public Void call() {
        try {
            decrypt();
        } catch (Exception e) {
            e.printStackTrace();
            CommandLine.usage(this, System.err);
        }
        return null;
    }

    private void decrypt() throws Exception {
        Token token = new PKCS12Token(new FileInputStream(keyStore), password, alias);
        new CDOCDecrypter()
            .withToken(token)
            .withCDOC(inputFile)
            .decrypt(outputPath);
    }

}
