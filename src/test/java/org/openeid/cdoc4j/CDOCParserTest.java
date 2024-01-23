package org.openeid.cdoc4j;

import org.junit.jupiter.api.Test;
import org.openeid.cdoc4j.xml.exception.XmlParseException;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CDOCParserTest {

    @Test
    void getDataFileNamesSuccessful_cdoc11_withOneDataFile() throws XmlParseException, FileNotFoundException {
        FileInputStream cdocStream = new FileInputStream("src/test/resources/cdoc/valid_cdoc11_ECC.cdoc");
        List<String> dataFileNames = CDOCParser.getDataFileNames(cdocStream);
        assertEquals(1, dataFileNames.size());
        assertEquals("lorem1.txt", dataFileNames.get(0));
    }

    @Test
    void getDataFileNamesSuccessful_cdoc11_withTwoDataFiles() throws XmlParseException, FileNotFoundException {
        FileInputStream cdocStream = new FileInputStream("src/test/resources/cdoc/valid_cdoc11_ECC_withDDOC.cdoc");
        List<String> dataFileNames = CDOCParser.getDataFileNames(cdocStream);
        assertEquals(2, dataFileNames.size());
        assertEquals("lorem1.txt", dataFileNames.get(0));
        assertEquals("lorem2.txt", dataFileNames.get(1));
    }

    @Test
    void getDataFileNamesSuccessful_cdoc10_withOneDataFile() throws XmlParseException, FileNotFoundException {
        FileInputStream cdocStream = new FileInputStream("src/test/resources/cdoc/valid_cdoc10.cdoc");
        List<String> dataFileNames = CDOCParser.getDataFileNames(cdocStream);
        assertEquals(1, dataFileNames.size());
        assertEquals("test.txt", dataFileNames.get(0));
    }

    @Test
    void getDataFileNamesSuccessful_cdoc10_withTwoDataFiles() throws XmlParseException, FileNotFoundException {
        FileInputStream cdocStream = new FileInputStream("src/test/resources/cdoc/valid_cdoc10_withDDOC.cdoc");
        List<String> dataFileNames = CDOCParser.getDataFileNames(cdocStream);
        assertEquals(2, dataFileNames.size());
        assertEquals("lorem1.txt", dataFileNames.get(0));
        assertEquals("lorem2.txt", dataFileNames.get(1));
    }

    @Test
    void getDataFileNames_withInvalidCDOCStructure_shouldThrowException() throws FileNotFoundException {
        FileInputStream cdocStream = new FileInputStream("src/test/resources/cdoc/invalid_cdoc11_structure.cdoc");

        XmlParseException caughtException = assertThrows(
                XmlParseException.class,
                () -> CDOCParser.getDataFileNames(cdocStream)
        );

        assertEquals("Error parsing file names from CDOC", caughtException.getMessage());
    }

    @Test
    void getDataFileNames_withEntityExpansionAttack_shouldThrowException() {
        InputStream cdocStream = getClass().getResourceAsStream("/cdoc/1.0-XXE.cdoc");

        XmlParseException caughtException = assertThrows(
                XmlParseException.class,
                () -> CDOCParser.getDataFileNames(cdocStream)
        );

        assertEquals("Error parsing file names from CDOC", caughtException.getMessage());
    }

    @Test
    void getRecipients_cdoc10_withOneRecipient() throws XmlParseException, FileNotFoundException {
        FileInputStream cdocStream = new FileInputStream("src/test/resources/cdoc/valid_cdoc10.cdoc");
        List<Recipient> recipients = CDOCParser.getRecipients(cdocStream);
        assertEquals(1, recipients.size());
        assertEquals("ŽÕRINÜWŠKY,MÄRÜ-LÖÖZ,11404176865", recipients.get(0).getCN());
    }

    @Test
    void getRecipients_cdoc10_withMultipleRecipients() throws XmlParseException, FileNotFoundException {
        FileInputStream cdocStream = new FileInputStream("src/test/resources/cdoc/valid_cdoc10_withMultipleRecipients.cdoc");
        List<Recipient> recipients = CDOCParser.getRecipients(cdocStream);
        assertEquals(2, recipients.size());
        assertEquals("ŽÕRINÜWŠKY,MÄRÜ-LÖÖZ,11404176865", recipients.get(0).getCN());
        assertEquals("ŽÕRINÜWŠKY,MÄRÜ-LÖÖZ,11404176865", recipients.get(1).getCN());
    }

    @Test
    void getRecipients_cdoc11_withOneRecipient() throws XmlParseException, FileNotFoundException {
        FileInputStream cdocStream = new FileInputStream("src/test/resources/cdoc/valid_cdoc11_ECC.cdoc");
        List<Recipient> recipients = CDOCParser.getRecipients(cdocStream);
        assertEquals(1, recipients.size());
        assertEquals("TESTNUMBER,ECC,14212128029", recipients.get(0).getCN());
    }

    @Test
    void getRecipients_cdoc11_withMultipleRecipients() throws XmlParseException, FileNotFoundException {
        FileInputStream cdocStream = new FileInputStream("src/test/resources/cdoc/valid_cdoc11_withMultipleRecipients.cdoc");
        List<Recipient> recipients = CDOCParser.getRecipients(cdocStream);
        assertEquals(2, recipients.size());
        assertEquals("TESTNUMBER,ECC,14212128029", recipients.get(0).getCN());
        assertEquals("ŽÕRINÜWŠKY,MÄRÜ-LÖÖZ,11404176865", recipients.get(1).getCN());
    }

    @Test
    void getRecipients__withInvalidCDOCStructure_shouldThrowException() throws FileNotFoundException {
        FileInputStream cdocStream = new FileInputStream("src/test/resources/cdoc/invalid_cdoc11_structure.cdoc");

        XmlParseException caughtException = assertThrows(
                XmlParseException.class,
                () -> CDOCParser.getRecipients(cdocStream)
        );

        assertEquals("Error parsing recipients from CDOC", caughtException.getMessage());
    }

    @Test
    void getRecipients_withEntityExpansionAttack_shouldThrowException() {
        InputStream cdocStream = getClass().getResourceAsStream("/cdoc/1.0-XXE.cdoc");

        XmlParseException caughtException = assertThrows(
                XmlParseException.class,
                () -> CDOCParser.getDataFileNames(cdocStream)
        );

        assertEquals("Error parsing file names from CDOC", caughtException.getMessage());
    }
}
