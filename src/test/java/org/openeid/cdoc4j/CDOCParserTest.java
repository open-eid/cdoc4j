package org.openeid.cdoc4j;

import org.junit.Test;
import org.openeid.cdoc4j.xml.exception.XmlParseException;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class CDOCParserTest {

    @Test
    public void getDataFileNamesSuccessful_cdoc11_withOneDataFile() throws XmlParseException, FileNotFoundException {
        FileInputStream cdocStream = new FileInputStream("src/test/resources/cdoc/valid_cdoc11_ECC.cdoc");
        List<String> dataFileNames = CDOCParser.getDataFileNames(cdocStream);
        assertTrue(dataFileNames.size() == 1);
        assertEquals("lorem1.txt", dataFileNames.get(0));
    }

    @Test
    public void getDataFileNamesSuccessful_cdoc11_withTwoDataFiles() throws XmlParseException, FileNotFoundException {
        FileInputStream cdocStream = new FileInputStream("src/test/resources/cdoc/valid_cdoc11_ECC_withDDOC.cdoc");
        List<String> dataFileNames = CDOCParser.getDataFileNames(cdocStream);
        assertTrue(dataFileNames.size() == 2);
        assertEquals("lorem1.txt", dataFileNames.get(0));
        assertEquals("lorem2.txt", dataFileNames.get(1));
    }

    @Test
    public void getDataFileNamesSuccessful_cdoc10_withOneDataFile() throws XmlParseException, FileNotFoundException {
        FileInputStream cdocStream = new FileInputStream("src/test/resources/cdoc/valid_cdoc10.cdoc");
        List<String> dataFileNames = CDOCParser.getDataFileNames(cdocStream);
        assertTrue(dataFileNames.size() == 1);
        assertEquals("test.txt", dataFileNames.get(0));
    }

    @Test
    public void getDataFileNamesSuccessful_cdoc10_withTwoDataFiles() throws XmlParseException, FileNotFoundException {
        FileInputStream cdocStream = new FileInputStream("src/test/resources/cdoc/valid_cdoc10_withDDOC.cdoc");
        List<String> dataFileNames = CDOCParser.getDataFileNames(cdocStream);
        assertTrue(dataFileNames.size() == 2);
        assertEquals("lorem1.txt", dataFileNames.get(0));
        assertEquals("lorem2.txt", dataFileNames.get(1));
    }

    @Test(expected = XmlParseException.class)
    public void getDataFileNamesSuccessful_invalidCDOCStructure() throws FileNotFoundException, XmlParseException {
        FileInputStream cdocStream = new FileInputStream("src/test/resources/cdoc/invalid_cdoc11_structure.cdoc");
        CDOCParser.getDataFileNames(cdocStream);
    }
}
