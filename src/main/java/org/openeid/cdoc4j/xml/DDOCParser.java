package org.openeid.cdoc4j.xml;

import org.openeid.cdoc4j.DataFile;
import org.openeid.cdoc4j.xml.exception.XmlParseException;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.List;

public class DDOCParser {

    private static final Logger LOGGER = LoggerFactory.getLogger(DDOCParser.class);

    private Document document;

    public DDOCParser(byte[] ddocBytes) throws XmlParseException {
        document = XMLDocumentBuilder.buildDocument(new ByteArrayInputStream(ddocBytes));
    }

    public List<DataFile> getDataFiles() throws XmlParseException {
        try {
            List <DataFile> dataFiles = new ArrayList<>();
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expression = xpath.compile("/SignedDoc/DataFile");
            NodeList dataFileNodes = (NodeList) expression.evaluate(document, XPathConstants.NODESET);
            for (int i = 0; i < dataFileNodes.getLength(); i++) {
                Node dataFileNode = dataFileNodes.item(i);
                String dataFileName = dataFileNode.getAttributes().getNamedItem("Filename").getTextContent();
                byte[] dataFileContent = Base64.decodeBase64(dataFileNode.getTextContent());
                dataFiles.add(new DataFile(dataFileName, dataFileContent));
            }
            return dataFiles;
        } catch (Exception e) {
            String message = "Error parsing datafiles from DDOC!";
            LOGGER.error(message, e);
            throw new XmlParseException(message, e);
        }
    }

} 
