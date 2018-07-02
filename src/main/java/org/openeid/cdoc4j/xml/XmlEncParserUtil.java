package org.openeid.cdoc4j.xml;

import org.apache.commons.codec.binary.StringUtils;
import org.openeid.cdoc4j.stream.CustomOutputStreamWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.io.IOException;

import static javax.xml.stream.XMLStreamConstants.END_ELEMENT;
import static javax.xml.stream.XMLStreamConstants.START_ELEMENT;

public class XmlEncParserUtil {

    private static final Logger LOGGER = LoggerFactory.getLogger(XmlEncParserUtil.class);

    public static void goToElement(XMLStreamReader reader, String elementName) throws XMLStreamException {
        if (reader.getEventType() == START_ELEMENT && reader.getLocalName().equals(elementName)) {
            LOGGER.debug("Already at element named <{}>", elementName);
            return;
        }

        while(reader.hasNext()) {
            int eventType = reader.next();
            switch (eventType) {
                case START_ELEMENT:
                    if (reader.getLocalName().equals(elementName)) {
                        return;
                    }
                    break;
                case END_ELEMENT:
                    break;
            }
        }

        throw new XMLStreamException("Could not find element name <" + elementName + ">");
    }

    public static void goToElementWithAttributeValue(XMLStreamReader reader, String elementName, String attributeName, String attributeValue) throws XMLStreamException {
        while(reader.hasNext()) {
            int eventType = reader.next();
            switch (eventType) {
                case START_ELEMENT:
                    String attrValue = reader.getAttributeValue(null, attributeName);
                    if (reader.getLocalName().equals(elementName) && StringUtils.equals(attrValue, attributeValue)) {
                        return;
                    }
                    break;
                case END_ELEMENT:
                    break;
            }
        }
        throw new XMLStreamException("Could not find element name <" + elementName + ">");
    }
    
    public static String getAttributeValue(XMLStreamReader reader, String attributeName) throws XMLStreamException {
        String attributeValue = reader.getAttributeValue(null, attributeName);
        if (attributeValue != null) {
            return attributeValue;
        }
        throw new XMLStreamException("Could not find attribute named <" + attributeName + ">");
    }

    public static boolean nextElementIs(XMLStreamReader reader, String expectedElement) throws XMLStreamException {
        while (reader.hasNext()) {
            int eventType = reader.next();
            if (eventType == START_ELEMENT) {
                return reader.getLocalName().equals(expectedElement);
            }
        }
        return false;
    }

    public static String readCharacters(XMLStreamReader reader) throws XMLStreamException {
        StringBuilder result = new StringBuilder();
        while (reader.hasNext()) {
            int eventType = reader.next();
            switch (eventType) {
                case XMLStreamReader.CHARACTERS:
                case XMLStreamReader.CDATA:
                    result.append(reader.getText());
                    break;
                case XMLStreamReader.END_ELEMENT:
                    return result.toString();
            }
        }
        throw new XMLStreamException("Premature end of file during reading characters");
    }

    public static void readCharacters(XMLStreamReader reader, CustomOutputStreamWriter output, int bufferSize) throws XMLStreamException, IOException {
        int textTotalLength;
        int sourcePosition;
        char[] buffer;

        while (reader.hasNext()) {
            int eventType = reader.next();
            switch (eventType) {
                case XMLStreamReader.CHARACTERS:
                    textTotalLength = reader.getTextLength();
                    sourcePosition = 0;
                    buffer = new char[bufferSize];
                    while (sourcePosition < textTotalLength) {
                        reader.getTextCharacters(sourcePosition, buffer, 0, bufferSize);
                        output.write(buffer, 0, bufferSize);
                        sourcePosition += bufferSize;
                        buffer = new char[bufferSize];
                    }
                    break;
                case XMLStreamReader.END_ELEMENT:
                    return;
            }
        }
        throw new XMLStreamException("Premature end of file during reading characters");
    }

    public static void readBase64DecodedAndEncryptedCharacters(XMLStreamReader reader, CustomOutputStreamWriter output, int bufferSize) throws XMLStreamException, IOException {
        /*
            Expected to have XMLStreamReader character reading event already open because parsing of the cipher IV.
            Construction of decryption output stream required for parsing data here requires cipher initiation which requires IV.
         */
        boolean hasNext = true;
        int eventType = XMLStreamReader.CHARACTERS;
        int textTotalLength;
        int sourcePosition;
        char[] buffer;

        while (hasNext) {
            switch (eventType) {
                case XMLStreamReader.CHARACTERS:
                    textTotalLength = reader.getTextLength();
                    sourcePosition = 0;
                    buffer = new char[bufferSize];
                    while((sourcePosition + bufferSize) < textTotalLength) {
                        reader.getTextCharacters(sourcePosition, buffer, 0, bufferSize);
                        output.write(buffer, 0, bufferSize);
                        sourcePosition += bufferSize;
                        buffer = new char[bufferSize];
                    }

                    reader.getTextCharacters(sourcePosition, buffer, 0, bufferSize);

                    hasNext = reader.hasNext();
                    eventType = reader.next();

                    while(eventType == XMLStreamReader.CHARACTERS && consistsOfOnlyLineChange(reader, bufferSize)) {
                        hasNext = reader.hasNext();
                        eventType = reader.next();
                    }

                    if (areLastCharactersToRead(hasNext, eventType)) {
                        output.informOfLastWrite();
                    }
                    output.write(buffer, 0, bufferSize);
                    break;
                case XMLStreamReader.END_ELEMENT:
                    return;
            }
        }
        throw new XMLStreamException("Premature end of file during reading characters");
    }

    private static boolean consistsOfOnlyLineChange(XMLStreamReader reader, int bufferSize) throws XMLStreamException {
        char[] buffer = new char[bufferSize];
        reader.getTextCharacters(0, buffer, 0, bufferSize);
        return reader.getTextLength() == 1 && buffer[0] == '\n';
    }

    private static boolean areLastCharactersToRead(boolean hasNext, int eventType) {
        return hasNext && eventType == XMLStreamReader.END_ELEMENT;
    }
}
