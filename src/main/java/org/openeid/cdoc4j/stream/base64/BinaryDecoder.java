package org.openeid.cdoc4j.stream.base64;

/**
 * Defines common decoding methods for byte array decoders.
 *
 * @version $Id: BinaryDecoder.java 1379145 2012-08-30 21:02:52Z tn $
 */
public interface BinaryDecoder extends Decoder {

    /**
     * Decodes a byte array and returns the results as a byte array.
     *
     * @param source
     *            A byte array which has been encoded with the appropriate encoder
     * @return a byte array that contains decoded content
     * @throws DecoderException
     *             A decoder exception is thrown if a Decoder encounters a failure condition during the decode process.
     */
    byte[] decode(byte[] source) throws DecoderException;
}
