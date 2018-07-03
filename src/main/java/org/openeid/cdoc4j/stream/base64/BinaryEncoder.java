package org.openeid.cdoc4j.stream.base64;

/**
 * Defines common encoding methods for byte array encoders.
 *
 * @version $Id: BinaryEncoder.java 1379145 2012-08-30 21:02:52Z tn $
 */
public interface BinaryEncoder extends Encoder {

    /**
     * Encodes a byte array and return the encoded data as a byte array.
     *
     * @param source
     *            Data to be encoded
     * @return A byte array containing the encoded data
     * @throws EncoderException
     *             thrown if the Encoder encounters a failure condition during the encoding process.
     */
    byte[] encode(byte[] source) throws EncoderException;
}
