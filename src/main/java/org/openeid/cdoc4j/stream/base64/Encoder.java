package org.openeid.cdoc4j.stream.base64;

/**
 * Provides the highest level of abstraction for Encoders.
 * <p>
 * This is the sister interface of {@link Decoder}.  Every implementation of Encoder provides this
 * common generic interface which allows a user to pass a generic Object to any Encoder implementation
 * in the codec package.
 *
 * @version $Id: Encoder.java 1379145 2012-08-30 21:02:52Z tn $
 */
public interface Encoder {

    /**
     * Encodes an "Object" and returns the encoded content as an Object. The Objects here may just be
     * <code>byte[]</code> or <code>String</code>s depending on the implementation used.
     *
     * @param source
     *            An object to encode
     * @return An "encoded" Object
     * @throws EncoderException
     *             An encoder exception is thrown if the encoder experiences a failure condition during the encoding
     *             process.
     */
    Object encode(Object source) throws EncoderException;
}
