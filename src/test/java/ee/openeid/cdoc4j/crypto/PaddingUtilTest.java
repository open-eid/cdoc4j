package ee.openeid.cdoc4j.crypto;

import org.junit.Test;

import java.io.IOException;
import java.util.Arrays;

import static org.junit.Assert.assertTrue;

public class PaddingUtilTest {

    @Test
    public void testX923PaddingAddition() throws IOException {
        assertTrue(Arrays.equals(new byte[] {116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12},
                PaddingUtil.addX923Padding("test".getBytes(), 16)));

        assertTrue(Arrays.equals(new byte[] {116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 0, 0, 0, 4},
                PaddingUtil.addX923Padding("testtesttest".getBytes(), 16)));

        assertTrue(Arrays.equals(new byte[] {116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16},
                PaddingUtil.addX923Padding("testtesttesttest".getBytes(), 16)));
    }

    @Test
    public void testX923PaddingRemoval() {
        assertTrue(Arrays.equals("test".getBytes(),
                PaddingUtil.removeX923Padding(new byte[] {116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12})));

        assertTrue(Arrays.equals("testtesttest".getBytes(),
                PaddingUtil.removeX923Padding(new byte[] {116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 0, 0, 0, 4})));

        assertTrue(Arrays.equals("testtesttesttest".getBytes(),
                PaddingUtil.removeX923Padding(new byte[] {116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16})));
    }

    @Test
    public void testPkcs7PaddingAddition() throws IOException {
        assertTrue(Arrays.equals(new byte[] {116, 101, 115, 116, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12},
                PaddingUtil.addPkcs7Padding("test".getBytes(), 16)));

        assertTrue(Arrays.equals(new byte[] {116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 4, 4, 4, 4},
                PaddingUtil.addPkcs7Padding("testtesttest".getBytes(), 16)));

        assertTrue(Arrays.equals(new byte[] {116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16},
                PaddingUtil.addPkcs7Padding("testtesttesttest".getBytes(), 16)));
    }

    @Test
    public void testPkcs7PaddingRemoval() {
        assertTrue(Arrays.equals("test".getBytes(),
                PaddingUtil.removePkcs7Padding(new byte[] {116, 101, 115, 116, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12})));

        assertTrue(Arrays.equals("testtesttest".getBytes(),
                PaddingUtil.removePkcs7Padding(new byte[] {116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 4, 4, 4, 4})));

        assertTrue(Arrays.equals("testtesttesttest".getBytes(),
                PaddingUtil.removePkcs7Padding(new byte[] {116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16})));
    }

} 
