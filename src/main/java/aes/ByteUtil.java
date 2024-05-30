package aes;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ByteUtil {

    private static final Logger log = LogManager.getLogger(ByteUtil.class);

    public static void changeByte(byte[] bytes, int index, byte value) {
        bytes[index] = value;
        log.info("!Byte in index {} is reset {}!", index, value);
    }

    public static byte[] moveBytesPosition(byte[] bytes, int startIndex, int endIndex) {
        byte[] result = bytes.clone();
        int length = endIndex - startIndex;
        System.arraycopy(bytes, startIndex, result, endIndex, length);
        System.arraycopy(bytes, endIndex, result, startIndex, length);
        log.info("!Bytes in index {}⭤{} moved!", startIndex, endIndex);
        return result;
    }
}
