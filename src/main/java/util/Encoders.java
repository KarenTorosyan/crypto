package util;

import java.util.Base64;
import java.util.HexFormat;

public class    Encoders {

    public static Encoder defaultEncoder() {
        return base64();
    }

    public static Encoder hex() {
        return new HexEncoder();
    }

    public static Encoder base64() {
        return new Base64Encoder();
    }

    public interface Encoder {
        String encode(byte[] data);

        byte[] decode(String data);
    }

    public static class HexEncoder implements Encoder {

        @Override
        public String encode(byte[] data) {
            return HexFormat.of().formatHex(data);
        }

        @Override
        public byte[] decode(String data) {
            return HexFormat.of().parseHex(data);
        }
    }

    public static class Base64Encoder implements Encoder {

        @Override
        public String encode(byte[] data) {
            return Base64.getEncoder().encodeToString(data);
        }

        @Override
        public byte[] decode(String data) {
            return Base64.getDecoder().decode(data);
        }
    }
}
