package encryption.impl.bitStream;

import java.security.InvalidParameterException;

public class Bits {
    private Bits() {

    }

    public static boolean isBit(int bit) {
        return (bit == 0x0000) || (bit == 0x0001);
    }

    public static boolean[] toBooleans(final int value, final int bitCount) {
        if ((bitCount < 0) || (bitCount > Integer.SIZE)) {
            throw new InvalidParameterException("非法比特位数");
        }
        int maskBit = 0x0000;
        for (int i = 0; i < bitCount; i++) {
            maskBit <<= 1;
            maskBit |= 0x0001;
        }
        int t = value & maskBit;
        boolean[] res = new boolean[bitCount];
        for (int i = bitCount - 1; i >= 0; i--) {
            res[i] = ((t & 0x0001) == 0x0001);
            t >>= 1;
        }
        return res;
    }

}
