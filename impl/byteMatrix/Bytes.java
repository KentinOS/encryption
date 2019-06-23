package encryption.impl.byteMatrix;

import java.util.Objects;

public class Bytes {
    private Bytes() {

    }

    public static int[] to32BitWordsOfCols(ByteMatrix byteMatrix) {
        if (Objects.isNull(byteMatrix)) {
            throw new NullPointerException("byteMatrix is null");
        }
        if (byteMatrix.rows() != Integer.BYTES) {
            throw new IllegalArgumentException(
                    "the count of byteMatrix 's row" +
                            " is not " + Integer.BYTES +
                            ": " + byteMatrix.rows()
            );
        }
        final byte[][] values = byteMatrix.values();
        final int cols = byteMatrix.cols();

        final int[] ints = new int[cols];
        for (int i = 0; i < Integer.BYTES; i++) {
            for (int j = 0; j < cols; j++) {
                ints[j] <<= Byte.SIZE;
                ints[j] |= values[i][j];
            }
        }
        return ints;
    }

    public static ByteMatrix toByteMatrixByCols(int[] ints) {
        if (Objects.isNull(ints)) {
            throw new NullPointerException("ints is null");
        }
        final byte[][] bytes = new byte[Integer.BYTES][ints.length];
        final int usize = Byte.SIZE;
        for (int i = 0; i < Integer.BYTES; i++) {
            final int offset = usize * (Integer.BYTES - i - 1);
            for (int j = 0; j < ints.length; j++) {
                bytes[i][j] = (byte) ((ints[j] >> offset) & 0x000f);
            }
        }
        return new ByteMatrix(bytes);
    }
}
