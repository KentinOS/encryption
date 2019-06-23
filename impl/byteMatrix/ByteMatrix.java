package encryption.impl.byteMatrix;

import encryption.impl.streamUtils.Streamable;

import java.util.Objects;

/**
 * 字节矩阵是AES加密过程中频繁使用的一种数据结构，
 * 支持原子性的字节表替换、行移位、有限域（伽罗华域）内的加法乘法运算（组成列混合的基本运算），
 * 不可变对象(通过bitStream和当前数据类型的构造得出一点：
 * 左操作数类型必然包含右操作数：
 * 当前左右操作数属于同一维度的类型时表现为不可变对象且结果返回的是新对象，
 * 但当右操作数类型为左操作数类型的最小单位时表现为可变对象且结果返回的是该对象本身)
 */
public final class ByteMatrix implements Streamable<ByteMatrix> {

    private final byte[][] values;
    private final int rows;
    private final int cols;

    /**
     * 按列取字节组成字符串，同列每两个字节作为一个字符
     *
     * @param text
     * @return
     */
    public static ByteMatrix valueOf(String text) {
        if (text == null) {
            return null;
        }
        if (text.length() % Character.BYTES != 0) {
            throw new IllegalArgumentException("text's bytes are not divided by Character.BYTES completely");
        }
        final char[] chars = text.toCharArray();
        final int count = chars.length * Character.BYTES;
        final int rows = Integer.BYTES; //取整型字节数为行数，是为了便于随后的密钥类型转换为int
        final byte[][] bytes = new byte[rows][count / rows];
        final int mask = 0x00ff;
        int k;
        for (int i = 0; i < count; ) {
            k = i++;
            bytes[k % rows][k / rows] = (byte) ((chars[k / Character.BYTES] >> Byte.SIZE) & mask);
            k = i++;
            bytes[k % rows][k / rows] = (byte) (chars[k / Character.BYTES] & mask);
        }
        return new ByteMatrix(bytes);
    }

    private ByteMatrix() {
        this(null);
    }

    private ByteMatrix(int[][] matrix, boolean test) {
        final byte[][] bytes = new byte[matrix.length][];
        for (int i = 0; i < matrix.length; i++) {
            final int[] ints = matrix[i];
            bytes[i] = new byte[ints.length];
            for (int j = 0; j < ints.length; j++) {
                bytes[i][j] = (byte) ints[j];
            }
        }
        this.values = bytes;
        this.rows = this.values.length;
        this.cols = this.values[0].length;
    }

    public ByteMatrix(final byte[][] vals) {
        if (Objects.isNull(vals)) {
            throw new NullPointerException("val:null");
        }
        this.values = vals;
        this.rows = vals.length;
        this.cols = vals[0].length;
    }

    /**
     * 构造按列方向序存储字节数据的矩阵
     *
     * @param bytes
     */
    public ByteMatrix(final byte[] bytes, int rows, int cols) {
        if (bytes == null) {
            throw new NullPointerException("bytes is null");
        }
        if (bytes.length != rows * cols) {
            throw new IllegalArgumentException("byte.length is invalid");
        }
        byte[][] vals = new byte[rows][cols];
        for (int i = 0; i < cols; i++) {
            for (int j = 0; j < rows; j++) {
                vals[j][i] = bytes[i * rows + j];
            }
        }
        this.values = vals;
        this.rows = rows;
        this.cols = cols;
    }

    /**
     * 构造合法空矩阵
     *
     * @param rows
     * @param cols
     */
    public ByteMatrix(final int rows, final int cols) {
        if ((rows <= 0) || (cols <= 0)) {
            throw new IllegalArgumentException("either rows or cols is invalid!");
        }
        this.values = new byte[rows][cols];
        this.rows = rows;
        this.cols = cols;
    }

    /**
     * 字节替换
     *
     * @param box
     * @return
     */
    public ByteMatrix substitute(final int[] box) {
        if (Objects.isNull(box)) {
            throw new NullPointerException("box:null");
        }
        if (box.length < this.rows * this.cols) {
            throw new IndexOutOfBoundsException("sbox index: {" + box.length + "," + this.rows * this.cols + "}");
        }
        final byte[][] values = new byte[this.rows][this.cols];
        for (int i = 0; i < this.rows; i++) {
            for (int j = 0; j < this.cols; j++) {
                /**
                 * 不能使用系统的强制转换，因为转换时作为最高位的进位是会考虑进去的
                 * 如(int) 1001 0100 -> 1111 1111 1001 0100
                 * maskBit:0x00ff to deal with.
                 */
                values[i][j] = (byte) box[this.values[i][j] & 0x00ff];
            }
        }

        return new ByteMatrix(values);
    }

    /**
     * 按行索引循环左移
     *
     * @return
     */
    public ByteMatrix leftShift() {
        final byte[][] values = new byte[this.rows][this.cols];
        final byte[][] datas = this.values;
        for (int i = 0; i < this.rows; i++) {
            byte[] ls = datas[i];
            System.arraycopy(ls, i, values[i], 0, this.cols - i);
            System.arraycopy(ls, 0, values[i], this.cols - i, i);
        }
        return new ByteMatrix(values);
    }

    /**
     * 按行索引循环右移
     *
     * @return
     */
    public ByteMatrix rightShift() {
        final byte[][] values = new byte[this.rows][this.cols];
        final byte[][] datas = this.values;
        for (int i = 0; i < this.rows; i++) {
            byte[] rs = datas[i];
            System.arraycopy(rs, this.cols - i, values[i], 0, i);
            System.arraycopy(rs, 0, values[i], i, this.cols - i);
        }
        return new ByteMatrix(values);
    }

    /**
     * 字节矩阵乘法:要左乘!!!
     * 基本运算：
     * * -> gfMultiply 基于2倍的组合完成因数的各个数位的基础乘法并将由此得到的各位结果异或即最终积
     * 基础乘法：10 * a7 a6 a5 a4 a3 a2 a1 a0
     * = a6 a5 a4 a3 a2 a1 a0 0 & 0 0 0 a7 a7 0 a7 a7
     * + -> ^
     *
     * @param leftFactor
     * @return
     */
    public ByteMatrix leftMultiply(final ByteMatrix leftFactor) {
        if (Objects.isNull(leftFactor)) {
            throw new NullPointerException("leftFactor:null");
        }
        byte[][] values = leftFactor.values();
        if (Objects.isNull(values) || (leftFactor.cols != this.rows)) {
            throw new IllegalArgumentException("leftFactor is not legal argument");
        }
        final byte[][] datas = new byte[leftFactor.rows][this.cols];
        for (int i = 0; i < leftFactor.rows; i++) {
            for (int j = 0; j < this.cols; j++) {
                for (int k = 0; k < leftFactor.cols; k++) {
                    datas[i][j] ^= this.gfMultiply(values[i][k], this.values[k][j]);
                }
            }
        }
        return new ByteMatrix(datas);
    }

    private byte gfMultiply(byte v1, byte v2) {
        byte res = 0x00;
        //构造v1二进制各位权值的倍数表
        final int byteSize = Byte.SIZE;
        final byte[] temps = new byte[byteSize];
        int i = 0;
        temps[i++] = v1;
        for (; i < byteSize; i++) {
            temps[i] = this.xtime(temps[i - 1]);
        }
        //v2各位比特值乘以v1二进制倍数表对应的权值并累加到结果中
        for (int j = 0; j < byteSize; j++) {
            res ^= ((v2 >> j) & 0x01) * temps[j];
        }
        //返回结果
        return res;
    }

    /**
     * 基于多项式P(X) = x^8 + x^4 + x^3 + x + 1 ， 故非0异或码为 0x1b
     *
     * @param x
     * @return
     */
    private byte xtime(byte x) {
        return (byte) ((x << 1) ^ ((x & 0x80) == 0x00 ? 0x00 : 0x1b));
    }

    @Override
    public ByteMatrix xor(ByteMatrix other) {
        if (Objects.isNull(other)) {
            throw new NullPointerException("other : null");
        }
        final byte[][] datas = new byte[this.rows][this.cols];
        byte[][] values = other.values();
        for (int i = 0; i < this.rows; i++) {
            for (int j = 0; j < this.cols; j++) {
                datas[i][j] = (byte) (this.values[i][j] ^ values[i][j]);
            }
        }
        return new ByteMatrix(datas);
    }

    /**
     * 由于字节矩阵按列的顺序排列数据的，单位（字节）左移相当于矩阵首元素循环上移
     *
     * @param nBits 能被Byte.SIZE整除的bit数
     * @return
     */
    @Override
    public ByteMatrix leftShift(int nBits, boolean isLoop) {
        if (nBits % Byte.SIZE != 0) {
            throw new IllegalArgumentException("非法bit大小：不能被字节大小整除");
        }
        byte[] bytes = new byte[this.rows * this.cols];
        //还原成一维数组
        for (int i = 0; i < this.cols; i++) {
            for (int j = 0; j < this.rows; j++) {
                bytes[i * this.rows + j] = this.values[j][i];
            }
        }
        //构造结果矩阵
        byte[] vals = new byte[bytes.length];
        final int n = nBits / Byte.SIZE;
        System.arraycopy(bytes, n, vals, 0, vals.length - n);
        if (isLoop) {
            System.arraycopy(bytes, 0, vals, vals.length - n, n);
        }
        return new ByteMatrix(vals, this.rows, this.cols);
    }

    byte[][] values() {
        return values;
    }

    public int rows() {
        return rows;
    }

    public int cols() {
        return cols;
    }

    @Override
    public String toString() {
        final StringBuffer stringBuffer = new StringBuffer();
        stringBuffer.append("{\n");
        for (int i = 0; i < this.rows; i++) {
            stringBuffer.append("\t");
            for (int j = 0; j < this.cols; j++) {
                stringBuffer.append(" " + this.values[i][j] + " ");
            }
            stringBuffer.append("\n");
        }
        stringBuffer.append("}\n");
        return stringBuffer.toString();
    }

    public String toCharacters() {
        final byte[][] values = this.values;
        final int uBitSize = Byte.SIZE;
        final int byteLength = this.rows * this.cols;
        char highMask = 0xff00;
        char lowMask = 0x00ff;


        final StringBuffer res = new StringBuffer();
        int p;
        for (int i = 0; i < byteLength; ) {
            char work = 0;
            p = i++;
            work |= ((((char) values[p % this.rows][p / this.rows]) << uBitSize) & highMask);
            p = i++;
            work |= ((char) values[p % this.rows][p / this.rows]) & lowMask;
            res.append(work);
        }
        return res.toString();
    }

    @Override
    public boolean equals(Object object) {
        if (!(object instanceof ByteMatrix)) {
            return false;
        }
        final ByteMatrix other = (ByteMatrix) object;
        for (int i = 0; i < this.rows; i++) {
            for (int j = 0; j < this.cols; j++) {
                if (this.values[i][j] != other.values[i][j]) {
                    return false;
                }
            }
        }
        return true;
    }

    @Override
    public void setByte(byte val, final int pos) {
        this.checkPosRange(pos);
        this.values[(pos - 1) % this.rows][(pos - 1) / this.rows] = val;
    }

    @Override
    public byte getByte(final int pos) {
        this.checkPosRange(pos);
        return this.values[(pos - 1) % this.rows][(pos - 1) / this.rows];
    }

    private void checkPosRange(final int pos) {
        final int size = this.rows * this.cols;
        if ((pos <= 0) || (pos > size)) {
            throw new IllegalArgumentException("pos is invalid");
        }
    }

    @Override
    public int byteSize() {
        return this.rows * this.cols;
    }
}
