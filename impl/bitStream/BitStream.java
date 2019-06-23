package encryption.impl.bitStream;

import encryption.Config;
import encryption.impl.streamUtils.Streamable;

import java.io.Serializable;
import java.security.InvalidParameterException;
import java.util.InputMismatchException;
import java.util.Optional;

/**
 * byte与boolean之争
 * byte存储bit可以是boolean的最大容量的8倍,
 * 因为在数组长度属于整型最大值范围内的局限下数组的内存申请容量存在上限，本质JVM内存申请也是存在上限的，
 * 所以一开始只是考虑到尽可能存储大量数据的需求，没有考虑到比特流需要基本操作涉及的元素操作单位必须要是bit的，否则基本操作的复杂度会大大增加。
 * 再三修改最终决定使用boolean类型作为基础类型，虽然存储容量缩小了很多，但最后实在容量大的话依然可以采用分组策略处理。
 * 最主要是因为它与bit类型所占位数一样，而且为更方便支持移位这种基本操作
 * 处理加密解密操作涉及字节的类型转换的数据结构
 * 解决的问题主要有以下所述：
 * 1.作为字符串类型的消息明文转换成字节数组类型
 * 2.转换后的字节数组类型如何进行批量异或操作
 * <p>
 * 对外封装成比特流的数据类型，支持读写比特流比特的操作
 * <p>
 * 关于数值运算的基本操作，最好将结果值使用为不可变对象的实现
 * <p>
 * 关于基本操作，均应为以比特流作为基本单位的基本操作，
 * 即对于独立于流之外的单个比特的操作建议若常有需要以比特为独立单位操作的场景则应再另外封装数据类;
 * 若只是个别的比特操作比较频繁且并无强烈的场景需求比特作为独立单位，则可以以工具类的方式实现操作即可。
 * <p>
 * 特化：关于String入参的构造方法和toString方法重写是为了输出加密解密编码
 */
public class BitStream extends Number implements Comparable<BitStream>, Streamable<BitStream>, Serializable, Config {

    private final boolean[] values;
    private final int size;
    private final int usize = 1; //单位元素所占比特
    private final int tsize;
    private final long DEAL_MAX_SIZE = Config.DEAL_MAX_SIZE;

    /**
     * Constructor(String)
     *
     * @param data
     */
    public BitStream(String data) {
        data = Optional.ofNullable(data).orElse("");
        boolean[] values = getBits(data);
        if ((long) values.length * usize > DEAL_MAX_SIZE) {
            throw new IndexOutOfBoundsException("超出可读取范围！");
        }
        this.values = values;
        this.size = values.length;
        this.tsize = this.size * this.usize;
    }

    /**
     * 获取data字符串标准编码的bit串
     *
     * @param data
     * @return
     */
    private boolean[] getBits(String data) {
        final int size = data.length();
        final int usize = Character.SIZE;

//        final int offset = Byte.SIZE;
//        final char baseMask = 0xff00;
//        final int[] masks = new int[usize];
//
//        //掩码表赋值，这样写是为增强可维护性
//        for (int i = 0; i < usize; i++) {
//            masks[i] = baseMask >>> ((usize - i - 1) * offset);
//        }

        boolean[] bs = new boolean[size * usize];
        char[] works = data.toCharArray();
        //字符分解成若干字节
        for (int i = 0; i < size; i++) {
            for (int j = 0; j < usize; j++) {
                bs[i * usize + j] = (((works[i] >>> (usize - 1 - j)) & 0x01) == 1);
            }
        }
        return bs;
    }

    /**
     * Constructor(boolean[])
     *
     * @param data
     */
    public BitStream(boolean[] data) {
        if (data == null) {
            throw new NullPointerException("字节转化参数异常！");
        }
        this.values = data;
        this.size = data.length;
        this.tsize = this.size * this.usize;
    }

    /**
     * Constructor(long)
     *
     * @param value
     */
    public BitStream(Long value) {
        if (value == null) {
            throw new NullPointerException("nullPtr value");
        }
        boolean[] values = new boolean[Long.SIZE];
        long t = value;
        for (int i = 0; i < Long.SIZE; i++) {
            values[i] = toBoolean((int) (t & 0x00000001));
            t >>>= 1;
        }
        this.values = values;
        this.size = values.length;
        this.tsize = this.size * this.usize;
    }

    /**
     * Constructor(int)
     *
     * @param value
     */
    public BitStream(Integer value) {
        if (value == null) {
            throw new NullPointerException("nullPtr Integer");
        }
        boolean[] values = new boolean[Integer.SIZE];
        int t = value;
        for (int i = 0; i < Integer.SIZE; i++) {
            values[i] = toBoolean(t & 0x0001);
            t >>>= 1;
        }
        this.values = values;
        this.size = values.length;
        this.tsize = this.size * this.usize;
    }

    /**
     * Constructor(self)
     * 复制构造器
     *
     * @param data
     */
    private BitStream(BitStream data) {
        this(data.values());
    }

    /**
     * Non-param Constructor
     * 缺省实现为Constructor(String"")
     * 私有化防止非法调用
     */
    private BitStream() {
        this("");
    }


    public BitStream(int bitLength) {
        this(new boolean[bitLength]);
    }

    public static BitStream valueOf(String data) {
        return new BitStream(data);
    }

    /**
     * 获取比特流的大小数组
     *
     * @return
     */
    private boolean[] values() {
        return this.values;
    }

    /**
     * 获取比特流的比特总长度(=单位比特大小×比特流长度)
     *
     * @return
     */
    public int size() {
        return tsize;
    }

    /**
     * 获取比特流的长度
     *
     * @return
     */
    public int length() {
        return this.size;
    }


    /**
     * 比特转换成数值
     *
     * @param isBit
     * @return
     */
    private int toBit(boolean isBit) {
        return isBit ? 0x0001 : 0x0000;
    }

    /**
     * 数值转换成比特(只取最低的二进制位)
     *
     * @param bit
     * @return
     */
    private boolean toBoolean(int bit) {
        return (bit == 0x0001);
    }

    /**
     * 获取[fromIndex , toIndex)的连续子比特流
     *
     * @param fromIndex
     * @param toIndex
     * @return
     */
    public BitStream getSubBits(int fromIndex, int toIndex) {
        if ((fromIndex < 0) || (toIndex > this.size)) {
            throw new IndexOutOfBoundsException("比特数组溢出！");
        }
        if (fromIndex >= toIndex) {
            throw new InvalidParameterException("索引参数非法");
        }
        final int size = toIndex - fromIndex;
        boolean[] subValues = new boolean[size];
        for (int i = 0; i < size; i++) {
            subValues[i] = this.values[fromIndex + i];
        }
        return new BitStream(subValues);
    }

    /**
     * 比特位置互换操作，用表置换算法，核心为含有置换规则的二维表maps
     *
     * @param maps 位置映射规则表
     * @return
     */
    public BitStream permute(int[] maps) {
        boolean[] vals = new boolean[maps.length];
        int length = maps.length > this.size ? this.size : maps.length;
        System.arraycopy(this.values, 0, vals, 0, length);
        BitStream res = new BitStream(vals);
        for (int i = 0; i < maps.length; i++) {
            res.setBit(this.getBit(maps[i] - 1), i); //可见 关系R(i , maps[i] - 1)存在映射(i -> maps[i] - 1)
        }
        return res;
    }

    /**
     * 比特流循环左移n位
     *
     * @param n
     * @return
     */
    @Override
    public BitStream leftShift(int n, boolean isLoop) {
        if (n < 0) {
            throw new IllegalArgumentException("n is invalid");
        }
        boolean[] vals = new boolean[this.size];
        System.arraycopy(this.values, n, vals, 0, this.size - n);
        if (isLoop) {
            System.arraycopy(this.values, 0, vals, this.size - n, n);
        }
        return new BitStream(vals);
    }

    /**
     * 与另一个比特流another进行异或
     *
     * @param another
     * @return
     */
    @Override
    public BitStream xor(BitStream another) {
        boolean[] anothers = another.values();
        long anotherSize = another.size();
        if (anotherSize != this.size) {
            throw new InputMismatchException("长度不一致！");
        }
        boolean[] res = new boolean[this.size];
        for (int i = 0; i < this.size; i++) {
            res[i] = ((this.toBit(this.values[i]) ^ this.toBit(anothers[i])) == 1);
//            System.out.println(this.values[i] + "\t" + anothers[i]);
        }
        return new BitStream(res);
    }

    /**
     * 连接另一个比特流another
     *
     * @param another
     * @return
     */
    public BitStream concat(BitStream another) {
        boolean[] res = new boolean[this.size + another.size()];
        System.arraycopy(this.values, 0, res, 0, this.size);
        System.arraycopy(another.values(), 0, res, this.size, another.size());
        return new BitStream(res);
    }

    /**
     * 获取某位比特值
     *
     * @param i 比特流的索引
     * @return
     */
    public int getBit(int i) {
        if ((i >= this.size) || (i < 0)) {
            throw new IndexOutOfBoundsException("非法比特流索引：" + i + "," + this.size);
        }
        return this.toBit(this.values[i]);
    }

    /**
     * 设置比特值
     *
     * @param bit
     * @param i   比特流的索引（从0开始）
     */
    public void setBit(int bit, int i) {
        if ((i > this.size) || (i < 0)) {
            throw new IndexOutOfBoundsException("比特流索引非法：" + i);
        }
        if (!isBit(bit)) {
            throw new InputMismatchException("比特参数非法！");
        }
        this.values[i] = this.toBoolean(bit);
    }

    /**
     * 判断bit是否为纯粹的比特值(0 , 1)
     *
     * @param bit
     * @return
     */
    private boolean isBit(int bit) {
        return (bit == 0x0001) || (bit == 0x0000);
    }

    @Override
    public int intValue() {
        return (int) sum();
    }

    @Override
    public long longValue() {
        return sum();
    }

    @Override
    public float floatValue() {
        return (float) sum();
    }

    @Override
    public double doubleValue() {
        return (double) sum();
    }


    private char[] hexChars = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

    public String toHex() {
        StringBuffer s = new StringBuffer();
        final int usize = Byte.SIZE / 2;
        for (int i = 0; i < this.size; i++) {

        }
        return s.toString();
    }

    /**
     * 比特流总值
     *
     * @return
     */
    private long sum() {
        long res = 0;
        boolean[] datas = this.values;

        for (int i = 0; i < datas.length; i++) {
            res <<= 1;
            res += this.toBit(datas[i]);
        }
        return res;
    }

    /**
     * 以索引数组对应的比特重组的比特流的总值
     *
     * @param idxs
     * @return
     */
    public long sum(int[] idxs) {
        if (idxs == null) {
            throw new NullPointerException("nullPtr : idx");
        }
        long res = 0;
        boolean[] vals = this.values;
        for (int i = 0; i < idxs.length; i++) {
            int idx = idxs[i];
            if ((idx < 0) || (idx >= this.size)) {
                throw new IndexOutOfBoundsException("index : " + idx + "," + this.size);
            }
            res <<= 1;
            res += this.toBit(vals[idx]);
        }
        return res;

    }

    /**
     * 不可变对象的克隆，要注意用克隆对象所有成员的副本构造
     *
     * @return
     */
    @Override
    public BitStream clone() {
        boolean[] newValues = new boolean[this.size];
        System.arraycopy(this.values, 0, newValues, 0, this.size);
        return new BitStream(newValues);
    }

    @Override
    public int compareTo(BitStream another) {
        return (int) (this.sum() - another.sum());
    }

    @Override
    public String toString() {
        StringBuffer s = new StringBuffer();
        final int usize = Byte.SIZE;
        final String delimiter = " ";
        s.append(this.size + "bit:");
        for (int i = 0; i < this.size; i++) {
            s.append((this.toBit(this.values[i]) & 0x01));
            if ((i + 1) % usize == 0) {
                s.append(delimiter);
            }
        }
        return s.toString();
    }

    public String toCharacters() {
        final int charSize = Character.SIZE;
        final boolean[] values = this.values;
        //注意要是比特流无法被字符字节数整除的话
        if (values.length % charSize != 0) {
            throw new IllegalArgumentException("value can't be divided by charSize completely");
        }
        final StringBuffer res = new StringBuffer();
        final int groupCount = values.length / charSize;
        final char mask = 0xffff;
        final int uBitSize = 1;
        for (int i = 0; i < groupCount; i++) {
            char val = 0x0000;
            for (int j = 0; j < charSize; j++) {
                val <<= uBitSize;
                val |= this.values[i * charSize + j] ? 1 : 0;
            }
            val &= mask;
            res.append(val);
        }
        return res.toString();
    }


    /**
     * 流密码所需扩展方法
     */

    @Override
    public void setByte(byte vals, int pos) {
        final int byteSize = Byte.SIZE;
        final int size = this.tsize / byteSize;
        if ((pos <= 0) || (pos > size) || (size * pos > this.tsize)) {
            throw new IllegalArgumentException("pos of (" + this.tsize + "," + size + ")is invalid : " + pos);
        }
        boolean[] values = this.values;
        final int fromIndex = (pos - 1) * byteSize;
        final int toIndex = pos * byteSize;
        final byte mask = 0x01;
        for (int i = fromIndex; i < toIndex; i++) {
            values[i] = (((vals >> (toIndex - 1 - i)) & mask) == 0x0001);
        }
    }

    @Override
    public byte getByte(int pos) {
        final int size = this.tsize / Byte.SIZE;
        if ((pos <= 0) || (pos > size) || (size * pos > this.tsize)) {
            throw new IllegalArgumentException("pos is invalid");
        }
        BitStream subBits = this.getSubBits((pos - 1) * Byte.SIZE, pos * Byte.SIZE);
        return subBits.byteValue();
    }

    @Override
    public int byteSize() {
        return this.tsize / Byte.SIZE;
    }
}


