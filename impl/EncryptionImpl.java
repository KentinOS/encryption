package encryption.impl;
/**
 * 信息加密的流程：
 * 我们所见的消息->编码->明文->加密->密文,真正处理的明文是我们所见所能解读的消息在文件系统中存储的真正数据（即所谓的比特流，可以理解为只有0和1的数据序列），
 * 同一个文件用不同的编码标准解析出来的内容于我们而言是不一样的，但在文件系统中数据却从未变化过;
 * 相反，我们键入的同一字符消息用不同的编码标准解析，得到的数据也不一样，现代计算机字符序列常用的编码标准有ascii编码，utf编码,utf-BOM，
 * 因此我们直接处理数据即是用Java现成的编码标准（unicode）去解析消息了。
 * 为加强加密算法研究的针对性，我们应忽略矛盾的次要方面，抓住矛盾的主要方面，采用现成的编码标准转换明文消息即可，编码这一步交由计算机去处理。
 */

import java.util.Random;

/**
 * 基础根类提供顶层公有方法
 * <p>
 * 因为JAVA整型的原始数据类型中byte已经是最小的，故在代码中以字节为最小的操作单位，
 * 但逻辑上加密中最小的操作单位是bit，这也会在代码中体现出来。
 */
public abstract class EncryptionImpl<T> {

    //辅助工具
    protected static Random random = new Random();

    //加密共用常量区


    //工具基类保护构造方法
    protected EncryptionImpl() {
    }

    protected abstract T convertString(String text);

    protected abstract String recoverString(T obj);

    /**
     * 用于格式化指定字符串
     *
     * @param string
     * @param length
     * @return
     */
    protected String format(String string, int length) {
        if (length < 0) {
            throw new IllegalArgumentException("size < 0");
        }
        if (!(string != null && !string.equals(""))) {
            throw new IllegalArgumentException("string is null");
        }
        while (string.length() < length) {
            string = string.concat(string);
        }
        return string.substring(0, length);
    }

    /**
     * 经典小案例：原地交换两整数，
     * 如果映射到加密算法领域，
     * 则可认为b是明文, a是目标密文,
     * 第一次 a ^ b 的是密钥,密钥存储到寄存器a中
     * 第二次 b ^ a 的是加密,原地加密,加密得到的密文存储到寄存器b中
     * 第三次 a ^ b 的是解密,解密出来的明文b存储到寄存器a中，
     * 此时恰好寄存器b中的密文即目标密文a, 故实现了原地交换
     * 最主要是利用了异或的运算性质：双重否定等于肯定
     *
     * @param a
     * @param b
     * @return
     */
    protected static int[] swap(Integer a, Integer b) {
        a = a ^ b; //密钥
        b = b ^ a; //b为明文 ， 用密钥a加密b
        a = a ^ b; //用a再去解密b ， 得到的明文也就存储到a中了
        int[] arr = {a, b};
        return arr;
    }
}
