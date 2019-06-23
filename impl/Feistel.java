package encryption.impl;

import encryption.impl.bitStream.BitStream;

/**
 * 加密算法是一种偏数据运算型的算法，所用变量最好设计成不可变对象！
 * Feistel结构是一种高程度的对称密码结构
 * 计算流程相对SP网络密码结构具体，
 * 使其使用的数据结构具有较为显著的计算特征，
 * 故实例化泛型
 */

public abstract class Feistel extends GroupPassword<BitStream> {

    /**
     * 缺省次数
     */
    protected final static int DEFAULT_CRYPTO_TIME = 16;
    private int cryptoTime;
    /**
     * 缺省密钥
     */
    private static String keyStr = "abc";

    private BitStream[] subKeys;


    /**
     * Non-Param Constructor
     */
    public Feistel() {
        this(null, DEFAULT_GROUP_BIT, DEFAULT_CRYPTO_TIME);
    }

    /**
     * Standard Constructor
     *
     * @param keyStr
     */
    public Feistel(String keyStr, int groupBitSize, int cryptoTime) {
        super(groupBitSize);
        if (keyStr == null) {
            keyStr = Feistel.keyStr;
        }
        keyStr = this.format(keyStr, groupBitSize / Character.SIZE);
        this.subKeys = this.generateSubKeys(BitStream.valueOf(keyStr), cryptoTime);
        this.cryptoTime = cryptoTime;
    }

    /**
     * 加密方法
     *
     * @param msg
     * @return
     */
    @Override
    public BitStream encrypt(BitStream msg) {
        try {
            final int size = msg.size();
            this.checkSize(size);
            BitStream left = msg.getSubBits(0, size / 2),
                    right = msg.getSubBits(size / 2, size);
            BitStream tmp;
            for (int i = 0; i < cryptoTime; i++) {
                tmp = left;
                left = right;
                right = tmp.xor(F(right, this.subKeys[i]));
            }
            return left.concat(right);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    /**
     * 解密方法
     *
     * @param pwd
     * @return
     */
    @Override
    public BitStream decrypt(BitStream pwd) {
        try {
            final int size = pwd.size();
            this.checkSize(size);
            BitStream left = pwd.getSubBits(0, size / 2);
            BitStream right = pwd.getSubBits(size / 2, size);
            BitStream tmp;
            for (int i = cryptoTime - 1; i >= 0; i--) {
                tmp = right;
                right = left;
                left = tmp.xor(F(left, this.subKeys[i]));
            }
            return left.concat(right);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    protected abstract void checkSize(int size);

    protected abstract BitStream F(BitStream bytes, BitStream key);

    protected abstract BitStream[] generateSubKeys(BitStream key, int cryptoTime);

    /**
     * 更新密钥接口
     *
     * @param initKeyStr
     */
    public void updateKeys(String initKeyStr) {
        initKeyStr = this.format(initKeyStr, SYMMETRIC_BIT / Character.SIZE);
        this.subKeys = this.generateSubKeys(this.convertString(initKeyStr), DEFAULT_CRYPTO_TIME);
    }

}



