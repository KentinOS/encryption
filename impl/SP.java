package encryption.impl;

import encryption.impl.streamUtils.Streamable;

public abstract class SP<T extends Streamable> extends GroupPassword<T> {

    protected final static int DEFAULT_CRYPT_TIME = 10;

    protected T[] keys;

    private int cryptTime;

    public SP() {
        this(null, DEFAULT_GROUP_BIT, DEFAULT_CRYPT_TIME);
    }

    public SP(String keyStr, int groupBitSize, int cryptTime) {
        super(groupBitSize);
        keyStr = this.format(keyStr, groupBitSize / Character.SIZE);
        keys = this.extendKeys(this.convertString(keyStr), cryptTime);
        this.cryptTime = cryptTime;
    }

    abstract protected T[] extendKeys(T initKey, int cryptTime);

    /**
     * AES加密
     *
     * @param msg
     * @return
     */
    @Override
    public T encrypt(T msg) {
        if (msg == null) {
            throw new NullPointerException("msg must be not null!");
        }
        msg = F(msg, 0);
        for (int i = 1; i <= this.cryptTime; i++) {
            msg = S(msg, i);
            msg = P(msg, i);
            msg = F(msg, i);
        }
        return msg;
    }

    abstract protected T S(T msg, int cryptTime);

    abstract protected T P(T msg, int cryptTime);

    /**
     * AES解密
     *
     * @param pwd
     * @return
     */
    @Override
    public T decrypt(T pwd) {
        if (pwd == null) {
            throw new NullPointerException("pwd must be not null!");
        }
        for (int i = this.cryptTime; i >= 1; i--) {
            pwd = F(pwd, i);
            pwd = PR(pwd, i);
            pwd = SR(pwd, i);
        }
        pwd = F(pwd, 0);
        return pwd;
    }

    abstract protected T SR(T pwd, int cryptTime);

    abstract protected T PR(T pwd, int cryptTime);

    /**
     * 轮密钥加
     *
     * @param data
     * @param cryptTime
     * @return
     */
    private T F(T data, int cryptTime) {
        //19-4-22 some of keys ever is null because they are extended by method named "extendKeys"
        return XOR(data, this.keys[cryptTime]);
    }

    abstract protected T XOR(T data, T key);

    abstract protected boolean isEncryptInvalid(int cryptTime);

    abstract protected boolean isDecryptInvalid(int cryptTime);

    /**
     * 更新密钥接口
     *
     * @param initKeyStr
     */
    public void updateKeys(String initKeyStr) {
        initKeyStr = this.format(initKeyStr, SYMMETRIC_LONG_BIT / Character.SIZE);
        this.keys = this.extendKeys(this.convertString(initKeyStr), this.cryptTime);
    }

}
