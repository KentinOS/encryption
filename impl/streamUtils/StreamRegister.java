package encryption.impl.streamUtils;

import encryption.SymEncryption;

public class StreamRegister<T extends Streamable> {

    /**
     * 取8bit为一个流单位
     */

    private SymEncryption symEncryption;

    /**
     * 与流密码相关联的流寄存器
     * Constructor
     *
     * @param symEncryption
     */
    public StreamRegister(SymEncryption symEncryption) {
        this.symEncryption = symEncryption;
    }

    private Streamable content;

    /**
     * 初始化寄存器
     *
     * @param initContent
     */
    public void init(Streamable initContent) {
        this.content = initContent;
    }

    /**
     * 执行加密
     */
    public void encrypt() {
        this.content = (Streamable) this.symEncryption.encrypt(this.content);
    }

    /**
     * 返回首位8bit组（1字节）
     *
     * @return
     */
    public byte getBits() {
        return this.content.getByte(1);
    }

    /**
     * 寄存器内容左移，以padding填充末尾8bit组
     *
     * @param padding
     * @return
     */
    public boolean leftShift(byte padding) {
        this.content = (Streamable) this.content.leftShift(8, false);
        this.content.setByte(padding, this.content.byteSize());
        return true;
    }


}
