package encryption.impl.streamUtils;

import encryption.Encryptible;

/**
 * 流化采用byte为基本单位
 *
 * @param <T>
 */
public interface Streamable<T> extends Encryptible<T> {

    void setByte(byte val, int pos);

    byte getByte(int pos);

    int byteSize();
}
