package encryption;

/**
 * 加密解密单元必须继承的接口
 * 运算均以不可变对象的规范实现
 *
 * @param <T>
 */
public interface Encryptible<T> {
    T xor(T other);   //异或

    T leftShift(int nBits, boolean isLoop);//左移n个bit
}
