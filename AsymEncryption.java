package encryption;

public interface AsymEncryption<T> extends Encryption<T> {
    T encrypt(T msg, T publicKey);

    T decrypt(T pwd, T privateKey);
}
