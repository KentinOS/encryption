package encryption;

public interface SymEncryption<T> extends Encryption<T> {
    T encrypt(T msg);

    T decrypt(T pwd);
}
