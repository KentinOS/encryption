package encryption.impl;

import encryption.SymEncryption;

public abstract class SymKeyEncryptionImpl<T> extends EncryptionImpl<T> implements SymEncryption<T> {
    protected static final int SYMMETRIC_BIT = 64;
    protected static final int SYMMETRIC_LONG_BIT = 128;


}
