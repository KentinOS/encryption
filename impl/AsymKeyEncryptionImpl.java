package encryption.impl;

import encryption.AsymEncryption;

public abstract class AsymKeyEncryptionImpl<T> extends EncryptionImpl<T> implements AsymEncryption<T> {
    protected static final int ASYMMETRIC_BIT = 1024;
}
