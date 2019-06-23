package encryption.impl;

import encryption.Encryptible;
import encryption.impl.blockUtils.StringSplit;
import encryption.utils.TaskUtil;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * 要注意非对称加密的明文与密文分块大小是不一样的！！！
 * 防止出现这种BUG，长度问题重点关注blockBitSize和getValidLengthOfChars
 *
 * @param <T>
 */
public abstract class BlockPassword<T extends Encryptible> extends AsymKeyEncryptionImpl<T> {

    /**
     * 若不限制加密长度，接口容易陷入超时响应的阻塞状态
     */
    private static final int MAX_AVAILABLE_TIMES = 128;
    protected static final int MESSAGE_BIT_SIZE = Character.SIZE;

    /**
     * 明文分块大小
     */
    private final int blockBitSize;

    protected BlockPassword(int blockBitSize) {
        this.randomOffset = MESSAGE_BIT_SIZE * (random.nextInt(5) + 5);
        this.blockBitSize = blockBitSize;
        this.randomObj = this.convertString(this.format("" + this.hashCode(), blockBitSize / MESSAGE_BIT_SIZE));
    }

    protected abstract int getBitLength();

    private final T randomObj;

    /**
     * 加密模式
     * ECB电子密码本
     * CBC加密区块链
     * 明文密文面向服务对象String
     * 统一StringBuffer容器
     */

    private final int randomOffset;

    /**
     * ECB加密
     *
     * @param msgText
     * @return
     */
    @SuppressWarnings("Duplicates")
    protected StringBuffer encrypt_ECB(StringBuffer msgText, T publicKey) {
        this.checkValid(msgText);
        this.checkEncryptValid(msgText);
        //分割明文消息串，分成每组（块）64bit(即4个字符)
        StringSplit stringSplit = new StringSplit(msgText, this.blockBitSize / Character.SIZE, true);
        //结果容器
        final StringBuffer res = new StringBuffer();
        //连接密文序列
        String msg = stringSplit.next();
        while (msg != null) {
            T obj = this.convertString(msg);
            T encrypt = this.encrypt(obj, publicKey);
            res.append(this.addLeadingEmptyPadding(this.recoverString(encrypt), this.getValidLengthOfChars())); //编码已超过100位，直接存储
            msg = stringSplit.next();
        }
        //返回密文序列缓冲区
        return res;
    }

    /**
     * ECB解密
     */
    /**
     * 块解密需要去掉填充字符
     *
     * @param pwdText
     * @return
     */
    @SuppressWarnings("Duplicates")
    protected StringBuffer decrypt_ECB(StringBuffer pwdText, T publicKey) {
        this.checkValid(pwdText);
        this.checkDecryptValid(pwdText);
        final int blockLength = this.getValidLengthOfChars();
        if (!this.preCheck(pwdText, blockLength)) {
            throw new IllegalArgumentException("参数不合法");
        }
        StringSplit split = new StringSplit(pwdText, blockLength, true);
        final StringBuffer res = new StringBuffer();
        String pwd = split.next();
        while (pwd != null) {
            T obj = this.convertString(pwd);
            T decrypt = this.decrypt(obj, publicKey);
            res.append(this.recoverString(decrypt));
            pwd = split.next();
        }
        this.filterTailPadding(res, StringSplit.PADDING);
        return res;
    }

    /**
     * assert text.length() <= length
     *
     * @param text
     * @param blockLength
     * @return
     */
    private String addLeadingEmptyPadding(String text, final int blockLength) {
        final int length = blockLength;
        if (text.length() < length) {
            final int leftSize = length - text.length();
            final char[] tmpChar = new char[leftSize];
            text = new String(tmpChar).concat(text);
        }
        return text;
    }

    /**
     * CBC加密
     *
     * @param msgText
     * @return
     */
    @SuppressWarnings("Duplicates")
    protected StringBuffer encrypt_CBC(StringBuffer msgText, T publicKey) {
        this.checkValid(msgText);
        this.checkEncryptValid(msgText);
        //分割明文消息串，单位长度64bit
        StringSplit stringSplit = new StringSplit(msgText, this.blockBitSize / Character.SIZE, true);

        final StringBuffer res = new StringBuffer();
        String msg = stringSplit.next();
        T lastResObj = this.randomObj;
        while (msg != null) {
            T msgObj = this.convertString(msg);
            msgObj = (T) msgObj.xor(lastResObj);
            T encrypt = this.encrypt(msgObj, publicKey);
            res.append(this.addLeadingEmptyPadding(
                    this.recoverString(encrypt),
                    this.getValidLengthOfChars())
            );
            msg = stringSplit.next();
            lastResObj = encrypt;
        }
        return res;
    }

    /**
     * CBC解密
     *
     * @param pwdText
     * @return
     */
    @SuppressWarnings("Duplicates")
    protected StringBuffer decrypt_CBC(StringBuffer pwdText, T privateKey) {
        this.checkValid(pwdText);
        this.checkDecryptValid(pwdText);
        final int blockLength = this.getValidLengthOfChars();
        if (!this.preCheck(pwdText, blockLength)) {
            throw new IllegalArgumentException("参数不合法");
        }
        StringSplit split = new StringSplit(pwdText, blockLength, true);
        final StringBuffer res = new StringBuffer();
        String pwd = split.next();
        T lastResObj = this.randomObj;
        while (pwd != null) {
            T pwdObj = this.convertString(pwd);
            T decrypt = this.decrypt(pwdObj, privateKey);
            decrypt = (T) decrypt.xor(lastResObj);
            res.append(this.recoverString(decrypt));
            pwd = split.next();
            lastResObj = pwdObj;
        }
        this.filterTailPadding(res, StringSplit.PADDING);
        return res;
    }

    private void filterTailPadding(StringBuffer stringBuffer, char padding) {
        while ((stringBuffer.length() > 0) && (stringBuffer.charAt(stringBuffer.length() - 1) == padding)) {
            stringBuffer.deleteCharAt(stringBuffer.length() - 1);
        }
    }

    /**
     * 多线程服务
     * 非对称加密的多线程任务列表并无分割
     * 是因为该加密一般使用于短明文，并无该必要
     */
    @SuppressWarnings("Duplicates")
    public StringBuffer encrypt_ECB_with_multiply_threads(StringBuffer msgText, final T publicKey) {
        //检查参数合法性
        this.checkValid(msgText);
        this.checkEncryptValid(msgText);
        //预处理添加填充字符使其刚好完全分组
        final int taskLength = this.blockBitSize / Character.SIZE;
        this.preDealPadding(msgText, taskLength, StringSplit.PADDING);
        //分割明文消息串，分成每组（块）blockbitSize(即至少1024)
        final String target = msgText.toString();
        final int length = target.length();
        final int groupCount = this.getGroupCount(length, taskLength);
        String substring;
        //构造回调任务列表
        List<Callable<Boolean>> callableList = new ArrayList<>();
        final String[] strings = new String[groupCount];
        int sp = 0, ep = 0;
        final int cipherBlockLength = this.getValidLengthOfChars();
        for (int i = 0; i < groupCount; i++) {
            ep += taskLength;
            if (ep > length) {
                ep = length;
            }
            substring = target.substring(sp, ep);
            String s = substring;
            int idx = i;
            callableList.add(() -> {
                final T t = this.convertString(s);
                final T encryptEcb = this.encrypt(t, publicKey);
                strings[idx] = this.addLeadingEmptyPadding(this.recoverString(encryptEcb), cipherBlockLength);
                return true;
            });
            sp = ep;
        }
        //并发执行
        TaskUtil.initAndInvokeAll(callableList);
        //结果容器
        final StringBuffer res = new StringBuffer();
        //连接密文序列
        for (int i = 0; i < groupCount; i++) {
            res.append(strings[i]);
        }
        //返回密文序列缓冲区
        return res;

    }

    @SuppressWarnings("Duplicates")
    public StringBuffer decrypt_ECB_with_multiply_threads(StringBuffer pwdText, final T privateKey) {
        //检查参数合法性
        this.checkValid(pwdText);
        this.checkDecryptValid(pwdText);
        final int taskLength = this.getValidLengthOfChars();
        if (!this.preCheck(pwdText, taskLength)) {
            throw new IllegalArgumentException("参数不合法");
        }
        //取目标字符串
        final String target = pwdText.toString();
        final int length = target.length();
        //分组：groupCount * taskLength = floor(totalLength)
        final int groupCount = this.getGroupCount(length, taskLength);
        //根据分组划分字符串构造回调任务列表
        List<Callable<Boolean>> callableList = new ArrayList<>();
        String substring;
        int sp = 0, ep = 0;
        final String[] strings = new String[groupCount];
        for (int i = 0; i < groupCount; i++) {
            ep += taskLength;
            if (ep > length) {
                ep = length;
            }
            substring = target.substring(sp, ep);
            String s = substring;
            int idx = i;
            callableList.add(() -> {
                T decrypt = this.decrypt(this.convertString(s), privateKey);
                strings[idx] = this.recoverString(decrypt);
                return true;
            });
            sp = ep;
        }
        //启用多线程调用任务并发执行
        TaskUtil.initAndInvokeAll(callableList);
        final StringBuffer res = new StringBuffer();
        //把strings拼接到缓冲区中返回
        for (int i = 0; i < groupCount; i++) {
            res.append(strings[i]);
        }
        //过滤填充字符
        this.filterTailPadding(res, StringSplit.PADDING);
        return res;
    }

    /**
     * CBC解密可异步
     *
     * @param pwdText
     * @return
     */
    @SuppressWarnings("Duplicates")
    public StringBuffer decrypt_CBC_multiply_threads(StringBuffer pwdText, final T privateKey) {
        //检查参数合法性
        this.checkValid(pwdText);
        this.checkDecryptValid(pwdText);
        final int taskLength = this.getValidLengthOfChars();
        if (!this.preCheck(pwdText, taskLength)) {
            throw new IllegalArgumentException("参数不合法");
        }
        //获取作为处理目标的字符串对象
        final String target = pwdText.toString();
        //对缓冲区字符串分组成groupCount , 每组大小为taskLength
        final int length = target.length();
        final int groupCount = this.getGroupCount(length, taskLength);
        List<Callable<Boolean>> callableList = new ArrayList<>();
        //遍历分组构造回调任务列表
        int sp = 0, ep = 0;
        String substring;
        final String[] strings = new String[groupCount];
        String lastString = this.recoverString(this.randomObj);
        for (int i = 0; i < groupCount; i++) {
            ep += taskLength;
            if (ep > length) {
                ep = length;
            }
            substring = target.substring(sp, ep);
            String lastDealString = lastString;
            String s = substring;
            int idx = i;
            callableList.add(() -> {
                T decrypt = this.decrypt(this.convertString(s), privateKey);
                decrypt = (T) decrypt.xor(this.convertString(lastDealString));
                strings[idx] = this.recoverString(decrypt);
                return true;
            });
            lastString = substring;
            sp = ep;
        }
        //调用所有任务并发执行，写入主线程的final向量变量strings
        TaskUtil.initAndInvokeAll(callableList);
        StringBuffer res = new StringBuffer();
        //将strings中的字符串元素拼接到res字符串缓冲区中返回
        for (int i = 0; i < groupCount; i++) {
            res.append(strings[i]);
        }
        this.filterTailPadding(res, StringSplit.PADDING);
        return res;
    }


    private void checkValid(StringBuffer stringBuffer) {
        if (stringBuffer == null) {
            throw new NullPointerException("缓冲区为Null");
        }
    }

    private void checkEncryptValid(StringBuffer stringBuffer) {
        if (stringBuffer.length() > MAX_AVAILABLE_TIMES * this.blockBitSize / MESSAGE_BIT_SIZE) {
            throw new IllegalArgumentException("缓冲区长度超过限制长度");
        }
    }

    private void checkDecryptValid(StringBuffer stringBuffer) {
        if (stringBuffer.length() > MAX_AVAILABLE_TIMES * this.getValidLengthOfChars()) {
            throw new IllegalArgumentException("缓冲区长度超过限制长度");
        }

    }

    private boolean preCheck(StringBuffer stringBuffer, int unitLength) {
        return (stringBuffer.length() % unitLength == 0);
    }

    private int getValidLengthOfChars() {
        return this.getGroupCount(this.getBitLength(), Character.SIZE);
    }

    private int getGroupCount(int totalLength, int unitLength) {
        return (totalLength - 1) / unitLength + 1;
    }

    //19-5-1 非对称加密不存在流加密的工作模式!! 因为流密码的加密和解密都是使用加密方法，故不适用非对称加密的
    @SuppressWarnings("Duplicates")
    private void preDealPadding(StringBuffer stringBuffer, int unitLength, char padding) {
        final int length = stringBuffer.length();
        final int remainder = length % unitLength;
        if (remainder == 0) {
            return;
        }
        char[] chars = new char[unitLength - remainder];
        Arrays.fill(chars, padding);
        stringBuffer.append(chars);
    }

    protected void finalize() {
        TaskUtil.recycleExecutor();
    }
}
