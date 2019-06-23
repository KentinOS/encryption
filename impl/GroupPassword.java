package encryption.impl;

import encryption.impl.blockUtils.StringSplit;
import encryption.impl.streamUtils.StreamRegister;
import encryption.impl.streamUtils.Streamable;
import encryption.utils.TaskUtil;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * 分组加密一般设64Bit或128Bit为一组处理明文
 * 分组密码中按结构又有以下划分：
 * Feistel结构，SP网络，其他密码结构
 * 故继续往下衍生派生类
 */
public abstract class GroupPassword<T extends Streamable> extends SymKeyEncryptionImpl<T> {


    protected static final int DEFAULT_GROUP_BIT = SYMMETRIC_LONG_BIT;
    private final int groupBitSize;

    private final T randomObj;
    /**
     * 混淆矩阵
     */
    //初始化向量,置换规则，可用以打乱明文，增加扰乱
    private final static int[] IP = {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
    };

    //初始化向量的逆向量,逆置换规则，可用以恢复密文，还原扰乱
    private final static int[] IPR = {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
    };

    protected GroupPassword(int groupBitSize) {
        this.groupBitSize = groupBitSize;
        this.randomObj = this.convertString(this.format("" + this.hashCode(), groupBitSize / Character.SIZE));
    }

    /**
     * 加密模式
     * ECB电子密码本
     * CBC加密区块链
     * CFB加密反馈模式
     * OFB输出反馈模式
     * CTR计数器模式 (暂不实现)
     * 明文密文面向服务对象String
     * 统一采用StringBuffer容器
     * 块解密需要去掉填充字符
     * 流加密要初始化寄存器
     */

    /**
     * ECB加密
     *
     * @param msgText
     * @return
     */
    @SuppressWarnings("Duplicates")
    public StringBuffer encrypt_ECB(StringBuffer msgText) {
        this.checkValid(msgText);
        //分割明文消息串，分成每组（块）64bit(即4个字符)
        StringSplit stringSplit = new StringSplit(msgText, this.groupBitSize, Character.SIZE, true);
        //结果容器
        final StringBuffer res = new StringBuffer();
        //连接密文序列
        String msg = stringSplit.next();
        while (msg != null) {
            T obj = this.convertString(msg);
            T encrypt = this.encrypt(obj);
            res.append(this.recoverString(encrypt));
            msg = stringSplit.next();
        }
        //返回密文序列缓冲区
        return res;
    }

    /**
     * ECB解密
     *
     * @param pwdText
     * @return
     */
    @SuppressWarnings("Duplicates")
    public StringBuffer decrypt_ECB(StringBuffer pwdText) {
        this.checkValid(pwdText);
        final int bitSize = this.groupBitSize;
        StringSplit split = new StringSplit(pwdText, bitSize, Character.SIZE, true);
        final StringBuffer res = new StringBuffer();
        String pwd = split.next();
        while (pwd != null) {
            T obj = this.convertString(pwd);
            T decrypt = this.decrypt(obj);
            res.append(this.recoverString(decrypt));
            pwd = split.next();
        }
        this.filterTailPadding(res, StringSplit.PADDING);
        return res;
    }

    /**
     * CBC加密
     *
     * @param msgText
     * @return
     */
    @SuppressWarnings("Duplicates")
    public StringBuffer encrypt_CBC(StringBuffer msgText) {
        this.checkValid(msgText);
        //分割明文消息串，单位长度64bit
        StringSplit stringSplit = new StringSplit(msgText, this.groupBitSize, Character.SIZE, true);

        final StringBuffer res = new StringBuffer();
        String msg = stringSplit.next();
        T lastResObj = this.randomObj;
        while (msg != null) {
            T msgObj = this.convertString(msg);
            msgObj = (T) msgObj.xor(lastResObj);
            T encrypt = this.encrypt(msgObj);
            res.append(this.recoverString(encrypt));
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
    public StringBuffer decrypt_CBC(StringBuffer pwdText) {
        this.checkValid(pwdText);
        StringSplit split = new StringSplit(pwdText, this.groupBitSize, Character.SIZE, true);

        final StringBuffer res = new StringBuffer();
        String pwd = split.next();
        T lastResObj = this.randomObj;
        while (pwd != null) {
            T pwdObj = this.convertString(pwd);
            T decrypt = this.decrypt(pwdObj);
            decrypt = (T) decrypt.xor(lastResObj);
            res.append(this.recoverString(decrypt));
            pwd = split.next();
            lastResObj = pwdObj;
        }
        this.filterTailPadding(res, StringSplit.PADDING);
        return res;
    }

    private void filterTailPadding(StringBuffer stringBuffer, char padding) {
        while (stringBuffer.charAt(stringBuffer.length() - 1) == padding) {
            stringBuffer.deleteCharAt(stringBuffer.length() - 1);
        }
    }

    /**
     * 流密码模式处理单元较小，相对块加密时间开销会稍大，只作实现，不被系统调用
     */

    /**
     * CFB加密
     *
     * @param msgText
     * @return
     */
    @SuppressWarnings("Duplicates")
    public StringBuffer encrypt_CFB(StringBuffer msgText) {
        this.checkValid(msgText);
        StreamRegister<T> streamRegister = new StreamRegister<>(this);
        char[] datas = msgText.toString().toCharArray();
        final int length = datas.length;

        streamRegister.init(this.randomObj);
        StringBuffer rs = new StringBuffer();
        for (int i = 0; i < length; i++) {
            byte[] plainBytes = this.charToBytes(datas[i]);
            byte[] pwdBytes = new byte[plainBytes.length];
            for (int j = 0; j < plainBytes.length; j++) {
                streamRegister.encrypt();
                byte bits = streamRegister.getBits();
                byte res = (byte) (plainBytes[j] ^ bits);
                pwdBytes[j] = res;
                streamRegister.leftShift(res);
            }
            rs.append(this.bytesToChar(pwdBytes));
        }
        return rs;
    }

    /**
     * CFB解密是CBC的加密的逆过程
     *
     * @param pwdText
     * @return
     */
    @SuppressWarnings("Duplicates")
    public StringBuffer decrypt_CFB(StringBuffer pwdText) {
        this.checkValid(pwdText);
        StreamRegister<T> streamRegister = new StreamRegister<>(this);
        char[] datas = pwdText.toString().toCharArray();
        final int length = datas.length;

        streamRegister.init(this.randomObj);
        final StringBuffer rs = new StringBuffer();
        for (int i = 0; i < length; i++) {
            final byte[] pwdBytes = this.charToBytes(datas[i]);
            final byte[] plainBytes = new byte[pwdBytes.length];
            for (int j = 0; j < plainBytes.length; j++) {
                streamRegister.encrypt();
                final byte bits = streamRegister.getBits();
                plainBytes[j] = (byte) (bits ^ pwdBytes[j]);
                streamRegister.leftShift(pwdBytes[j]);
            }
            rs.append(this.bytesToChar(plainBytes));
        }
        return rs;
    }


    /**
     * OFB加密
     *
     * @param msgText
     * @return
     */
    public StringBuffer encrypt_OFB(StringBuffer msgText) {
        this.checkValid(msgText);
        final StreamRegister<T> streamRegister = new StreamRegister<>(this);
        final char[] datas = msgText.toString().toCharArray();

        final StringBuffer res = new StringBuffer();
        streamRegister.init(this.randomObj);
        for (int i = 0; i < datas.length; i++) {
            final byte[] msgBytes = this.charToBytes(datas[i]);
            final byte[] pwdBytes = new byte[msgBytes.length];
            for (int j = 0; j < msgBytes.length; j++) {
                streamRegister.encrypt();
                final byte bits = streamRegister.getBits();
                pwdBytes[j] = (byte) (bits ^ msgBytes[j]);
                streamRegister.leftShift(bits);
            }
            res.append(this.bytesToChar(pwdBytes));
        }
        return res;
    }

    /**
     * OFB解密与加密完全一样，根本原因是异或的逆运算还是它本身
     *
     * @param pwdText
     * @return
     */
    public StringBuffer decrypt_OFB(StringBuffer pwdText) {
        return this.encrypt_OFB(pwdText);
    }

    private byte[] charToBytes(char c) {
        final char lowMask = 0x00ff;
        final char highMask = 0xff00;
        return new byte[]{(byte) ((c & highMask) >> Byte.SIZE), (byte) (c & lowMask)};
    }

    private char bytesToChar(final byte[] bytes) {
        final char mask = 0x00ff;
        char c = 0x0000;
        c |= (bytes[0] & mask);
        c <<= Byte.SIZE;
        c |= (bytes[1] & mask);
        return c;
    }

    private void checkValid(StringBuffer stringBuffer) {
        if (stringBuffer == null) {
            throw new NullPointerException("存储数据的字符缓冲区为null");
        }
    }

    /**
     * 多线程版本
     *  为了可以根据不同的业务场景采用不同的版本接口
     *  非多线程版本与多线程版本实现上还是有所区别的
     */

    /**
     * @param msgText
     * @return
     */
    @SuppressWarnings("Duplicates")
    public StringBuffer encrypt_ECB_multiply_threads(StringBuffer msgText) {
        this.checkValid(msgText);
        final int taskLength = this.groupBitSize / Character.SIZE;
        this.preDealPadding(msgText, taskLength, StringSplit.PADDING);
        final String target = msgText.toString();
        final int length = target.length();
        final int groupCount = this.getGroupCount(length, taskLength);

        List<Callable<Boolean>> callableList;
        final String[] strings = new String[groupCount];
        String substring;
        int sp = 0, ep = 0;

        final int taskOnceSize = TaskUtil.TASK_ONCE_SIZE;
        final int taskGroupCount = this.getGroupCount(groupCount, taskOnceSize);
        final int remainder = groupCount % taskOnceSize;
        /**
         * 任务列表再分割，是因为微机内存不足，一次性构造所有回调任务要生成的实例当数据量上去以后很容易出现十分隐蔽的严重漏洞gc heap limit exceed
         * 分开多次构造是解决该问题的最直接方案
         * 当然该方案会降低执行效率的
         * 是健壮性与高效性的折中方案
         */
        TaskUtil.initExecutor();
        int count = taskOnceSize;
        for (int i = 0; i < taskGroupCount; i++) {
            if (i == taskGroupCount - 1) {
                count = remainder;
            }
            callableList = new ArrayList<>();
            for (int j = 0; j < count; j++) {
                ep += taskLength;
                if (ep > length) {
                    ep = length;
                }
                substring = target.substring(sp, ep);
                String s = substring;
                int idx = i * taskOnceSize + j;
                callableList.add(() -> {
                    T encrypt = this.encrypt(this.convertString(s));
                    strings[idx] = this.recoverString(encrypt);
                    return true;
                });
                sp = ep;
            }
            //调用所有任务并发执行，写入主线程的final向量变量strings
            TaskUtil.invokeAll(callableList, TaskUtil.DEFAULT_TIME_OUT);
        }

        StringBuffer res = new StringBuffer();
        //拼接字符串
        for (int i = 0; i < groupCount; i++) {
            res.append(strings[i]);
        }
        return res;
    }

    /**
     * @param pwdText
     * @return
     */
    @SuppressWarnings("Duplicates")
    public StringBuffer decrypt_ECB_multiply_threads(StringBuffer pwdText) {
        //检查参数合法性
        this.checkValid(pwdText);
        final int taskLength = this.groupBitSize / Character.SIZE;
        this.preCheck(pwdText, taskLength);
        //获取目标字符串
        String target = pwdText.toString();
        //分组成groupCount , 每组大小taskLength
        final int length = target.length();
        final int groupCount = this.getGroupCount(length, taskLength);

        //构造回调任务列表
        List<Callable<Boolean>> callableList;
        String substring;
        int sp = 0, ep = 0;
        final String[] strings = new String[groupCount];

        final int taskOnceSize = TaskUtil.TASK_ONCE_SIZE;
        final int taskGroupCount = this.getGroupCount(groupCount, taskOnceSize);
        final int remainder = groupCount % taskOnceSize;
        /**
         * 任务列表再分割，是因为微机内存不足，一次性构造所有回调任务要生成的实例当数据量上去以后很容易出现十分隐蔽的严重漏洞full gc
         * 分开多次构造是解决该问题的最直接方案
         * 当然该方案会降低执行效率的
         * 是健壮性与高效性的折中方案
         */
        TaskUtil.initExecutor();
        int count = taskOnceSize;
        for (int i = 0; i < taskGroupCount; i++) {
            if (i == taskGroupCount - 1) {
                count = remainder;
            }
            callableList = new ArrayList<>();
            for (int j = 0; j < count; j++) {
                ep += taskLength;
                if (ep > length) {
                    ep = length;
                }
                substring = target.substring(sp, ep);
                String s = substring;
                int idx = i * taskOnceSize + j;
                callableList.add(() -> {
                    T decrypt = this.decrypt(this.convertString(s));
                    strings[idx] = this.recoverString(decrypt);
                    return true;
                });
                sp = ep;
            }
            //调用所有任务并发执行，写入主线程的final向量变量strings
            TaskUtil.invokeAll(callableList, TaskUtil.DEFAULT_TIME_OUT);
        }
        final StringBuffer res = new StringBuffer();
        //拼接所有明文字符串
        for (int i = 0; i < groupCount; i++) {
            res.append(strings[i]);
        }
        //过滤填充字符
        this.filterTailPadding(res, StringSplit.PADDING);
        return res;
    }

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

    private void preCheck(StringBuffer stringBuffer, int unitLength) {
        if (!(stringBuffer.length() % unitLength == 0)) {
            throw new IllegalArgumentException("参数不合法");
        }
    }

    /**
     * CBC解密可异步
     *
     * @param pwdText
     * @return
     */
    @SuppressWarnings("Duplicates")
    public StringBuffer decrypt_CBC_multiply_threads(StringBuffer pwdText) {
        //检查参数合法性
        this.checkValid(pwdText);
        final int taskLength = this.groupBitSize / Character.SIZE;
        this.preCheck(pwdText, taskLength);
        //获取作为处理目标的字符串对象
        final String target = pwdText.toString();
        //对缓冲区字符串分组成groupCount , 每组大小为taskLength
        final int length = target.length();
        final int groupCount = this.getGroupCount(length, taskLength);
        //遍历分组构造回调任务列表
        List<Callable<Boolean>> callableList;
        int sp = 0, ep = 0;
        String substring;
        final String[] strings = new String[groupCount];
        String last = this.recoverString(this.randomObj);
        final int taskOnceSize = TaskUtil.TASK_ONCE_SIZE;
        final int taskGroupCount = this.getGroupCount(groupCount, taskOnceSize);
        final int remainder = groupCount % taskOnceSize;
        /**
         * 任务列表再分割，是因为微机内存不足，一次性构造所有回调任务要生成的实例当数据量上去以后很容易出现十分隐蔽的严重漏洞full gc
         * 分开多次构造是解决该问题的最直接方案
         * 当然该方案会降低执行效率的
         * 是健壮性与高效性的折中方案
         */
        TaskUtil.initExecutor();
        int count = taskOnceSize;
        for (int i = 0; i < taskGroupCount; i++) {
            if (i == taskGroupCount - 1) {
                count = remainder;
            }
            callableList = new ArrayList<>();
            for (int j = 0; j < count; j++) {
                ep += taskLength;
                if (ep > length) {
                    ep = length;
                }
                substring = target.substring(sp, ep);
                String lastDeal = last;
                String s = substring;
                int idx = i * taskOnceSize + j;
                callableList.add(() -> {
                    T decrypt = this.decrypt(this.convertString(s));
                    strings[idx] = this.recoverString((T) decrypt.xor(this.convertString(lastDeal)));
                    return true;
                });
                last = s;
                sp = ep;
            }
            //调用所有任务并发执行，写入主线程的final向量变量strings
            TaskUtil.invokeAll(callableList);
        }
        //将strings中的字符串元素拼接到res字符串缓冲区中返回
        StringBuffer res = new StringBuffer();
        for (int i = 0; i < groupCount; i++) {
            res.append(strings[i]);
        }
        this.filterTailPadding(res, StringSplit.PADDING);
        return res;
    }

    private int getGroupCount(int totalLength, int unitLength) {
        return (totalLength - 1) / unitLength + 1;
    }

    protected void finalize() {
        TaskUtil.recycleExecutor();
    }

}
